"""The bridge as splunkd runs it: our modular input script, configured through splunkd's REST API."""

import os
import signal
import socket
import ssl
import subprocess
import sys

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

import pki
from harness import ROOT, SESSION_KEY, Client, wait_for

SCRIPT = ROOT / "package" / "bin" / "mtls_bridge_daemon.py"


@pytest.fixture
def bridge_port(test_pki, upstream, splunkd, unused_port):
    """Point the fake splunkd's settings at the test PKI and fake upstream; return the bridge's port."""
    splunkd.content_overrides["settings_listener.json"] = {
        "listen_host": "127.0.0.1",
        "listen_port": str(unused_port),
        "server_cert": str(test_pki.server.cert),
        "server_key": str(test_pki.server.key),
        "upstream_url": upstream.url,
        "upstream_ca_bundle": str(test_pki.ca.cert_path),
    }
    return unused_port


def _input_xml(splunkd, checkpoint_dir, session_key=SESSION_KEY):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<input>
  <server_host>sh1</server_host>
  <server_uri>{splunkd.uri}</server_uri>
  <session_key>{session_key}</session_key>
  <checkpoint_dir>{checkpoint_dir}</checkpoint_dir>
  <configuration>
    <stanza name="mtls_bridge_daemon://bridge">
      <param name="interval">30</param>
    </stanza>
  </configuration>
</input>
"""


def _start(splunkd, splunk_home, checkpoint_dir, session_key=SESSION_KEY):
    process = subprocess.Popen(
        [sys.executable, str(SCRIPT)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=dict(os.environ, SPLUNK_HOME=str(splunk_home)),
    )
    process.stdin.write(_input_xml(splunkd, checkpoint_dir, session_key).encode())
    process.stdin.close()
    return process


def _serving(test_pki, port):
    client = Client(("127.0.0.1", port), test_pki.ca.cert_path, test_pki.mapped)
    try:
        return client.rpc("tools/list")[0] == 200
    except ConnectionRefusedError:
        return False


@pytest.fixture
def daemon(splunkd, splunk_home, tmp_path, bridge_port):
    process = _start(splunkd, splunk_home, tmp_path)
    wait_for(lambda: process.poll() is not None or _port_open(bridge_port), timeout=10)
    yield process
    if process.poll() is None:
        process.terminate()
        process.wait(10)


def _port_open(port):
    with socket.socket() as sock:
        return sock.connect_ex(("127.0.0.1", port)) == 0


def _log(splunk_home):
    path = splunk_home / "var" / "log" / "splunk" / "ta_mtls_bridge.log"
    return path.read_text() if path.exists() else ""


def test_scheme_declares_a_single_instance_input():
    result = subprocess.run([sys.executable, str(SCRIPT), "--scheme"], capture_output=True, text=True, check=True)
    assert "<use_single_instance>true</use_single_instance>" in result.stdout
    assert "<title>" in result.stdout


def test_validate_arguments_accepts_the_stanza(splunkd, tmp_path):
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--validate-arguments"], input=_input_xml(splunkd, tmp_path), text=True
    )
    assert result.returncode == 0


def test_daemon_serves_mapped_clients_from_splunk_config(test_pki, upstream, bridge_port, daemon):
    assert daemon.poll() is None
    assert _serving(test_pki, bridge_port)
    assert upstream.received[0].headers["Authorization"].endswith(".agent-a")


def test_second_instance_exits_without_a_second_listener(test_pki, splunkd, splunk_home, bridge_port, daemon, tmp_path):
    second = _start(splunkd, splunk_home, tmp_path)

    assert second.wait(10) == 0
    assert daemon.poll() is None
    assert _serving(test_pki, bridge_port)
    assert "already running" in _log(splunk_home)


def test_sigterm_stops_the_listener(bridge_port, daemon):
    daemon.send_signal(signal.SIGTERM)

    assert daemon.wait(10) == 0
    assert not _port_open(bridge_port)


def test_daemon_exits_when_splunkd_goes_away(splunkd, splunk_home, bridge_port, tmp_path):
    # A parent process stands in for splunkd: it starts the daemon, reports its pid and exits.
    parent = subprocess.run(
        [
            sys.executable,
            "-c",
            "import subprocess, sys; "
            f"p = subprocess.Popen([sys.executable, {str(SCRIPT)!r}], stdin=subprocess.PIPE, "
            "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
            "p.stdin.write(sys.stdin.buffer.read()); p.stdin.close(); print(p.pid); import time; time.sleep(1)",
        ],
        input=_input_xml(splunkd, tmp_path),
        capture_output=True,
        text=True,
        env=dict(os.environ, SPLUNK_HOME=str(splunk_home)),
        check=True,
    )
    pid = int(parent.stdout)

    wait_for(lambda: not _alive(pid), timeout=15)
    assert "parent process exited" in _log(splunk_home)


def test_unconfigured_bridge_exits_cleanly_and_says_why(splunkd, splunk_home, bridge_port, tmp_path):
    splunkd.content_overrides["settings_listener.json"]["ca_bundle"] = None

    process = _start(splunkd, splunk_home, tmp_path)

    assert process.wait(10) == 0
    assert "not configured" in _log(splunk_home)


def test_rejected_session_key_exits_with_an_error(splunkd, splunk_home, bridge_port, tmp_path):
    process = _start(splunkd, splunk_home, tmp_path, session_key="stale")

    assert process.wait(10) != 0
    assert "session key" in _log(splunk_home)


def _alive(pid):
    try:
        with open(f"/proc/{pid}/status") as status:
            return "\nState:\tZ" not in status.read()
    except FileNotFoundError:
        return False


def _served_cert(test_pki, port):
    context = Client(("127.0.0.1", port), test_pki.ca.cert_path, test_pki.mapped).context
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname="localhost") as tls:
            return tls.getpeercert(binary_form=True)


def _der(path):
    return ssl.PEM_cert_to_DER_cert(path.read_text())


def test_listener_defaults_to_splunkds_server_cert(test_pki, splunkd, splunk_home, bridge_port, tmp_path):
    splunkd_cert = pki.issue(
        test_pki.ca,
        tmp_path,
        "splunkd_server",
        "SplunkServerDefaultCert",
        sans=[x509.DNSName("localhost")],
        eku=ExtendedKeyUsageOID.SERVER_AUTH,
        rsa_key=True,
    )
    # Splunk's server.pem holds the cert followed by its key.
    server_pem = splunk_home / "etc" / "auth" / "server.pem"
    server_pem.write_bytes(splunkd_cert.cert.read_bytes() + splunkd_cert.key.read_bytes())
    splunkd.content_overrides["settings_listener.json"].update(server_cert=None, server_key=None)

    process = _start(splunkd, splunk_home, tmp_path)
    try:
        wait_for(lambda: process.poll() is not None or _port_open(bridge_port), timeout=10)
        assert _served_cert(test_pki, bridge_port) == _der(splunkd_cert.cert)
    finally:
        process.terminate()
        process.wait(10)


def test_listener_serves_the_override_cert(test_pki, bridge_port, daemon):
    assert _served_cert(test_pki, bridge_port) == _der(test_pki.server.cert)
