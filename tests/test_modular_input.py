"""The bridge as splunkd runs it: our modular input script, configured through splunkd's REST API."""

import json
import os
import signal
import socket
import ssl
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from mtls_bridge import splunk_config

import pki
from fake_splunkd import AUDIT_INPUT_PATH
from harness import ROOT, SESSION_KEY, Client, wait_for

SCRIPT = ROOT / "package" / "bin" / "mtls_bridge_daemon.py"
# The daemon's config poll interval in these tests (30 s in production).
POLL_SECONDS = 0.3


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
        env=dict(os.environ, SPLUNK_HOME=str(splunk_home), TA_MTLS_BRIDGE_POLL_SECONDS=str(POLL_SECONDS)),
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


def _audit_events(splunk_home):
    path = Path(splunk_config.AUDIT_LOG.replace("$SPLUNK_HOME", str(splunk_home)))
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def test_daemon_audits_calls_to_the_file_splunk_monitors(test_pki, splunk_home, bridge_port, daemon):
    assert _serving(test_pki, bridge_port)
    wait_for(lambda: _audit_events(splunk_home), timeout=5)
    [event] = _audit_events(splunk_home)
    assert (event["event"], event["user"], event["status"]) == ("call", "svc_agent_a", 200)


def test_default_audit_settings_leave_the_input_alone(test_pki, splunkd, bridge_port, daemon):
    assert _serving(test_pki, bridge_port)
    assert splunkd.posts == []
    assert splunkd.reloads == 0


@pytest.mark.parametrize(
    "settings, expected",
    [
        ({"audit_index": "security"}, {"index": "security", "disabled": "0"}),
        ({"audit_forwarding": "0"}, {"index": "main", "disabled": "1"}),
    ],
)
def test_audit_settings_repoint_the_monitor_input(
    test_pki, splunkd, splunk_home, bridge_port, tmp_path, settings, expected
):
    splunkd.content_overrides["settings_audit.json"] = settings
    process = _start(splunkd, splunk_home, tmp_path)
    try:
        wait_for(lambda: _serving(test_pki, bridge_port), timeout=10)
        assert splunkd.posts == [(AUDIT_INPUT_PATH, expected)]
        assert splunkd.reloads == 1
        # With forwarding off the file is still written.
        wait_for(lambda: _audit_events(splunk_home), timeout=5)
    finally:
        process.terminate()
        process.wait(10)


def _status(test_pki, port, issued, ca=None):
    """The HTTP status of a tools/list call, "handshake failed" or "not listening"."""
    client = Client(("127.0.0.1", port), ca or test_pki.ca.cert_path, issued)
    try:
        return client.rpc("tools/list")[0]
    except ConnectionRefusedError:
        return "not listening"
    except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
        return "handshake failed"


def _eventually(condition):
    wait_for(condition, timeout=POLL_SECONDS * 10)


def test_mapping_added_after_startup_works_without_a_restart(test_pki, splunkd, bridge_port, daemon):
    splunkd.empty.add("mappings.json")
    _eventually(lambda: _status(test_pki, bridge_port, test_pki.mapped) == 403)

    splunkd.empty.discard("mappings.json")
    _eventually(lambda: _status(test_pki, bridge_port, test_pki.mapped) == 200)
    assert daemon.poll() is None


def test_deleted_mapping_is_revoked_on_the_next_poll(test_pki, splunkd, bridge_port, daemon):
    assert _status(test_pki, bridge_port, test_pki.mapped) == 200
    splunkd.empty.add("mappings.json")
    _eventually(lambda: _status(test_pki, bridge_port, test_pki.mapped) == 403)


def test_changed_token_is_used_for_the_next_request(test_pki, upstream, splunkd, bridge_port, daemon):
    splunkd.content_overrides["mappings.json"] = {"token": "rotated-token"}

    def forwards_new_token():
        upstream.received.clear()
        return (
            _status(test_pki, bridge_port, test_pki.mapped) == 200
            and upstream.received[-1].headers["Authorization"] == "Bearer rotated-token"
        )

    _eventually(forwards_new_token)


def test_replaced_ca_bundle_takes_effect_for_new_handshakes(test_pki, splunkd, splunk_home, bridge_port, tmp_path):
    bundle = tmp_path / "clients.pem"
    bundle.write_bytes(test_pki.ca.cert_path.read_bytes())
    splunkd.content_overrides["settings_listener.json"]["ca_bundle"] = str(bundle)
    process = _start(splunkd, splunk_home, tmp_path)
    try:
        _eventually(lambda: _status(test_pki, bridge_port, test_pki.mapped) == 200)
        assert _status(test_pki, bridge_port, test_pki.other_ca_client) == "handshake failed"

        bundle.write_bytes(test_pki.ca.cert_path.read_bytes() + test_pki.other_ca.cert_path.read_bytes())
        # The other CA's client now gets through the handshake; it has no mapping, so it's refused.
        _eventually(lambda: _status(test_pki, bridge_port, test_pki.other_ca_client) == 403)
    finally:
        process.terminate()
        process.wait(10)


@pytest.mark.parametrize(
    "breakage",
    [
        lambda splunkd: splunkd.content_overrides["settings_listener.json"].update(listen_port="not-a-port"),
        lambda splunkd: splunkd.content_overrides["settings_listener.json"].update(ca_bundle="/nonexistent.pem"),
        lambda splunkd: splunkd.empty.add("settings_listener.json"),
    ],
    ids=["invalid", "unloadable", "missing"],
)
def test_bad_config_keeps_the_last_good_one_serving(test_pki, splunkd, splunk_home, bridge_port, daemon, breakage):
    breakage(splunkd)
    _eventually(lambda: "keeping the last good configuration" in _log(splunk_home))
    assert _status(test_pki, bridge_port, test_pki.mapped) == 200
    assert daemon.poll() is None


def test_session_key_rejected_mid_run_makes_the_daemon_exit(test_pki, splunkd, splunk_home, bridge_port, daemon):
    assert _status(test_pki, bridge_port, test_pki.mapped) == 200
    splunkd.session_key = "rotated-by-splunkd"

    assert daemon.wait(POLL_SECONDS * 10) == 1
    assert "rejected the session key" in _log(splunk_home)
