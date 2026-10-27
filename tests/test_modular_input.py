"""The bridge as splunkd runs it: our modular input script, configured through splunkd's REST API."""

import os
import signal
import socket
import subprocess
import sys

import pytest
from fake_splunkd import FakeSplunkd

from harness import ROOT, Client, wait_for

SCRIPT = ROOT / "package" / "bin" / "mtls_bridge_daemon.py"
SESSION_KEY = "modinput-session-key"


@pytest.fixture
def splunk_home(tmp_path):
    home = tmp_path / "splunk"
    (home / "etc" / "auth").mkdir(parents=True)
    (home / "var" / "log" / "splunk").mkdir(parents=True)
    return home


@pytest.fixture
def splunkd(test_pki, upstream, splunk_home, unused_port):
    fake = FakeSplunkd(
        test_pki.server, SESSION_KEY, {"{PKI}": str(test_pki.ca.cert_path.parent), "{SPLUNK_HOME}": str(splunk_home)}
    )
    fake.content_overrides["settings_listener.json"] = {
        "listen_host": "127.0.0.1",
        "listen_port": str(unused_port),
        "server_cert": str(test_pki.server.cert),
        "server_key": str(test_pki.server.key),
        "upstream_url": upstream.url,
        "upstream_ca_bundle": str(test_pki.ca.cert_path),
    }
    fake.port = unused_port
    yield fake.start()
    fake.stop()


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
def daemon(splunkd, splunk_home, tmp_path):
    process = _start(splunkd, splunk_home, tmp_path)
    wait_for(lambda: process.poll() is not None or _serving_quietly(splunkd), timeout=10)
    yield process
    if process.poll() is None:
        process.terminate()
        process.wait(10)


def _serving_quietly(splunkd):
    with socket.socket() as sock:
        return sock.connect_ex(("127.0.0.1", splunkd.port)) == 0


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


def test_daemon_serves_mapped_clients_from_splunk_config(test_pki, upstream, splunkd, daemon):
    assert daemon.poll() is None
    assert _serving(test_pki, splunkd.port)
    assert upstream.received[0].headers["Authorization"].endswith(".agent-a")


def test_second_instance_exits_without_a_second_listener(test_pki, splunkd, splunk_home, daemon, tmp_path):
    second = _start(splunkd, splunk_home, tmp_path)

    assert second.wait(10) == 0
    assert daemon.poll() is None
    assert _serving(test_pki, splunkd.port)
    assert "already running" in _log(splunk_home)


def test_sigterm_stops_the_listener(splunkd, daemon):
    daemon.send_signal(signal.SIGTERM)

    assert daemon.wait(10) == 0
    assert not _serving_quietly(splunkd)


def test_daemon_exits_when_splunkd_goes_away(splunkd, splunk_home, tmp_path):
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


def test_unconfigured_bridge_exits_cleanly_and_says_why(splunkd, splunk_home, tmp_path):
    splunkd.content_overrides["settings_listener.json"]["ca_bundle"] = None

    process = _start(splunkd, splunk_home, tmp_path)

    assert process.wait(10) == 0
    assert "not configured" in _log(splunk_home)


def test_rejected_session_key_exits_with_an_error(splunkd, splunk_home, tmp_path):
    process = _start(splunkd, splunk_home, tmp_path, session_key="stale")

    assert process.wait(10) != 0
    assert "session key" in _log(splunk_home)


def _alive(pid):
    try:
        with open(f"/proc/{pid}/status") as status:
            return "\nState:\tZ" not in status.read()
    except FileNotFoundError:
        return False
