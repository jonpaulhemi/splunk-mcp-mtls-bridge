"""Every call and every rejection leaves one JSON event in the audit file; secrets and results never do."""

import json
import ssl
import subprocess
import sys

import pytest

from mtls_bridge.config import Mapping

import pki
from harness import MAPPED_TOKEN, ROOT, Client, client_of, make_config, running_bridge

RESULT_MARKER = "result-text-that-must-not-be-audited"


@pytest.fixture
def audit_path(tmp_path):
    return tmp_path / "audit" / "audit.log"


def _events(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def _call(client, arguments, request_id=7):
    body = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": "splunk_run_query", "arguments": arguments},
    }
    return client.request("POST", body=body, headers={"Authorization": "Bearer client-supplied-secret"})


def test_forwarded_tool_call_is_audited_once_with_every_field(test_pki, upstream, audit_path):
    upstream.result = {"content": [{"type": "text", "text": RESULT_MARKER}]}
    config = make_config(test_pki, upstream, audit_log=str(audit_path))
    with running_bridge(config) as bridge:
        status, headers, _ = _call(client_of(bridge, test_pki, test_pki.mapped), {"query": "index=main | head 1"})

    assert status == 200
    [event] = _events(audit_path)
    assert event["event"] == "call"
    assert event["time"]
    assert event["request_id"] == headers["X-MCP-Request-Id"] == upstream.received[0].headers["X-MCP-Request-Id"]
    assert event["peer_ip"] == "127.0.0.1"
    assert event["issuer"] == test_pki.ca.issuer_dn
    assert (event["identity_type"], event["identity"]) == ("URI", pki.MAPPED_URI)
    assert event["user"] == "svc_agent_a"
    assert event["method"] == "tools/call"
    assert event["tool"] == "splunk_run_query"
    assert json.loads(event["arguments"]) == {"query": "index=main | head 1"}
    assert event["arguments_truncated"] is False
    assert event["status"] == 200
    assert event["latency_ms"] >= 0

    text = audit_path.read_text()
    for secret in (RESULT_MARKER, MAPPED_TOKEN, "client-supplied-secret"):
        assert secret not in text


def test_long_arguments_are_truncated_and_marked(test_pki, upstream, audit_path):
    config = make_config(test_pki, upstream, audit_log=str(audit_path))
    with running_bridge(config) as bridge:
        _call(client_of(bridge, test_pki, test_pki.mapped), {"query": "é" * 10000})

    [event] = _events(audit_path)
    assert event["arguments_truncated"] is True
    assert 4000 <= len(event["arguments"].encode()) <= 4096


def test_locally_answered_and_refused_calls_are_audited(test_pki, upstream, audit_path):
    config = make_config(test_pki, upstream, audit_log=str(audit_path))
    with running_bridge(config) as bridge:
        client = client_of(bridge, test_pki, test_pki.mapped)
        client.rpc("ping")
        client.request("GET")

    ping, get = _events(audit_path)
    assert (ping["event"], ping["method"], ping["status"]) == ("call", "ping", 200)
    assert (get["event"], get["http_method"], get["status"]) == ("call", "GET", 405)
    assert get["user"] == "svc_agent_a"
    assert upstream.received == []


@pytest.mark.parametrize("cert_name, reason", [("unmapped", "unmapped"), ("ambiguous", "ambiguous")])
def test_rejected_cert_is_audited_with_values_to_paste_into_a_mapping(
    test_pki, upstream, audit_path, cert_name, reason
):
    mappings = [
        Mapping(test_pki.ca.issuer_dn, "URI", "spiffe://bridge.test/amb-1", "one", token="t1"),
        Mapping(test_pki.ca.issuer_dn, "URI", "spiffe://bridge.test/amb-2", "two", token="t2"),
    ]
    cert = getattr(test_pki, cert_name)
    config = make_config(test_pki, upstream, audit_log=str(audit_path), mappings=mappings)
    with running_bridge(config) as bridge:
        status, _, _ = client_of(bridge, test_pki, cert).rpc("tools/list")

    assert status == 403
    [event] = _events(audit_path)
    assert event["event"] == "rejection"
    assert event["reason"] == reason
    assert event["status"] == 403
    assert event["method"] == "tools/list"
    inspected = subprocess.run(
        [sys.executable, str(ROOT / "package" / "bin" / "inspect-cert"), str(cert.cert)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert f"Issuer: {event['issuer']}" in inspected
    assert f"Serial: {event['serial']}" in inspected
    assert f"SHA-256: {event['sha256']}" in inspected
    for identity in event["identities"]:
        assert f"{identity['type']}: {identity['value']}" in inspected
    assert event["identities"]


def test_failed_handshakes_from_one_ip_collapse_into_one_event(test_pki, upstream, audit_path):
    config = make_config(test_pki, upstream, audit_log=str(audit_path))
    with running_bridge(config) as bridge:
        # A cert from a CA the bridge doesn't trust fails verification.
        stranger = Client(bridge.address, test_pki.ca.cert_path, test_pki.other_ca_client)
        for _ in range(20):
            with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
                stranger.rpc("tools/list")

    events = [e for e in _events(audit_path) if e["event"] == "handshake_failure"]
    assert len(events) == 1
    event = events[0]
    assert event["count"] == 20
    assert event["peer_ip"] == "127.0.0.1"
    assert isinstance(event["peer_port"], int)
    assert event["verify_code"] is not None
    assert event["reason"]
    assert event["time"]
