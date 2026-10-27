"""How the bridge adapts requests and responses to the Splunk MCP Server app."""

import threading
import time

from mtls_bridge.config import Mapping

from harness import MAPPED_TOKEN, Client, make_config, running_bridge

TRACEPARENT = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"


def test_ping_is_answered_locally(test_pki, upstream, client_for):
    status, _, body = client_for(test_pki.mapped).rpc("ping", request_id=9)

    assert status == 200
    assert body == {"jsonrpc": "2.0", "id": 9, "result": {}}
    assert upstream.received == []


def test_ping_from_an_unmapped_cert_is_refused(test_pki, upstream, client_for):
    status, _, _ = client_for(test_pki.unmapped).rpc("ping")
    assert status == 403


def test_get_and_delete_get_405(test_pki, upstream, client_for):
    client = client_for(test_pki.mapped)
    for method in ("GET", "DELETE"):
        status, headers, _ = client.request(method)
        assert status == 405
        assert headers["Allow"] == "POST"
    assert upstream.received == []


def test_forwarded_request_carries_exactly_the_bridge_header_set(test_pki, upstream, client_for):
    client_for(test_pki.mapped).rpc(
        "tools/call",
        headers={
            "Authorization": "Bearer client-supplied",
            "X-MTLS-Identity": "spoofed",
            "X-Forwarded-For": "203.0.113.9",
            "Cookie": "splunkd_8089=stolen",
            "traceparent": TRACEPARENT,
            "MCP-Protocol-Version": "2025-06-18",
        },
    )

    headers = {k.lower(): v for k, v in upstream.received[0].headers.items()}
    host, port = upstream.url.split("/")[2].split(":")
    assert headers["host"] == f"{host}:{port}"
    assert headers["authorization"] == "Bearer " + MAPPED_TOKEN
    assert headers["x-forwarded-for"] == "127.0.0.1"
    assert headers["traceparent"] == TRACEPARENT
    assert headers["mcp-protocol-version"] == "2025-06-18"
    assert len(headers["x-mcp-request-id"]) >= 16
    assert set(headers) == {
        "host",
        "content-type",
        "content-length",
        "accept",
        "accept-encoding",
        "authorization",
        "x-forwarded-for",
        "x-mcp-request-id",
        "traceparent",
        "mcp-protocol-version",
    }


def test_each_request_gets_its_own_request_id(test_pki, upstream, client_for):
    client = client_for(test_pki.mapped)
    client.rpc("tools/list")
    client.rpc("tools/list")
    ids = [r.headers["X-MCP-Request-Id"] for r in upstream.received]
    assert ids[0] != ids[1]


def test_malformed_traceparent_is_not_forwarded(test_pki, upstream, client_for):
    client_for(test_pki.mapped).rpc("tools/list", headers={"traceparent": "00-not-a-valid-trace"})
    assert "traceparent" not in {k.lower() for k in upstream.received[0].headers}


def test_response_headers_from_splunkd_are_filtered(test_pki, upstream, client_for):
    upstream.headers = {
        "WWW-Authenticate": 'Bearer realm="splunk"',
        "Set-Cookie": "splunkd_8089=secret",
        "Cache-Control": "no-store",
    }

    status, headers, _ = client_for(test_pki.mapped).rpc("tools/list")

    assert status == 200
    lowered = {k.lower() for k in headers}
    assert "www-authenticate" not in lowered
    assert "set-cookie" not in lowered
    assert headers["Cache-Control"] == "no-store"


def test_upstream_401_becomes_502_and_reports_the_mapping(test_pki, upstream):
    rejected = []
    upstream.status = 401
    upstream.headers = {"WWW-Authenticate": "Bearer"}
    with running_bridge(make_config(test_pki, upstream), on_token_rejected=rejected.append) as bridge:
        status, headers, body = Client(bridge.address, test_pki.ca.cert_path, test_pki.mapped).rpc(
            "tools/list", request_id=5
        )

    assert status == 502
    assert "www-authenticate" not in {k.lower() for k in headers}
    assert body["id"] == 5
    assert body["error"]["message"] == "bridge credential invalid"
    assert [m.account for m in rejected] == ["svc_agent_a"]


def test_body_over_the_cap_gets_413_without_reaching_upstream(test_pki, upstream, client_for):
    oversized = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"x":"' + b"a" * (129 * 1024) + b'"}}'
    status, _, _ = client_for(test_pki.mapped).request("POST", body=oversized)
    assert status == 413
    assert upstream.received == []


def test_body_at_the_cap_is_forwarded(test_pki, upstream, client_for):
    prefix = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"x":"'
    suffix = b'"}}'
    body = prefix + b"a" * (128 * 1024 - len(prefix) - len(suffix)) + suffix
    status, _, _ = client_for(test_pki.mapped).request("POST", body=body)
    assert status == 200


def test_concurrent_requests_beyond_the_per_identity_cap_get_429(test_pki, upstream):
    upstream.gate = threading.Event()
    with running_bridge(make_config(test_pki, upstream, max_concurrent_per_identity=2)) as bridge:
        client = Client(bridge.address, test_pki.ca.cert_path, test_pki.mapped)
        results = []
        held = [threading.Thread(target=lambda: results.append(client.rpc("tools/list")[0])) for _ in range(2)]
        for thread in held:
            thread.start()
        _wait_for(lambda: len(upstream.received) == 2)

        assert client.rpc("tools/list")[0] == 429

        upstream.gate.set()
        for thread in held:
            thread.join(10)
        assert results == [200, 200]
        assert client.rpc("tools/list")[0] == 200


def test_cap_is_per_identity(test_pki, upstream):
    """A busy identity doesn't block a different one."""
    second = Mapping(
        issuer=test_pki.ca.issuer_dn,
        identity_type="URI",
        identity_value="spiffe://bridge.test/agent-b",
        account="svc_agent_b",
        token="token-b",
    )
    first = make_config(test_pki, upstream).mappings[0]
    config = make_config(test_pki, upstream, max_concurrent_per_identity=1, mappings=[first, second])
    upstream.gate = threading.Event()
    with running_bridge(config) as bridge:
        busy = Client(bridge.address, test_pki.ca.cert_path, test_pki.mapped)
        thread = threading.Thread(target=busy.rpc, args=("tools/list",))
        thread.start()
        _wait_for(lambda: len(upstream.received) == 1)
        upstream.gate.set()  # let agent-b's request through as soon as it arrives
        # The "unmapped" cert carries agent-b's URI, which this config maps.
        other = Client(bridge.address, test_pki.ca.cert_path, test_pki.unmapped)
        assert other.rpc("tools/list")[0] == 200
        thread.join(10)


def test_stalled_upstream_gets_504(test_pki, upstream):
    upstream.delay = 2
    with running_bridge(make_config(test_pki, upstream, upstream_timeout=0.3)) as bridge:
        status, _, body = Client(bridge.address, test_pki.ca.cert_path, test_pki.mapped).rpc("tools/list")
    assert status == 504
    assert "timed out" in body["error"]["message"]


def test_upstream_cert_from_an_untrusted_ca_gets_502(test_pki, upstream):
    config = make_config(test_pki, upstream, upstream_ca_bundle=str(test_pki.other_ca.cert_path))
    with running_bridge(config) as bridge:
        status, _, _ = Client(bridge.address, test_pki.ca.cert_path, test_pki.mapped).rpc("tools/list")
    assert status == 502
    assert upstream.received == []


def _wait_for(condition, timeout=5):
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "condition not met in time"
        time.sleep(0.02)
