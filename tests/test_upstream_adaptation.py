"""How the bridge adapts requests and responses to the Splunk MCP Server app."""

import http.client
import threading

import pytest

from mtls_bridge.config import Mapping

from harness import MAPPED_TOKEN, client_of, make_config, running_bridge, wait_for

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


def test_upstream_401_becomes_502_and_flags_the_mapping(test_pki, upstream):
    upstream.status = 401
    upstream.headers = {"WWW-Authenticate": "Bearer"}
    with running_bridge(make_config(test_pki, upstream)) as bridge:
        status, headers, body = client_of(bridge, test_pki, test_pki.mapped).rpc("tools/list", request_id=5)
        token_status = bridge.health()["mappings"][0]["token_status"]

    assert status == 502
    assert "www-authenticate" not in {k.lower() for k in headers}
    assert body["id"] == 5
    assert body["error"]["message"] == "bridge credential invalid"
    assert token_status == "invalid"


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


def test_eleventh_concurrent_request_from_one_identity_gets_429(test_pki, upstream):
    upstream.gate = threading.Event()
    with running_bridge(make_config(test_pki, upstream)) as bridge:
        client = client_of(bridge, test_pki, test_pki.mapped)
        results = []
        held = [threading.Thread(target=lambda: results.append(client.rpc("tools/list")[0])) for _ in range(10)]
        for thread in held:
            thread.start()
        wait_for(lambda: len(upstream.received) == 10)

        assert client.rpc("tools/list")[0] == 429

        upstream.gate.set()
        for thread in held:
            thread.join(10)
        assert results == [200] * 10
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
        busy = client_of(bridge, test_pki, test_pki.mapped)
        thread = threading.Thread(target=busy.rpc, args=("tools/list",))
        thread.start()
        wait_for(lambda: len(upstream.received) == 1)
        upstream.gate.set()  # let agent-b's request through as soon as it arrives
        # The "unmapped" cert carries agent-b's URI, which this config maps.
        other = client_of(bridge, test_pki, test_pki.unmapped)
        assert other.rpc("tools/list")[0] == 200
        thread.join(10)


def test_stalled_upstream_gets_504(test_pki, upstream):
    upstream.delay = 2
    with running_bridge(make_config(test_pki, upstream, upstream_timeout=0.3)) as bridge:
        status, _, body = client_of(bridge, test_pki, test_pki.mapped).rpc("tools/list")
    assert status == 504
    assert "timed out" in body["error"]["message"]


def test_upstream_cert_from_an_untrusted_ca_gets_502(test_pki, upstream):
    config = make_config(test_pki, upstream, upstream_ca_bundle=str(test_pki.other_ca.cert_path))
    with running_bridge(config) as bridge:
        status, _, _ = client_of(bridge, test_pki, test_pki.mapped).rpc("tools/list")
    assert status == 502
    assert upstream.received == []


def test_response_carries_the_request_id_sent_upstream(test_pki, upstream, client_for):
    _, headers, _ = client_for(test_pki.mapped).rpc("tools/list")
    assert headers["X-MCP-Request-Id"] == upstream.received[0].headers["X-MCP-Request-Id"]


def test_rejections_carry_a_request_id_too(test_pki, upstream, client_for):
    _, headers, _ = client_for(test_pki.unmapped).rpc("tools/list")
    assert len(headers["X-MCP-Request-Id"]) >= 16


def test_chunked_upstream_response_is_streamed_through(test_pki, upstream, client_for):
    upstream.chunked = True

    status, headers, body = client_for(test_pki.mapped).rpc("tools/list", request_id=12)

    assert status == 200
    assert headers["Transfer-Encoding"] == "chunked"
    assert body == {"jsonrpc": "2.0", "id": 12, "result": {"tools": [{"name": "splunk_run_query"}]}}


def test_upstream_failing_mid_response_truncates_rather_than_sending_a_second_response(test_pki, upstream, client_for):
    upstream.truncate = True
    with pytest.raises(http.client.IncompleteRead):
        client_for(test_pki.mapped).rpc("tools/list")
