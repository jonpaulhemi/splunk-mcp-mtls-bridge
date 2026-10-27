"""Black-box tests: real mTLS clients against the bridge in front of a fake upstream."""

import socket
import ssl
import time

import pytest

from harness import MAPPED_TOKEN, Client, make_config, running_bridge


def test_mapped_client_can_list_tools_through_the_bridge(test_pki, upstream, client_for):
    client = client_for(test_pki.mapped)

    status, _, body = client.rpc("tools/list", request_id=7)

    assert status == 200
    assert body == {"jsonrpc": "2.0", "id": 7, "result": {"tools": [{"name": "splunk_run_query"}]}}
    assert len(upstream.received) == 1
    forwarded = upstream.received[0]
    assert forwarded.path == "/services/mcp"
    assert forwarded.json()["method"] == "tools/list"
    assert forwarded.headers["Authorization"] == "Bearer " + MAPPED_TOKEN


def test_client_authorization_header_is_replaced_by_the_mapped_token(test_pki, upstream, client_for):
    client = client_for(test_pki.mapped)

    status, _, _ = client.rpc("tools/list", headers={"Authorization": "Bearer client-supplied"})

    assert status == 200
    assert upstream.received[0].headers["Authorization"] == "Bearer " + MAPPED_TOKEN
    assert "client-supplied" not in str(upstream.received[0].headers)


def _handshake_fails(client):
    try:
        client.rpc("tools/list")
    except (ssl.SSLError, ConnectionError):
        return True
    return False


def test_client_without_a_cert_fails_the_handshake(test_pki, upstream, client_for):
    assert _handshake_fails(client_for(issued=None))
    assert upstream.received == []


def test_client_cert_from_an_untrusted_ca_fails_the_handshake(test_pki, upstream, client_for):
    assert _handshake_fails(client_for(test_pki.other_ca_client))
    assert upstream.received == []


def test_valid_but_unmapped_cert_gets_403_json_rpc_error(test_pki, upstream, client_for):
    status, headers, body = client_for(test_pki.unmapped).rpc("tools/list", request_id=3)

    assert status == 403
    assert headers["Content-Type"] == "application/json"
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == 3
    assert "unmapped" in body["error"]["message"]
    assert upstream.received == []


def _client_context(test_pki, bridge, **settings):
    context = Client(bridge.address, test_pki.ca.cert_path, test_pki.mapped).context
    for name, value in settings.items():
        if name == "ciphers":
            context.set_ciphers(value)
        else:
            setattr(context, name, value)
    return context


def _negotiated(test_pki, bridge, **settings):
    context = _client_context(test_pki, bridge, **settings)
    with socket.create_connection(bridge.address, timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname="localhost") as tls:
            return tls.version(), tls.cipher()[0]


def test_listener_negotiates_tls_1_3_by_default(test_pki, bridge):
    version, _ = _negotiated(test_pki, bridge)
    assert version == "TLSv1.3"


def test_listener_accepts_tls_1_2_with_a_modern_cipher(test_pki, bridge):
    version, cipher = _negotiated(test_pki, bridge, maximum_version=ssl.TLSVersion.TLSv1_2)
    assert version == "TLSv1.2"
    assert cipher.startswith("ECDHE-")


def test_listener_refuses_tls_1_1(test_pki, bridge):
    with pytest.raises((ssl.SSLError, ConnectionError)):
        _negotiated(
            test_pki,
            bridge,
            minimum_version=ssl.TLSVersion.TLSv1_1,
            maximum_version=ssl.TLSVersion.TLSv1_1,
            ciphers="DEFAULT:@SECLEVEL=0",
        )


@pytest.mark.parametrize("cipher", ["AES128-SHA", "AES256-GCM-SHA384", "ECDHE-RSA-AES128-SHA"])
def test_listener_refuses_legacy_tls_1_2_ciphers(test_pki, bridge, cipher):
    with pytest.raises((ssl.SSLError, ConnectionError)):
        _negotiated(test_pki, bridge, maximum_version=ssl.TLSVersion.TLSv1_2, ciphers=cipher)


def test_unreachable_upstream_gets_502_json_rpc_error(test_pki, upstream, unused_port):
    config = make_config(test_pki, upstream, upstream_url=f"https://127.0.0.1:{unused_port}/services/mcp")
    with running_bridge(config) as bridge:
        status, _, body = Client(bridge.address, test_pki.ca.cert_path, test_pki.mapped).rpc("tools/list", request_id=4)

    assert status == 502
    assert body["id"] == 4
    assert "upstream" in body["error"]["message"]


def test_non_numeric_content_length_gets_400(client_for, test_pki, upstream):
    status, _, _ = client_for(test_pki.mapped).request("POST", body=b"{}", headers={"Content-Length": "abc"})
    assert status == 400
    assert upstream.received == []


def test_chunked_body_without_content_length_gets_411(client_for, test_pki, upstream):
    status, _, _ = client_for(test_pki.mapped).request(
        "POST", body=iter([b"{}"]), headers={"Transfer-Encoding": "chunked"}
    )
    assert status == 411
    assert upstream.received == []


def test_idle_client_after_handshake_is_disconnected(test_pki, upstream):
    with running_bridge(make_config(test_pki, upstream, client_timeout=0.5)) as bridge:
        context = Client(bridge.address, test_pki.ca.cert_path, test_pki.mapped).context
        with socket.create_connection(bridge.address, timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname="localhost") as tls:
                started = time.monotonic()
                assert tls.recv(1) == b""
                assert time.monotonic() - started < 3
