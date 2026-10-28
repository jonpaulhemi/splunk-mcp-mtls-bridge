"""The bridge answers initialize and notifications itself (#70): Splunk's MCP Server always announces
2025-11-25 and answers notifications with 202, and every upstream request spends the account's rate limit."""

import json
import threading

import pytest

from mtls_bridge import __version__

from harness import JOHN, client_of, make_config, make_proxy_config, running_bridge, wait_for

HEADER = "X-ProxiedEntitiesChain"


def _initialize(client, version, headers=None):
    body = {
        "jsonrpc": "2.0",
        "id": "init-1",
        "method": "initialize",
        "params": {"protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "ExampleClient"}},
    }
    status, _, data = client.request("POST", body=body, headers=headers)
    return status, json.loads(data)


def _notify(client, headers=None):
    body = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    status, _, data = client.request("POST", body=body, headers=headers)
    return status, data


@pytest.mark.parametrize("version", ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"])
def test_initialize_echoes_a_supported_version(test_pki, upstream, client_for, version):
    status, body = _initialize(client_for(test_pki.mapped), version)

    assert status == 200
    assert body == {
        "jsonrpc": "2.0",
        "id": "init-1",
        "result": {
            "protocolVersion": version,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "TA-mtls-bridge", "version": __version__},
        },
    }
    assert upstream.received == []


@pytest.mark.parametrize("version", ["1999-01-01", None, 7])
def test_initialize_offers_the_latest_version_otherwise(test_pki, upstream, client_for, version):
    status, body = _initialize(client_for(test_pki.mapped), version)
    assert (status, body["result"]["protocolVersion"]) == (200, "2025-11-25")


def test_notification_gets_an_empty_200(test_pki, upstream, client_for):
    status, data = _notify(client_for(test_pki.mapped))

    assert (status, data) == (200, b"")
    assert upstream.received == []


def test_unmapped_cert_is_still_refused(test_pki, upstream, client_for):
    client = client_for(test_pki.unmapped)
    assert _initialize(client, "2024-11-05")[0] == 403
    assert _notify(client)[0] == 403


def test_proxying_client_initializes_for_a_named_user(test_pki, upstream):
    with running_bridge(make_proxy_config(test_pki, upstream)) as bridge:
        client = client_of(bridge, test_pki, test_pki.unmapped)
        named = _initialize(client, "2024-11-05", headers={HEADER: JOHN})[0]
        unnamed = _initialize(client, "2024-11-05")[0]
        unknown = _initialize(client, "2024-11-05", headers={HEADER: "CN=Nobody,O=Org"})[0]

    assert (named, unnamed, unknown) == (200, 403, 403)
    assert upstream.received == []


def test_proxying_client_notifies_without_a_user(test_pki, upstream):
    with running_bridge(make_proxy_config(test_pki, upstream)) as bridge:
        client = client_of(bridge, test_pki, test_pki.unmapped)
        assert _notify(client)[0] == 200
        assert _notify(client, headers={HEADER: JOHN})[0] == 200


def test_client_not_proxying_users_may_not_name_one_in_a_notification(test_pki, upstream, client_for):
    assert _notify(client_for(test_pki.mapped), headers={HEADER: JOHN})[0] == 403


def test_a_busy_client_can_still_initialize(test_pki, upstream):
    """Local answers take no concurrency slot."""
    upstream.gate = threading.Event()
    with running_bridge(make_config(test_pki, upstream, max_concurrent_per_identity=1)) as bridge:
        client = client_of(bridge, test_pki, test_pki.mapped)
        held = threading.Thread(target=client.rpc, args=("tools/list",))
        held.start()
        wait_for(lambda: len(upstream.received) == 1)
        status = _initialize(client, "2024-11-05")[0]
        upstream.gate.set()
        held.join(10)
    assert status == 200
