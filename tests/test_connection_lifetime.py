"""A connection is checked against the TLS settings it was opened with, and doesn't live for ever."""

import dataclasses
import http.client
import json
import ssl

from mtls_bridge.config import Mapping

import pki
from harness import make_config, running_bridge


class KeepAliveClient:
    """One keep-alive connection to the bridge, reused for every request."""

    def __init__(self, bridge, test_pki, issued):
        context = ssl.create_default_context(cafile=str(test_pki.ca.cert_path))
        context.load_cert_chain(str(issued.cert), str(issued.key))
        self.conn = http.client.HTTPSConnection(*bridge.address, context=context, timeout=10)

    def rpc(self, method="tools/list"):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method})
        self.conn.request("POST", "/services/mcp", body=body, headers={"Content-Type": "application/json"})
        response = self.conn.getresponse()
        data = response.read()
        return response.status, response.getheader("Connection"), json.loads(data) if data else None

    def close(self):
        self.conn.close()


def _with_revoked_mapping(config, test_pki):
    revoked = Mapping(test_pki.ca.issuer_dn, "URI", pki.REVOKED_URI, "svc_agent_r", token="t-r")
    return dataclasses.replace(config, mappings=[*config.mappings, revoked])


def test_a_revoked_cert_is_refused_on_a_connection_opened_before_the_crl(test_pki, upstream, tmp_path):
    crl_path = tmp_path / "clients.crl"
    crl_path.write_bytes(pki.crl(test_pki.ca))
    config = _with_revoked_mapping(
        make_config(test_pki, upstream, crl_file=str(crl_path), audit_log=str(tmp_path / "audit.log")), test_pki
    )
    with running_bridge(config) as bridge:
        client = KeepAliveClient(bridge, test_pki, test_pki.revoked)
        try:
            assert client.rpc()[0] == 200
            crl_path.write_bytes(pki.crl(test_pki.ca, [test_pki.revoked.cert]))
            bridge.apply(config)

            status, _, body = client.rpc()
        finally:
            client.close()

    assert status == 421
    assert "reconnect" in body["error"]["message"]
    assert len(upstream.received) == 1
    events = [json.loads(line) for line in (tmp_path / "audit.log").read_text().splitlines()]
    assert events[-1]["event"] == "rejection" and events[-1]["reason"] == "stale_connection"


def test_an_unchanged_config_leaves_open_connections_alone(test_pki, upstream):
    config = make_config(test_pki, upstream)
    with running_bridge(config) as bridge:
        client = KeepAliveClient(bridge, test_pki, test_pki.mapped)
        try:
            assert client.rpc()[0] == 200
            bridge.apply(config)
            assert client.rpc()[0] == 200
        finally:
            client.close()


def test_an_old_connection_is_closed_after_its_next_response(test_pki, upstream):
    config = make_config(test_pki, upstream, max_connection_seconds=0)
    with running_bridge(config) as bridge:
        client = KeepAliveClient(bridge, test_pki, test_pki.mapped)
        try:
            status, connection, _ = client.rpc()
        finally:
            client.close()

    assert (status, connection) == (200, "close")


def test_a_young_connection_stays_open(test_pki, upstream):
    with running_bridge(make_config(test_pki, upstream)) as bridge:
        client = KeepAliveClient(bridge, test_pki, test_pki.mapped)
        try:
            assert client.rpc()[1] is None
        finally:
            client.close()
