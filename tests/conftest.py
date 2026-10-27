import http.client
import json
import ssl
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "package" / "bin"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mtls_bridge.config import Config, Mapping  # noqa: E402
from mtls_bridge.server import BridgeServer  # noqa: E402

import pki  # noqa: E402
from fake_upstream import FakeUpstream  # noqa: E402

MAPPED_TOKEN = "mapped-account-token"


@pytest.fixture(scope="session")
def test_pki(tmp_path_factory):
    return pki.build(tmp_path_factory.mktemp("pki"))


@pytest.fixture
def upstream(test_pki):
    fake = FakeUpstream(test_pki.server.cert, test_pki.server.key).start()
    yield fake
    fake.stop()


def make_config(test_pki, upstream, **overrides):
    values = dict(
        listen_host="127.0.0.1",
        listen_port=0,
        server_cert=str(test_pki.server.cert),
        server_key=str(test_pki.server.key),
        ca_bundle=str(test_pki.ca.cert_path),
        upstream_url=upstream.url,
        upstream_ca_bundle=str(test_pki.ca.cert_path),
        mappings=[
            Mapping(
                issuer=test_pki.ca.issuer_dn,
                identity_type="URI",
                identity_value=pki.MAPPED_URI,
                account="svc_agent_a",
                token=MAPPED_TOKEN,
            )
        ],
    )
    values.update(overrides)
    return Config(**values)


@pytest.fixture
def bridge(test_pki, upstream):
    server = BridgeServer(make_config(test_pki, upstream)).start()
    yield server
    server.stop()


class Client:
    """A real mTLS client for the bridge."""

    def __init__(self, address, ca, cert=None, key=None, context=None):
        self.address = address
        if context is None:
            context = ssl.create_default_context(cafile=str(ca))
            if cert:
                context.load_cert_chain(str(cert), str(key))
        self.context = context

    def request(self, method, path="/services/mcp", body=None, headers=None):
        host, port = self.address
        conn = http.client.HTTPSConnection(host, port, context=self.context, timeout=10)
        try:
            payload = json.dumps(body).encode() if isinstance(body, dict) else body
            all_headers = {"Content-Type": "application/json"}
            all_headers.update(headers or {})
            conn.request(method, path, body=payload, headers=all_headers)
            response = conn.getresponse()
            data = response.read()
            return response.status, dict(response.getheaders()), data
        finally:
            conn.close()

    def rpc(self, method, params=None, request_id=1, headers=None):
        body = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            body["params"] = params
        status, response_headers, data = self.request("POST", body=body, headers=headers)
        return status, response_headers, json.loads(data) if data else None


@pytest.fixture
def client_for(test_pki, bridge):
    def make(issued=None, context=None):
        if issued is None:
            return Client(bridge.address, test_pki.ca.cert_path, context=context)
        return Client(bridge.address, test_pki.ca.cert_path, issued.cert, issued.key, context=context)

    return make


@pytest.fixture
def unused_port():
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
