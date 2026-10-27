"""Shared helpers for driving the bridge as a black box."""

import contextlib
import dataclasses
import http.client
import json
import ssl
import time
from pathlib import Path

from mtls_bridge.config import Config, Mapping, RoleAccount, UserRule
from mtls_bridge.server import BridgeServer

import pki

ROOT = Path(__file__).resolve().parent.parent
MAPPED_TOKEN = "mapped-account-token"
ANALYST_TOKEN = "analyst-role-token"
ENGINEER_TOKEN = "engineer-role-token"
JOHN = "CN=John Smith,OU=Users,O=Org,C=US"
# The session key the fake splunkd accepts.
SESSION_KEY = "session-key-from-splunkd"


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


def make_proxy_config(test_pki, upstream, **overrides):
    """make_config, plus: the ``unmapped`` cert's identity proxies users, John's rule sends him to the
    analysts role account, and Jane's to the engineers one."""
    base = make_config(test_pki, upstream)
    values = dict(
        mappings=base.mappings
        + [Mapping(test_pki.ca.issuer_dn, "URI", "spiffe://bridge.test/agent-b", proxies_users=True)],
        role_accounts=[
            RoleAccount("analysts", "mcp_analyst", token=ANALYST_TOKEN),
            RoleAccount("engineers", "mcp_engineer", token=ENGINEER_TOKEN),
        ],
        user_rules=[
            UserRule("john", "dn", JOHN, "analysts"),
            UserRule("jane", "dn", "CN=Jane Doe,OU=Users,O=Org,C=US", "engineers"),
        ],
    )
    values.update(overrides)
    return dataclasses.replace(base, **values)


@contextlib.contextmanager
def running_bridge(config, **kwargs):
    server = BridgeServer(config, **kwargs).start()
    try:
        yield server
    finally:
        server.stop()


class Client:
    """A real mTLS client for the bridge. ``issued`` is the client's cert and key, or None for no cert."""

    def __init__(self, address, ca, issued=None):
        self.address = address
        self.context = ssl.create_default_context(cafile=str(ca))
        if issued is not None:
            self.context.load_cert_chain(str(issued.cert), str(issued.key))

    def request(self, method, body=None, headers=None, path="/services/mcp"):
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

    def health(self):
        """GET /health; returns (status, parsed JSON body)."""
        status, _, data = self.request("GET", path="/health")
        return status, json.loads(data)

    def rpc(self, method, request_id=1, headers=None):
        body = {"jsonrpc": "2.0", "id": request_id, "method": method}
        status, response_headers, data = self.request("POST", body=body, headers=headers)
        return status, response_headers, json.loads(data) if data else None


def client_of(bridge, test_pki, issued):
    """A client for ``bridge`` presenting ``issued`` (None for no cert)."""
    return Client(bridge.address, test_pki.ca.cert_path, issued)


def wait_for(condition, timeout=5):
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "condition not met in time"
        time.sleep(0.02)
