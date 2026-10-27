"""The HTTPS client for the Splunk MCP Server app."""

import contextlib
import http.client
import re
import ssl
import urllib.parse

# Request headers a client may pass through, with the shape their value must have.
_PASSTHROUGH_REQUEST_HEADERS = {
    "traceparent": re.compile(r"[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}"),
    "MCP-Protocol-Version": re.compile(r"\d{4}-\d{2}-\d{2}"),
}

# Response headers returned to the client. Everything else, notably WWW-Authenticate
# and splunkd's Set-Cookie, stays on the bridge.
_RETURNED_RESPONSE_HEADERS = frozenset(["content-type", "cache-control", "mcp-session-id", "mcp-protocol-version"])


def tls_context(config):
    context = ssl.create_default_context(cafile=config.upstream_ca_bundle)
    context.check_hostname = config.upstream_verify_hostname
    return context


def returned_headers(response):
    return [(name, value) for name, value in response.getheaders() if name.lower() in _RETURNED_RESPONSE_HEADERS]


class Upstream:
    def __init__(self, config):
        self._url = urllib.parse.urlsplit(config.upstream_url)
        self._context = tls_context(config)
        self._timeout = config.upstream_timeout

    @contextlib.contextmanager
    def post(self, token, body, client_headers, client_ip, request_id):
        """POST ``body`` with the mapped ``token`` and yield the unread http.client response."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": "Bearer " + token,
            "X-Forwarded-For": client_ip,
            "X-MCP-Request-Id": request_id,
        }
        for name, shape in _PASSTHROUGH_REQUEST_HEADERS.items():
            value = client_headers.get(name)
            if value is not None and shape.fullmatch(value):
                headers[name] = value
        conn = http.client.HTTPSConnection(
            self._url.hostname, self._url.port or 443, context=self._context, timeout=self._timeout
        )
        try:
            conn.request("POST", self._url.path or "/", body=body, headers=headers)
            yield conn.getresponse()
        finally:
            conn.close()
