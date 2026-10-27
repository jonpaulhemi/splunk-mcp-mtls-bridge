"""The HTTPS client for the Splunk MCP Server app."""

import collections
import contextlib
import http.client
import re
import socket
import ssl
import urllib.parse

# Request headers a client may pass through, with the shape their value must have.
# MCP-Protocol-Version is part of MCP's HTTP transport: without it the server assumes an old revision.
_PASSTHROUGH_REQUEST_HEADERS = {
    "traceparent": re.compile(r"[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}"),
    "MCP-Protocol-Version": re.compile(r"\d{4}-\d{2}-\d{2}"),
}

# Response headers returned to the client. Everything else, notably WWW-Authenticate
# and splunkd's Set-Cookie, stays on the bridge.
_RETURNED_RESPONSE_HEADERS = frozenset(["content-type", "cache-control", "mcp-protocol-version"])


Forwarded = collections.namedtuple("Forwarded", "client_ip request_id client_headers")


class UpstreamUnavailable(Exception):
    """The upstream couldn't be reached, or broke the connection."""


class UpstreamTimeout(Exception):
    """The upstream stopped answering for longer than the read timeout."""


def tls_context(config):
    context = ssl.create_default_context(cafile=config.upstream_ca_bundle)
    context.check_hostname = config.upstream_verify_hostname
    return context


@contextlib.contextmanager
def _translated_errors():
    try:
        yield
    except socket.timeout as exc:
        raise UpstreamTimeout(str(exc)) from exc
    except (OSError, http.client.HTTPException) as exc:
        raise UpstreamUnavailable(str(exc)) from exc


class Response:
    """An upstream response whose body is read on demand. Read errors raise Upstream* exceptions."""

    def __init__(self, raw):
        self._raw = raw
        self.status = raw.status
        self.headers = [(n, v) for n, v in raw.getheaders() if n.lower() in _RETURNED_RESPONSE_HEADERS]
        length = raw.getheader("Content-Length")
        self.length = int(length) if length is not None and length.isdigit() else None
        self._remaining = self.length

    def read_chunk(self, size):
        """Return the next piece of the body, at most ``size`` bytes, or b"" at its end."""
        with _translated_errors():
            if self._remaining is None:
                return self._raw.read1(size)
            chunk = self._raw.read(min(size, self._remaining))
        if self._remaining and not chunk:
            # http.client returns b"" rather than raising when the body is cut short.
            raise UpstreamUnavailable(f"upstream closed with {self._remaining} body bytes unsent")
        self._remaining -= len(chunk)
        return chunk


class Upstream:
    def __init__(self, config):
        self._url = urllib.parse.urlsplit(config.upstream_url)
        self._context = tls_context(config)
        self._connect_timeout = config.upstream_connect_timeout
        self._read_timeout = config.upstream_timeout

    @contextlib.contextmanager
    def post(self, token, body, forwarded):
        """POST ``body`` with the mapped ``token`` on behalf of a ``Forwarded`` client; yield a Response."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": "Bearer " + token,
            "X-Forwarded-For": forwarded.client_ip,
            "X-MCP-Request-Id": forwarded.request_id,
        }
        for name, shape in _PASSTHROUGH_REQUEST_HEADERS.items():
            value = forwarded.client_headers.get(name)
            if value is not None and shape.fullmatch(value):
                headers[name] = value
        conn = http.client.HTTPSConnection(
            self._url.hostname, self._url.port or 443, context=self._context, timeout=self._connect_timeout
        )
        try:
            try:
                conn.connect()
            except (OSError, http.client.HTTPException) as exc:
                # A connect timeout means splunkd is unreachable, not slow: report it as unavailable.
                raise UpstreamUnavailable(str(exc)) from exc
            conn.sock.settimeout(self._read_timeout)
            with _translated_errors():
                conn.request("POST", self._url.path or "/", body=body, headers=headers)
                raw = conn.getresponse()
            yield Response(raw)
        finally:
            conn.close()
