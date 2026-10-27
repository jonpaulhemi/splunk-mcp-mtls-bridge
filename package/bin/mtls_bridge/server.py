"""The mTLS listener that forwards MCP requests upstream with a mapped bearer token."""

import contextlib
import http.client
import json
import logging
import socket
import ssl
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import identity, resolver
from .upstream import Upstream, returned_headers

log = logging.getLogger(__name__)

# ECDHE with AEAD only, for TLS 1.2. TLS 1.3 suites are configured separately by OpenSSL.
_TLS12_CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20"

_COPY_CHUNK = 64 * 1024

_ERR_INVALID_REQUEST = -32600
# Codes in JSON-RPC's implementation-defined server error range.
_ERR_FORBIDDEN = -32001
_ERR_UPSTREAM = -32002
_ERR_CREDENTIAL = -32003
_ERR_BUSY = -32004
_ERR_TOO_LARGE = -32005


def listener_context(config):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(_TLS12_CIPHERS)
    context.options |= ssl.OP_NO_COMPRESSION | ssl.OP_CIPHER_SERVER_PREFERENCE
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=config.ca_bundle)
    context.load_cert_chain(config.server_cert, config.server_key, password=config.server_key_password)
    return context


def _parse(body):
    try:
        message = json.loads(body)
    except ValueError:
        return None
    return message if isinstance(message, dict) else None


class _ConcurrencyLimiter:
    """Caps in-flight requests per mapping identity."""

    def __init__(self, limit):
        self._limit = limit
        self._in_flight = {}
        self._lock = threading.Lock()

    @contextlib.contextmanager
    def slot(self, mapping):
        """Yield True while holding a slot for ``mapping``, or False if it has none free."""
        key = (mapping.issuer.lower(), mapping.identity_type.upper(), mapping.identity_value)
        with self._lock:
            acquired = self._in_flight.get(key, 0) < self._limit
            if acquired:
                self._in_flight[key] = self._in_flight.get(key, 0) + 1
        try:
            yield acquired
        finally:
            if acquired:
                with self._lock:
                    self._in_flight[key] -= 1
                    if not self._in_flight[key]:
                        del self._in_flight[key]


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mtls-bridge"
    sys_version = ""

    def log_message(self, fmt, *args):
        log.debug("%s %s", self.address_string(), fmt % args)

    def do_GET(self):
        self._method_not_allowed()

    def do_DELETE(self):
        self._method_not_allowed()

    def do_POST(self):
        bridge = self.server.bridge
        body = self._read_body(bridge.config.max_body_bytes)
        if body is None:
            return
        message = _parse(body)
        request_id = message.get("id") if message else None
        peer = identity.from_peercert(self.connection.getpeercert())
        try:
            mapping = resolver.resolve(bridge.config.mappings, peer)
        except resolver.Rejection as rejection:
            self._send_rpc_error(403, _ERR_FORBIDDEN, f"client certificate is {rejection.reason}", request_id)
            return
        if message and message.get("method") == "ping":
            # Answered here so health checks don't spend the upstream's shared rate limit.
            self._send_json(200, {"jsonrpc": "2.0", "id": request_id, "result": {}})
            return
        with bridge.limiter.slot(mapping) as acquired:
            if not acquired:
                self._send_rpc_error(429, _ERR_BUSY, "too many concurrent requests for this client", request_id)
                return
            self._forward(bridge, mapping, body, request_id)

    def _forward(self, bridge, mapping, body, request_id):
        try:
            with bridge.upstream.post(
                mapping.token, body, self.headers, self.client_address[0], uuid.uuid4().hex
            ) as response:
                if response.status == 401:
                    response.read()
                    bridge.token_rejected(mapping)
                    self._send_rpc_error(502, _ERR_CREDENTIAL, "bridge credential invalid", request_id)
                    return
                self._relay(response)
        except socket.timeout:
            self._send_rpc_error(504, _ERR_UPSTREAM, "upstream MCP server timed out", request_id)
        except (OSError, http.client.HTTPException) as exc:
            log.warning("upstream request failed: %s", exc)
            self._send_rpc_error(502, _ERR_UPSTREAM, "upstream MCP server unavailable", request_id)

    def _relay(self, response):
        length = response.getheader("Content-Length")
        if length is None or not length.isdigit():
            self._send(response.status, returned_headers(response), response.read())
            return
        self.send_response(response.status)
        for name, value in returned_headers(response):
            self.send_header(name, value)
        self.send_header("Content-Length", length)
        self.end_headers()
        while True:
            chunk = response.read(_COPY_CHUNK)
            if not chunk:
                break
            self.wfile.write(chunk)

    def _read_body(self, limit):
        """Read the request body, or answer with an error and return None."""
        length = self.headers.get("Content-Length")
        error = None
        if length is None:
            error = (411, "Content-Length required")
        elif not length.isdigit():
            error = (400, "invalid Content-Length")
        elif int(length) > limit:
            error = (413, f"request body exceeds {limit} bytes")
        if error:
            # The unread body would corrupt the next request on this connection.
            self.close_connection = True
            status, message = error
            self._send_rpc_error(status, _ERR_TOO_LARGE if status == 413 else _ERR_INVALID_REQUEST, message)
            return None
        return self.rfile.read(int(length))

    def _method_not_allowed(self):
        self.close_connection = True
        payload = b'{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"only POST is supported"}}'
        self._send(405, [("Content-Type", "application/json"), ("Allow", "POST")], payload)

    def _send_rpc_error(self, status, code, message, request_id=None):
        self._send_json(status, {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}})

    def _send_json(self, status, document):
        self._send(status, [("Content-Type", "application/json")], json.dumps(document).encode())

    def _send(self, status, headers, payload):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class _Listener(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, bridge):
        self.bridge = bridge
        config = bridge.config
        super().__init__((config.listen_host, config.listen_port), _Handler)
        self.socket = bridge.tls_context.wrap_socket(self.socket, server_side=True, do_handshake_on_connect=False)

    def finish_request(self, request, client_address):
        # The handshake runs here, in the worker thread, so a slow client can't stall accept().
        request.settimeout(self.bridge.config.handshake_timeout)
        try:
            request.do_handshake()
        except (ssl.SSLError, OSError) as exc:
            log.info("TLS handshake failed from %s:%s: %s", client_address[0], client_address[1], exc)
            return
        request.settimeout(self.bridge.config.client_timeout)
        super().finish_request(request, client_address)


class BridgeServer:
    """The bridge. ``on_token_rejected`` is called with a Mapping whose token the upstream refused."""

    def __init__(self, config, on_token_rejected=None):
        self.config = config
        self.tls_context = listener_context(config)
        self.upstream = Upstream(config)
        self.limiter = _ConcurrencyLimiter(config.max_concurrent_per_identity)
        self._on_token_rejected = on_token_rejected
        self._listener = _Listener(self)
        self._thread = threading.Thread(
            target=self._listener.serve_forever, args=(0.1,), name="mtls-bridge", daemon=True
        )

    @property
    def address(self):
        return self._listener.server_address[:2]

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._listener.shutdown()
        self._listener.server_close()

    def token_rejected(self, mapping):
        log.warning("upstream rejected the token for account %s", mapping.account)
        if self._on_token_rejected is not None:
            self._on_token_rejected(mapping)
