"""The mTLS listener that forwards MCP requests upstream with a mapped bearer token."""

import http.client
import json
import logging
import ssl
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import identity, resolver

log = logging.getLogger(__name__)

# ECDHE with AEAD only, for TLS 1.2. TLS 1.3 suites are configured separately by OpenSSL.
_TLS12_CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20"

_FORWARDED_RESPONSE_HEADERS = ("Content-Type",)

# JSON-RPC error codes in the implementation-defined server error range.
_ERR_FORBIDDEN = -32001


def listener_context(config):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(_TLS12_CIPHERS)
    context.options |= ssl.OP_NO_COMPRESSION | ssl.OP_CIPHER_SERVER_PREFERENCE
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=config.ca_bundle)
    context.load_cert_chain(config.server_cert, config.server_key, password=config.server_key_password)
    return context


def upstream_context(config):
    context = ssl.create_default_context(cafile=config.upstream_ca_bundle)
    context.check_hostname = config.upstream_verify_hostname
    return context


def _request_id(body):
    try:
        message = json.loads(body)
    except ValueError:
        return None
    return message.get("id") if isinstance(message, dict) else None


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mtls-bridge"
    sys_version = ""

    def log_message(self, fmt, *args):
        log.debug("%s %s", self.address_string(), fmt % args)

    def do_POST(self):
        bridge = self.server.bridge
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        peer = identity.from_peercert(self.connection.getpeercert())
        try:
            mapping = resolver.resolve(bridge.config.mappings, peer)
        except resolver.Rejection as rejection:
            self._send_rpc_error(403, _ERR_FORBIDDEN, f"client certificate is {rejection.reason}", body)
            return
        status, headers, payload = bridge.forward(mapping, body)
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_rpc_error(self, status, code, message, body):
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": _request_id(body), "error": {"code": code, "message": message}}
        ).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
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
        request.settimeout(self.bridge.config.upstream_timeout)
        super().finish_request(request, client_address)


class BridgeServer:
    def __init__(self, config):
        self.config = config
        self.tls_context = listener_context(config)
        self._upstream_context = upstream_context(config)
        self._upstream = urllib.parse.urlsplit(config.upstream_url)
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

    def serve_forever(self):
        self._listener.serve_forever()

    def forward(self, mapping, body):
        conn = http.client.HTTPSConnection(
            self._upstream.hostname,
            self._upstream.port or 443,
            context=self._upstream_context,
            timeout=self.config.upstream_timeout,
        )
        try:
            conn.request(
                "POST",
                self._upstream.path or "/",
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "Authorization": "Bearer " + mapping.token,
                },
            )
            response = conn.getresponse()
            payload = response.read()
            headers = [(n, v) for n, v in response.getheaders() if n.title() in _FORWARDED_RESPONSE_HEADERS]
            return response.status, headers, payload
        finally:
            conn.close()
