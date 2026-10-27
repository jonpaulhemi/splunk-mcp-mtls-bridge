"""The mTLS listener that forwards MCP requests upstream with a mapped bearer token."""

import collections
import contextlib
import dataclasses
import hashlib
import json
import logging
import socket
import ssl
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import resolver
from .audit import AuditLog, HandshakeFailures
from .upstream import Forwarded, Upstream, UpstreamTimeout, UpstreamUnavailable

log = logging.getLogger(__name__)

# ECDHE with AEAD only, for TLS 1.2. TLS 1.3 suites are configured separately by OpenSSL.
_TLS12_CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20"

_COPY_CHUNK = 64 * 1024
# Tool arguments beyond this many bytes of JSON are cut from audit events.
_AUDIT_ARGUMENT_BYTES = 4096

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


def _tls_fingerprint(config):
    """A digest of everything the listener's SSLContext is built from, so a replaced file is noticed."""
    digest = hashlib.sha256()
    for path in (config.ca_bundle, config.server_cert, config.server_key):
        with open(path, "rb") as handle:
            digest.update(hashlib.sha256(handle.read()).digest())
    digest.update(repr(config.server_key_password).encode())
    return digest.hexdigest()


class ApplyError(Exception):
    """Part of a new config couldn't be applied; the rest was."""


_TLS_FIELDS = ("ca_bundle", "server_cert", "server_key", "server_key_password")
_UPSTREAM_FIELDS = ("upstream_url", "upstream_ca_bundle", "upstream_verify_hostname")
_ADDRESS_FIELDS = ("listen_host", "listen_port")


def _fields(config, names):
    return {name: getattr(config, name) for name in names}


# What one request is served with, swapped as a whole when the config changes.
_Live = collections.namedtuple("_Live", "config tls_context upstream")


class _ConcurrencyLimiter:
    """Caps in-flight requests per mapping identity."""

    def __init__(self, limit):
        self.limit = limit
        self._in_flight = {}
        self._lock = threading.Lock()

    @contextlib.contextmanager
    def slot(self, mapping):
        """Yield True while holding a slot for ``mapping``, or False if it has none free."""
        key = mapping.key
        with self._lock:
            acquired = self._in_flight.get(key, 0) < self.limit
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
        self._audited(self._method_not_allowed)

    def do_DELETE(self):
        self._audited(self._method_not_allowed)

    def do_POST(self):
        self._audited(self._post)

    def _audited(self, handle):
        """Run ``handle`` for this request, then write its one audit event."""
        started = time.monotonic()
        # Requests already running keep the config they started with when a new one is applied.
        self._live = self.server.bridge.live
        # One id per request: returned to the client and sent upstream, so both sides' logs can be joined.
        self.bridge_request_id = uuid.uuid4().hex
        self._status = None
        self._aborted = None  # why the response was cut short after its headers went out
        self._message = {}
        self._peer = self._mapping = self._rejection = None
        try:
            try:
                self._peer = resolver.peer_of(self.connection.getpeercert(binary_form=True))
                self._mapping = resolver.resolve(self._live.config.mappings, self._peer)
            except resolver.Rejection as rejection:
                self._rejection = rejection.reason
            handle()
        finally:
            try:
                self._audit(time.monotonic() - started)
            except Exception:
                log.exception("cannot write audit event for request %s", self.bridge_request_id)

    def _audit(self, elapsed):
        fields = {
            "request_id": self.bridge_request_id,
            "peer_ip": self.client_address[0],
            "http_method": self.command,
            "method": self._message.get("method"),
            "status": self._status,
        }
        if self._aborted:
            fields["aborted"] = self._aborted
        audit = self.server.bridge.audit
        if self._rejection is not None:
            audit.write("rejection", reason=self._rejection, **fields, **(self._peer.describe() if self._peer else {}))
        elif self._mapping is not None:
            audit.write("call", **fields, **self._call_fields(elapsed))

    def _call_fields(self, elapsed):
        mapping = self._mapping
        fields = dict(
            issuer=self._peer.issuer,
            identity_type=mapping.identity_type,
            identity=mapping.identity_value,
            user=mapping.account,
            latency_ms=round(elapsed * 1000, 1),
        )
        params = self._message.get("params")
        if self._message.get("method") == "tools/call" and isinstance(params, dict):
            arguments = json.dumps(params.get("arguments"), ensure_ascii=False).encode()
            fields.update(
                tool=params.get("name"),
                arguments=arguments[:_AUDIT_ARGUMENT_BYTES].decode("utf-8", "ignore"),
                arguments_truncated=len(arguments) > _AUDIT_ARGUMENT_BYTES,
            )
        return fields

    def _post(self):
        bridge = self.server.bridge
        body = self._read_body(self._live.config.max_body_bytes)
        if body is None:
            return
        message = self._message = _parse(body) or {}
        rpc_id = message.get("id")
        if self._rejection is not None:
            self._send_rpc_error(403, _ERR_FORBIDDEN, f"client certificate is {self._rejection}", rpc_id)
            return
        mapping = self._mapping
        if message.get("method") == "ping":
            # Answered here so health checks don't spend the upstream's shared rate limit.
            self._send_json(200, {"jsonrpc": "2.0", "id": rpc_id, "result": {}})
            return
        with bridge.limiter.slot(mapping) as acquired:
            if not acquired:
                self._send_rpc_error(429, _ERR_BUSY, "too many concurrent requests for this client", rpc_id)
                return
            self._forward(bridge, mapping, body, rpc_id)

    def _forward(self, bridge, mapping, body, rpc_id):
        forwarded = Forwarded(self.client_address[0], self.bridge_request_id, self.headers)
        self._headers_sent = False
        try:
            with self._live.upstream.post(mapping.token, body, forwarded) as response:
                if response.status == 401:
                    bridge.token_rejected(mapping)
                    self._send_rpc_error(502, _ERR_CREDENTIAL, "bridge credential invalid", rpc_id)
                    return
                self._relay(response)
        except UpstreamTimeout:
            self._fail(504, "upstream MCP server timed out", rpc_id)
        except UpstreamUnavailable as exc:
            log.warning("upstream request failed: %s", exc)
            self._fail(502, "upstream MCP server unavailable", rpc_id)
        except OSError as exc:
            # The client went away or stalled mid-response.
            log.debug("client connection failed: %s", exc)
            self._aborted = "client connection failed"
            self.close_connection = True

    def _fail(self, status, message, rpc_id):
        if self._headers_sent:
            # Too late for an error response: cut the connection so the client sees a truncated body.
            self._aborted = message
            self.close_connection = True
        else:
            self._send_rpc_error(status, _ERR_UPSTREAM, message, rpc_id)

    def _relay(self, response):
        if response.length is not None:
            self._send_headers(response.status, response.headers + [("Content-Length", str(response.length))])
            write = self.wfile.write
        else:
            self._send_headers(response.status, response.headers + [("Transfer-Encoding", "chunked")])
            write = self._write_chunk
        while True:
            chunk = response.read_chunk(_COPY_CHUNK)
            if not chunk:
                break
            write(chunk)
        if response.length is None:
            self.wfile.write(b"0\r\n\r\n")

    def _write_chunk(self, chunk):
        self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))

    def _read_body(self, limit):
        """Read the request body, or answer with an error and return None."""
        length = self.headers.get("Content-Length")
        error = None
        if length is None:
            error = (411, _ERR_INVALID_REQUEST, "Content-Length required")
        elif not length.isdigit():
            error = (400, _ERR_INVALID_REQUEST, "invalid Content-Length")
        elif int(length) > limit:
            error = (413, _ERR_TOO_LARGE, f"request body exceeds {limit} bytes")
        if error:
            # The unread body would corrupt the next request on this connection.
            self.close_connection = True
            self._send_rpc_error(*error)
            return None
        return self.rfile.read(int(length))

    def _method_not_allowed(self):
        self.close_connection = True
        self._send_rpc_error(405, _ERR_INVALID_REQUEST, "only POST is supported", headers=[("Allow", "POST")])

    def _send_rpc_error(self, status, code, message, rpc_id=None, headers=()):
        document = {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}
        self._send_json(status, document, headers)

    def _send_json(self, status, document, headers=()):
        payload = json.dumps(document).encode()
        self._send_headers(
            status, [("Content-Type", "application/json"), *headers, ("Content-Length", str(len(payload)))]
        )
        self.wfile.write(payload)

    def _send_headers(self, status, headers):
        self._status = status
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("X-MCP-Request-Id", self.bridge_request_id)
        self.end_headers()
        self._headers_sent = True


class _Listener(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, bridge, address):
        self.bridge = bridge
        super().__init__(address, _Handler)

    def finish_request(self, request, client_address):
        # TLS starts here, in the connection's worker thread, so a slow client can't stall accept(),
        # and with the SSLContext current when the connection is served, so a replaced CA bundle or
        # cert applies to new handshakes.
        live = self.bridge.live
        request.settimeout(live.config.handshake_timeout)
        tls = live.tls_context.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
        try:
            self._handshake_and_handle(tls, client_address, live.config)
        finally:
            with contextlib.suppress(OSError):
                tls.shutdown(socket.SHUT_WR)
            tls.close()

    def _handshake_and_handle(self, tls, client_address, config):
        try:
            tls.do_handshake()
        except (ssl.SSLError, OSError) as exc:
            log.debug("TLS handshake failed from %s:%s: %s", client_address[0], client_address[1], exc)
            reason = (
                getattr(exc, "verify_message", None) or getattr(exc, "reason", None) or str(exc) or type(exc).__name__
            )
            self.bridge.handshake_failures.record(
                client_address[0], client_address[1], getattr(exc, "verify_code", None), reason
            )
            return
        tls.settimeout(config.client_timeout)
        super().finish_request(tls, client_address)


class BridgeServer:
    """The bridge. ``on_token_rejected`` is called with a Mapping whose token the upstream refused."""

    def __init__(self, config, on_token_rejected=None):
        self._tls_fingerprint = _tls_fingerprint(config)
        self.live = _Live(config, listener_context(config), Upstream(config))
        self.limiter = _ConcurrencyLimiter(config.max_concurrent_per_identity)
        self.audit = AuditLog(config.audit_log)
        self.handshake_failures = HandshakeFailures(self.audit, config.handshake_audit_window)
        self._on_token_rejected = on_token_rejected
        self._listener = _Listener(self, config.listen_address)

    @property
    def config(self):
        return self.live.config

    @property
    def address(self):
        return self._listener.server_address[:2]

    def start(self):
        self.handshake_failures.start()
        self._start_serving(self._listener)
        return self

    def apply(self, config):
        """Serve ``config`` from the next request on. Call it from one thread only, as ``stop`` is.

        Mappings and tokens always apply, so a deleted mapping is revoked even when the rest can't be.
        A changed CA bundle, cert, key or key password rebuilds the SSLContext for new connections
        (open keep-alive connections keep theirs until they close); a changed bind address or port
        moves the listener. If either fails, or the upstream settings can't be loaded, those parts
        keep their current values and ApplyError says why. The audit file and handshake window are
        fixed at startup.
        """
        live = self.live
        problems = []
        fingerprint, context = self._tls_fingerprint, live.tls_context
        try:
            new_fingerprint = _tls_fingerprint(config)
            if new_fingerprint != fingerprint:
                fingerprint, context = new_fingerprint, listener_context(config)
        except (OSError, ValueError) as exc:
            problems.append(f"listener certificate or CA bundle: {exc}")
            config = dataclasses.replace(config, **_fields(live.config, _TLS_FIELDS))
        try:
            upstream = Upstream(config)
        except (OSError, ValueError) as exc:
            problems.append(f"MCP Server connection: {exc}")
            config = dataclasses.replace(config, **_fields(live.config, _UPSTREAM_FIELDS))
            upstream = live.upstream
        listener = None
        if config.listen_address != live.config.listen_address:
            try:
                listener = self._bind(config.listen_address)
            except OSError as exc:
                problems.append(f"cannot listen on {config.listen_host}:{config.listen_port}: {exc}")
                config = dataclasses.replace(config, **_fields(live.config, _ADDRESS_FIELDS))
        self.live = _Live(config, context, upstream)
        self._tls_fingerprint = fingerprint
        self.limiter.limit = config.max_concurrent_per_identity
        if listener is not None and listener is not self._listener:
            old, self._listener = self._listener, listener
            self._start_serving(listener)
            old.shutdown()
            old.server_close()
            log.info("listener moved to %s:%s", *self.address)
        if problems:
            raise ApplyError("; ".join(problems))

    def _bind(self, address):
        """A listener on ``address``. Raises OSError, leaving the current listener serving, if it can't bind.

        If the port is held by the current listener (say a host change from 0.0.0.0 to 127.0.0.1 on
        the same port), the current one closes first and comes back if the new bind fails.
        """
        try:
            return _Listener(self, address)
        except OSError:
            current = self.live.config.listen_address
            if address[1] != current[1] or address[1] == 0:
                raise
        self._listener.shutdown()
        self._listener.server_close()
        try:
            return _Listener(self, address)
        except OSError:
            self._listener = _Listener(self, current)
            self._start_serving(self._listener)
            raise

    def _start_serving(self, listener):
        threading.Thread(target=listener.serve_forever, args=(0.1,), name="mtls-bridge", daemon=True).start()

    def stop(self):
        self._listener.shutdown()
        self._listener.server_close()
        self.handshake_failures.stop()
        self.audit.close()

    def token_rejected(self, mapping):
        log.warning("upstream rejected the token for account %s", mapping.account)
        if self._on_token_rejected is not None:
            self._on_token_rejected(mapping)
