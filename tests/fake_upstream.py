"""An HTTPS stand-in for the Splunk MCP Server app that records what it receives."""

import json
import ssl
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@dataclass
class Received:
    method: str
    path: str
    headers: dict
    body: bytes

    def json(self):
        return json.loads(self.body)


class FakeUpstream:
    def __init__(self, issued):
        self.received = []
        # Knobs a test can turn to change how the upstream answers.
        self.status = 200
        self.headers = {}
        self.gate = None  # a threading.Event the handler waits on before answering
        self.delay = 0.0
        self.chunked = False  # send the body with chunked transfer encoding
        self.truncate = False  # promise more body than is sent, then hang up
        self.result = None  # the JSON-RPC result to send, instead of a tools/list answer
        self._lock = threading.Lock()
        upstream = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                with upstream._lock:
                    upstream.received.append(Received(self.command, self.path, dict(self.headers.items()), body))
                if upstream.gate is not None:
                    upstream.gate.wait(10)
                time.sleep(upstream.delay)
                payload = json.dumps(upstream.answer(body)).encode()
                self.send_response(upstream.status)
                self.send_header("Content-Type", "application/json")
                for name, value in upstream.headers.items():
                    self.send_header(name, value)
                if upstream.chunked:
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    for i in range(0, len(payload), 7):
                        piece = payload[i : i + 7]
                        self.wfile.write(b"%x\r\n%s\r\n" % (len(piece), piece))
                    self.wfile.write(b"0\r\n\r\n")
                else:
                    self.send_header("Content-Length", str(len(payload) + (100 if upstream.truncate else 0)))
                    self.end_headers()
                    self.wfile.write(payload)
                    if upstream.truncate:
                        self.close_connection = True

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(issued.cert), str(issued.key))
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.socket = context.wrap_socket(self._server.socket, server_side=True)
        self._thread = threading.Thread(target=self._server.serve_forever, args=(0.05,), daemon=True)

    def answer(self, body):
        try:
            request_id = json.loads(body).get("id")
        except ValueError:
            request_id = None
        result = self.result if self.result is not None else {"tools": [{"name": "splunk_run_query"}]}
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @property
    def url(self):
        host, port = self._server.server_address
        return f"https://{host}:{port}/services/mcp"

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._server.shutdown()
        self._server.server_close()
