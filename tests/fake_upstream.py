"""An HTTPS stand-in for the Splunk MCP Server app that records what it receives."""

import json
import ssl
import threading
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
                payload = json.dumps(upstream.tools_list_result(body)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(issued.cert), str(issued.key))
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.socket = context.wrap_socket(self._server.socket, server_side=True)
        self._thread = threading.Thread(target=self._server.serve_forever, args=(0.05,), daemon=True)

    @staticmethod
    def tools_list_result(body):
        try:
            request_id = json.loads(body).get("id")
        except ValueError:
            request_id = None
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": [{"name": "splunk_run_query"}]}}

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
