"""An HTTPS stand-in for splunkd's REST API that serves fixture responses."""

import json
import ssl
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from mtls_bridge.splunk_config import AUDIT_LOG

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "splunkd"

APP_PATH = "/servicesNS/nobody/TA-mtls-bridge"
AUDIT_INPUT_PATH = APP_PATH + "/configs/conf-inputs/" + urllib.parse.quote("monitor://" + AUDIT_LOG, safe="")
MONITOR_RELOAD_PATH = APP_PATH + "/data/inputs/monitor/_reload"
ROUTES = {
    APP_PATH + "/ta_mtls_bridge_settings/listener": "settings_listener.json",
    APP_PATH + "/ta_mtls_bridge_settings/audit": "settings_audit.json",
    AUDIT_INPUT_PATH: "conf_inputs_audit.json",
    APP_PATH + "/ta_mtls_bridge_mappings": "mappings.json",
    "/services/configs/conf-server/sslConfig": "conf_server_sslconfig.json",
}


class FakeSplunkd:
    def __init__(self, issued, session_key, replacements):
        self.session_key = session_key
        self.requests = []
        # (path, form fields) of each POST, in order.
        self.posts = []
        self.reloads = 0  # GETs of the monitor inputs' _reload endpoint
        # Edits tests make to a fixture's first entry content, by fixture file name.
        self.content_overrides = {}
        # Fixture file names to serve with no entries.
        self.empty = set()
        self._replacements = replacements
        splunkd = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_GET(self):
                url = urllib.parse.urlsplit(self.path)
                splunkd.requests.append((url.path, urllib.parse.parse_qs(url.query), dict(self.headers.items())))
                if self.headers.get("Authorization") != "Splunk " + splunkd.session_key:
                    self._reply(401, splunkd.fixture("unauthorized.json"))
                elif url.path == MONITOR_RELOAD_PATH:
                    splunkd.reloads += 1
                    self._reply(200, {"entry": [], "messages": []})
                elif url.path in ROUTES:
                    self._reply(200, splunkd.fixture(ROUTES[url.path]))
                else:
                    self._reply(404, {"messages": [{"type": "ERROR", "text": "Not Found"}]})

            def do_POST(self):
                url = urllib.parse.urlsplit(self.path)
                length = int(self.headers.get("Content-Length", 0))
                form = urllib.parse.parse_qs(self.rfile.read(length).decode())
                if self.headers.get("Authorization") != "Splunk " + splunkd.session_key:
                    self._reply(401, splunkd.fixture("unauthorized.json"))
                    return
                fields = {name: values[0] for name, values in form.items() if name != "output_mode"}
                splunkd.posts.append((url.path, fields))
                self._reply(200, {"entry": [], "messages": []})

            def _reply(self, status, document):
                payload = json.dumps(document).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(issued.cert), str(issued.key))
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.socket = context.wrap_socket(self._server.socket, server_side=True)
        self._thread = threading.Thread(target=self._server.serve_forever, args=(0.05,), daemon=True)

    def fixture(self, name):
        text = (FIXTURES / name).read_text()
        for placeholder, value in self._replacements.items():
            text = text.replace(placeholder, value)
        document = json.loads(text)
        if name in self.empty:
            document["entry"] = []
        overrides = self.content_overrides.get(name)
        if overrides:
            content = document["entry"][0]["content"]
            for key, value in overrides.items():
                if value is None:
                    content.pop(key, None)
                else:
                    content[key] = value
        return document

    @property
    def uri(self):
        host, port = self._server.server_address
        return f"https://{host}:{port}"

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._server.shutdown()
        self._server.server_close()
