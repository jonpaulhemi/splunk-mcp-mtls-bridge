"""The audit trail: one JSON line per call, rejection or burst of failed handshakes.

Splunk ingests the file with sourcetype mtls_bridge:audit. Callers pass only what may be logged:
never results, tokens or Authorization header values.
"""

import datetime
import json
import logging
import logging.handlers
import os
import threading
import time

_MAX_BYTES = 25 * 1024 * 1024
_BACKUPS = 5


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


class AuditLog:
    """Writes events to ``path``, or nowhere if ``path`` is None."""

    def __init__(self, path):
        self._logger = logging.Logger("mtls_bridge.audit")
        if path is None:
            self._logger.addHandler(logging.NullHandler())
            return
        os.makedirs(os.path.dirname(path), exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(path, maxBytes=_MAX_BYTES, backupCount=_BACKUPS)
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(handler)

    def write(self, event, **fields):
        self._logger.info(json.dumps({"time": _now(), "event": event, **fields}, ensure_ascii=False))

    def close(self):
        for handler in self._logger.handlers:
            handler.close()


class HandshakeFailures:
    """Collapses failed handshakes into one event per peer IP per ``window`` seconds, with a count.

    Each event carries the first failure's port, verify code and reason.
    """

    def __init__(self, audit, window):
        self._audit = audit
        self._window = window
        self._pending = {}  # ip -> [started (monotonic), time, fields, count]
        self._lock = threading.Lock()
        self._stopping = threading.Event()
        self._thread = threading.Thread(target=self._run, name="mtls-bridge-handshake-audit", daemon=True)

    def start(self):
        self._thread.start()

    def record(self, ip, port, verify_code, reason):
        with self._lock:
            entry = self._pending.get(ip)
            if entry is None:
                fields = {"peer_ip": ip, "peer_port": port, "verify_code": verify_code, "reason": reason}
                self._pending[ip] = [time.monotonic(), _now(), fields, 1]
            else:
                entry[3] += 1

    def stop(self):
        self._stopping.set()
        self._thread.join()
        self._flush(everything=True)

    def _run(self):
        while not self._stopping.wait(min(self._window, 1.0)):
            self._flush()

    def _flush(self, everything=False):
        now = time.monotonic()
        with self._lock:
            due = [ip for ip, entry in self._pending.items() if everything or now - entry[0] >= self._window]
            entries = [self._pending.pop(ip) for ip in due]
        for _, first_seen, fields, count in entries:
            self._audit.write("handshake_failure", first_seen=first_seen, count=count, **fields)
