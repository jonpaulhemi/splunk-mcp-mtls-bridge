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
from dataclasses import dataclass

_MAX_BYTES = 25 * 1024 * 1024
_BACKUPS = 5
# Distinct IPs whose failed handshakes are held at once; more flush the oldest early.
_MAX_PENDING_IPS = 10000


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

    def write(self, event, at=None, **fields):
        """Write one event, timestamped ``at`` (an ISO 8601 string) or now."""
        self._logger.info(json.dumps({"time": at or _now(), "event": event, **fields}, ensure_ascii=False))

    def close(self):
        for handler in self._logger.handlers:
            handler.close()


@dataclass
class _Burst:
    started: float  # time.monotonic() of the first failure
    first_seen: str
    fields: dict
    count: int = 1


class HandshakeFailures:
    """Collapses failed handshakes into one event per peer IP per ``window`` seconds, with a count.

    Each event is timestamped at the first failure and carries its port, verify code and reason.
    """

    def __init__(self, audit, window):
        self._audit = audit
        self._window = window
        self._pending = {}  # ip -> _Burst
        self._lock = threading.Lock()
        self._stopping = threading.Event()
        self._thread = threading.Thread(target=self._run, name="mtls-bridge-handshake-audit", daemon=True)

    def start(self):
        self._thread.start()

    def record(self, ip, port, verify_code, reason):
        fields = {"peer_ip": ip, "peer_port": port, "verify_code": verify_code, "reason": reason}
        if self._stopping.is_set():
            # A handshake that finished during shutdown, after the last flush.
            self._emit(_Burst(time.monotonic(), _now(), fields))
            return
        evicted = None
        with self._lock:
            burst = self._pending.get(ip)
            if burst is not None:
                burst.count += 1
                return
            if len(self._pending) >= _MAX_PENDING_IPS:
                # Dicts keep insertion order, so the first key has waited longest.
                evicted = self._pending.pop(next(iter(self._pending)))
            self._pending[ip] = _Burst(time.monotonic(), _now(), fields)
        if evicted is not None:
            self._emit(evicted)

    def stop(self):
        self._stopping.set()
        if self._thread.ident is not None:
            self._thread.join()
        self._flush(everything=True)

    def _run(self):
        while not self._stopping.wait(min(self._window, 1.0)):
            self._flush()

    def _flush(self, everything=False):
        now = time.monotonic()
        with self._lock:
            due = [ip for ip, burst in self._pending.items() if everything or now - burst.started >= self._window]
            bursts = [self._pending.pop(ip) for ip in due]
        for burst in bursts:
            self._emit(burst)

    def _emit(self, burst):
        self._audit.write("handshake_failure", at=burst.first_seen, count=burst.count, **burst.fields)
