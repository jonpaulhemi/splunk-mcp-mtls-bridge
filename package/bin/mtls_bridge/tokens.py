"""Watches each mapping's token: its admin-entered expiry date, and whether the upstream accepts it.

A token is checked upstream once, when it first appears in the config; after that only real calls
change its status. Nothing here ever logs or returns a token.
"""

import hashlib
import json
import logging
import threading
import uuid

from . import __version__
from .upstream import Forwarded, UpstreamTimeout, UpstreamUnavailable

log = logging.getLogger(__name__)

EXPIRY_WARNING_DAYS = 14

OK = "ok"  # the upstream accepted the token
INVALID = "invalid"  # the upstream answered 401
UNCHECKED = "unchecked"  # not checked yet, or the upstream couldn't be reached
UNVERIFIED = "unverified"  # the upstream answered the check with neither success nor 401

# The MCP revision the check's initialize offers; any answer but 401 says the token got through.
_PROTOCOL_VERSION = "2025-06-18"


def _token_id(mapping):
    """Tells a mapping's token apart from its earlier and later tokens without holding the token."""
    return (mapping.key, hashlib.sha256(mapping.token.encode()).hexdigest())


def days_remaining(mapping, today):
    return None if mapping.token_expiry is None else (mapping.token_expiry - today).days


def expiry_status(mapping, today):
    days = days_remaining(mapping, today)
    if days is None:
        return None
    if days < 0:
        return "expired"
    return "expiring" if days <= EXPIRY_WARNING_DAYS else "ok"


def _check_body():
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "mtls-bridge-token-check",
            "method": "initialize",
            "params": {
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "TA-mtls-bridge", "version": __version__},
            },
        }
    ).encode()


class TokenMonitor:
    def __init__(self, audit):
        self._audit = audit
        self._status = {}  # token id -> OK, INVALID or UNVERIFIED
        self._warned = {}  # token id -> the day its last expiry warning went out
        self._lock = threading.Lock()
        self._checker = None

    def status(self, mapping):
        with self._lock:
            return self._status.get(_token_id(mapping), UNCHECKED)

    def accepted(self, mapping):
        self._set(mapping, OK)

    def rejected(self, mapping):
        self._set(mapping, INVALID)

    def checking(self):
        """True while new tokens are being checked upstream."""
        return self._checker is not None and self._checker.is_alive()

    def check(self, mappings, upstream, today):
        """Warn about tokens near or past expiry, at most once a day each, and check new tokens upstream
        in the background."""
        current = {_token_id(m) for m in mappings}
        with self._lock:
            for table in (self._status, self._warned):
                for gone in set(table) - current:
                    del table[gone]
            new = [m for m in mappings if _token_id(m) not in self._status]
        for mapping in mappings:
            self._warn_expiry(mapping, today)
        if new and not self.checking():
            self._checker = threading.Thread(
                target=self._check_upstream, args=(new, upstream), name="mtls-bridge-token-check", daemon=True
            )
            self._checker.start()

    def _set(self, mapping, status):
        with self._lock:
            self._status[_token_id(mapping)] = status

    def _warn_expiry(self, mapping, today):
        status = expiry_status(mapping, today)
        if status not in ("expiring", "expired"):
            return
        token_id = _token_id(mapping)
        with self._lock:
            if self._warned.get(token_id) == today:
                return
            self._warned[token_id] = today
        days = days_remaining(mapping, today)
        expiry = mapping.token_expiry.isoformat()
        if status == "expired":
            log.warning("the token for account %s expired on %s; replace it", mapping.account, expiry)
        else:
            log.warning("the token for account %s expires on %s, in %d days; replace it", mapping.account, expiry, days)
        self._audit.write(
            "token_expiry",
            user=mapping.account,
            issuer=mapping.issuer,
            identity_type=mapping.identity_type,
            identity=mapping.identity_value,
            token_expiry=expiry,
            days_remaining=days,
            status=status,
        )

    def _check_upstream(self, mappings, upstream):
        body = _check_body()
        for mapping in mappings:
            forwarded = Forwarded(None, uuid.uuid4().hex, {})
            try:
                with upstream.post(mapping.token, body, forwarded) as response:
                    code = response.status
            except (UpstreamUnavailable, UpstreamTimeout) as exc:
                # Left unchecked, so the next config poll tries again.
                log.warning("cannot check the token for account %s: %s", mapping.account, exc)
                continue
            if code == 401:
                log.warning("the MCP Server rejected the token for account %s", mapping.account)
                self._set(mapping, INVALID)
            elif 200 <= code < 300:
                self._set(mapping, OK)
            else:
                log.warning(
                    "the MCP Server answered the token check for account %s with HTTP %s", mapping.account, code
                )
                self._set(mapping, UNVERIFIED)
