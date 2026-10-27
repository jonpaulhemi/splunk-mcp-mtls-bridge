"""Watches each mapping's and role account's token: its admin-entered expiry date, and whether the upstream accepts it.

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

# Token statuses.
OK = "ok"  # the upstream accepted the token
INVALID = "invalid"  # the upstream answered 401
UNCHECKED = "unchecked"  # not checked yet, or the upstream couldn't be reached
UNVERIFIED = "unverified"  # the upstream answered the check with neither success nor 401

# Expiry statuses.
EXPIRY_OK = "ok"
EXPIRING = "expiring"  # within EXPIRY_WARNING_DAYS of the expiry date
EXPIRED = "expired"

# The MCP revision the check's initialize offers; any answer but 401 says the token got through.
_PROTOCOL_VERSION = "2025-06-18"


def _token_id(holder):
    """Tells a holder's token apart from its earlier and later tokens without holding the token."""
    return (holder.key, hashlib.sha256(holder.token.encode()).hexdigest())


def days_remaining(holder, today):
    """Days from ``today`` to the holder's token expiry date (negative once past it), or None."""
    return None if holder.token_expiry is None else (holder.token_expiry - today).days


def expiry_status(holder, today):
    """EXPIRY_OK, EXPIRING or EXPIRED, or None if the holder has no expiry date."""
    days = days_remaining(holder, today)
    if days is None:
        return None
    if days < 0:
        return EXPIRED
    return EXPIRING if days <= EXPIRY_WARNING_DAYS else EXPIRY_OK


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
    """Holds the token status and expiry warnings of the current token holders: holders and role accounts.

    ``update`` sets the current holders; results for tokens no longer among them are dropped. A holder has
    ``key``, ``account``, ``token``, ``token_expiry`` and ``audit_fields()``.
    """

    def __init__(self, audit):
        self._audit = audit
        self._holders = []
        self._upstream = None
        self._status = {}  # token id -> OK, INVALID or UNVERIFIED
        self._warned = {}  # holder key -> the day its last expiry warning went out
        self._lock = threading.Lock()
        self._checker = None  # the background check, while one runs
        self._stopping = threading.Event()

    def update(self, holders, upstream):
        current = {_token_id(m) for m in holders}
        keys = {m.key for m in holders}
        with self._lock:
            self._holders, self._upstream = list(holders), upstream
            self._status = {token: status for token, status in self._status.items() if token in current}
            self._warned = {key: day for key, day in self._warned.items() if key in keys}

    def status(self, holder):
        with self._lock:
            return self._status.get(_token_id(holder), UNCHECKED)

    def accepted(self, holder):
        """A forwarded call with ``holder``'s token succeeded."""
        self._set(holder, OK)

    def rejected(self, holder):
        """The upstream answered a forwarded call with ``holder``'s token with 401."""
        log.warning("upstream rejected the token for account %s", holder.account)
        self._set(holder, INVALID)

    def checking(self):
        """True while new tokens are being checked upstream."""
        with self._lock:
            return self._checker is not None

    def warn_expiring(self, today):
        """Warn about each token near or past its expiry date, at most once a day per holder."""
        with self._lock:
            holders = self._holders
        for holder in holders:
            self._warn_expiry(holder, today)

    def check_new(self):
        """Check each token not checked yet upstream, in the background."""
        with self._lock:
            if self._checker is not None or self._stopping.is_set():
                return
            if all(_token_id(m) in self._status for m in self._holders):
                return
            self._checker = threading.Thread(target=self._check_upstream, name="mtls-bridge-token-check", daemon=True)
            self._checker.start()

    def report(self, holders, today):
        """Each of ``holders``' account, expiry and token status, for /health."""
        return [
            {
                "account": m.account,
                "token_expiry": m.token_expiry.isoformat() if m.token_expiry else None,
                "days_remaining": days_remaining(m, today),
                "expiry_status": expiry_status(m, today),
                "token_status": self.status(m),
            }
            for m in holders
        ]

    def stop(self):
        self._stopping.set()
        with self._lock:
            checker = self._checker
        if checker is not None:
            checker.join(1.0)

    def _set(self, holder, status, only_if_unchecked=False):
        token = _token_id(holder)
        with self._lock:
            if token not in {_token_id(m) for m in self._holders}:
                return  # a request or check that outlived its holder
            if only_if_unchecked and token in self._status:
                return  # a forwarded call answered while the check was in flight, and is newer
            self._status[token] = status

    def _warn_expiry(self, holder, today):
        status = expiry_status(holder, today)
        if status not in (EXPIRING, EXPIRED):
            return
        with self._lock:
            if self._warned.get(holder.key) == today:
                return
            self._warned[holder.key] = today
        days = days_remaining(holder, today)
        expiry = holder.token_expiry.isoformat()
        if status == EXPIRED:
            log.warning("the token for account %s expired on %s; replace it", holder.account, expiry)
        else:
            log.warning("the token for account %s expires on %s, in %d days; replace it", holder.account, expiry, days)
        self._audit.write(
            "token_expiry",
            user=holder.account,
            **holder.audit_fields(),
            token_expiry=expiry,
            days_remaining=days,
            status=status,
        )

    def _next_unchecked(self, tried):
        """The next current holder whose token is unchecked and not yet tried, and the upstream to try
        it on; or (None, None), which ends the check."""
        with self._lock:
            for holder in self._holders:
                token = _token_id(holder)
                if token not in self._status and token not in tried:
                    return holder, self._upstream
            self._checker = None
            return None, None

    def _check_upstream(self):
        body = _check_body()
        tried = set()
        # Picks up tokens that arrive while it runs, so a rotation mid-check is checked promptly.
        while not self._stopping.is_set():
            holder, upstream = self._next_unchecked(tried)
            if holder is None:
                return
            tried.add(_token_id(holder))
            try:
                with upstream.post(holder.token, body, Forwarded(None, uuid.uuid4().hex, {})) as response:
                    code = response.status
            except (UpstreamUnavailable, UpstreamTimeout) as exc:
                # Left unchecked, so the next config poll tries again.
                log.warning("cannot check the token for account %s: %s", holder.account, exc)
                continue
            if code == 401:
                log.warning("the MCP Server rejected the token for account %s", holder.account)
                status = INVALID
            elif 200 <= code < 300:
                status = OK
            else:
                log.warning("the MCP Server answered the token check for account %s with HTTP %s", holder.account, code)
                status = UNVERIFIED
            self._set(holder, status, only_if_unchecked=True)
        with self._lock:
            self._checker = None
