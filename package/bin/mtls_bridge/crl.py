"""Keeps the CRL the listener enforces: the last good copy of the configured file, and its expiry policy."""

import base64
import dataclasses
import datetime
import logging
import os
import ssl
import tempfile
import time
from typing import Optional

from . import certificate

log = logging.getLogger(__name__)

WARN_BEFORE = datetime.timedelta(hours=24)
# Repeated warnings and alerts (CRL nearing nextUpdate, CRL expired) go out at most this often.
_ALERT_INTERVAL = 3600.0

_VERIFY_FLAGS = {"leaf": ssl.VERIFY_CRL_CHECK_LEAF, "chain": ssl.VERIFY_CRL_CHECK_CHAIN}
_EXPIRY_POLICIES = ("fail_closed", "fail_open")


@dataclasses.dataclass(frozen=True)
class CrlState:
    """What the listener enforces for revocation right now."""

    pem: Optional[bytes] = None  # the CRLs to load into the SSLContext; None checks no revocation
    flags: int = 0  # ssl.VERIFY_CRL_CHECK_* to add
    refuse_all: Optional[str] = None  # set when every handshake must be refused (an expired CRL, fail_closed)
    warning: Optional[str] = None  # added to every audit event (an expired CRL, fail_open)
    next_update: Optional[datetime.datetime] = None  # the earliest nextUpdate of the CRLs read


def _pem(crls):
    return b"".join(
        b"-----BEGIN X509 CRL-----\n" + base64.encodebytes(der) + b"-----END X509 CRL-----\n" for der in crls
    )


def _openssl_problem(pem):
    """Why OpenSSL won't load ``pem``, or None if it will."""
    handle, path = tempfile.mkstemp(prefix="mtls-bridge-", suffix=".crl")
    try:
        with os.fdopen(handle, "wb") as out:
            out.write(pem)
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_verify_locations(cafile=path)
    except ssl.SSLError as exc:
        return str(exc)
    finally:
        os.unlink(path)
    return None


class CrlKeeper:
    """Tracks the configured CRL file across config polls.

    A changed file that parses, that OpenSSL loads, and that is current replaces the CRL in force;
    anything else is refused with an error and the previous CRL stays. The CRL in force is loaded
    from a private copy, so a bad replacement on disk never reaches an SSLContext.
    """

    def __init__(self, audit):
        self._audit = audit
        self._copy = None
        self._last_alert = {}
        self._reset()

    def _reset(self):
        self._accepted = None  # the file's bytes when the CRL in force was read
        self._pem = None  # the CRL in force
        self._next_update = None  # its earliest nextUpdate, or None

    def refresh(self, config, now=None):
        """Re-read the CRL file and return the CrlState to serve.

        Raises ValueError if the settings are invalid, or if there's no CRL to fall back on and the
        file can't be used.
        """
        if not config.crl_file:
            self._reset()
            return CrlState()
        if config.crl_check not in _VERIFY_FLAGS:
            raise ValueError(f"CRL check depth must be leaf or chain, not {config.crl_check!r}")
        if config.crl_expiry not in _EXPIRY_POLICIES:
            raise ValueError(f"CRL expiry behaviour must be fail_closed or fail_open, not {config.crl_expiry!r}")
        now = now or datetime.datetime.now(datetime.timezone.utc)
        self._read(config.crl_file, now)
        state = CrlState(self._pem, _VERIFY_FLAGS[config.crl_check], next_update=self._next_update)
        if self._next_update is None:
            return state
        if now >= self._next_update:
            return self._expired(config, state)
        if self._next_update - now <= WARN_BEFORE and self._due("nearing"):
            log.warning(
                "CRL %s reaches its nextUpdate at %s, within 24 hours; drop a fresh CRL before then",
                config.crl_file,
                self._next_update,
            )
        return state

    def load_into(self, context, state):
        """Load ``state``'s CRLs into an SSLContext."""
        if state.pem is None:
            return
        if self._copy is None:
            handle, self._copy = tempfile.mkstemp(prefix="mtls-bridge-", suffix=".crl")
            os.close(handle)
        with open(self._copy, "wb") as out:
            out.write(state.pem)
        context.load_verify_locations(cafile=self._copy)
        context.verify_flags |= state.flags

    def close(self):
        if self._copy is not None:
            os.unlink(self._copy)
            self._copy = None

    def _expired(self, config, state):
        expired = f"CRL {config.crl_file} expired at {self._next_update.isoformat()}"
        if config.crl_expiry == "fail_open":
            message = f"{expired}; revocation is not checked until a fresh CRL arrives (fail_open)"
            state = CrlState(warning=message, next_update=state.next_update)
        else:
            message = f"{expired}; every handshake is refused until a fresh CRL arrives (fail_closed)"
            state = dataclasses.replace(state, refuse_all=message)
        if self._due("expired"):
            log.error("%s", message)
            self._audit.write("crl_expired", policy=config.crl_expiry, crl_file=config.crl_file, message=message)
        return state

    def _due(self, alert):
        """True at most once per _ALERT_INTERVAL for each kind of alert."""
        now = time.monotonic()
        last = self._last_alert.get(alert)
        if last is not None and now - last < _ALERT_INTERVAL:
            return False
        self._last_alert[alert] = now
        return True

    def _read(self, path, now):
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError as exc:
            self._refuse(f"cannot read CRL file {path}: {exc}")
            return
        if data == self._accepted:
            return
        try:
            crls = certificate.load_crls(data)
        except certificate.CertificateError as exc:
            self._refuse(f"CRL file {path} won't parse: {exc}")
            return
        this_updates = [certificate.crl_times(der)[0] for der in crls]
        next_updates = [u for u in (certificate.crl_times(der)[1] for der in crls) if u is not None]
        next_update = min(next_updates) if next_updates else None
        pem = _pem(crls)
        problem = _openssl_problem(pem)
        if problem:
            self._refuse(f"OpenSSL won't load CRL file {path}: {problem}")
        elif max(this_updates) > now:
            self._refuse(f"CRL file {path} isn't valid yet (thisUpdate {max(this_updates).isoformat()})")
        elif self._pem is not None and next_update is not None and next_update <= now:
            self._refuse(f"CRL file {path} has already expired (nextUpdate {next_update.isoformat()})")
        else:
            # At startup an expired CRL is accepted, so the expiry policy decides what happens.
            self._accepted, self._pem, self._next_update = data, pem, next_update
            self._last_alert.clear()
            log.info("CRL %s loaded; nextUpdate %s", path, next_update.isoformat() if next_update else "none")

    def _refuse(self, problem):
        if self._pem is None:
            raise ValueError(problem)
        log.error("%s; keeping the previous CRL", problem)
