"""Keeps the CRL the listener enforces: the last good copy of the configured file, and its expiry policy."""

import base64
import datetime
import logging
import os
import ssl
import tempfile

from . import certificate

log = logging.getLogger(__name__)

WARN_BEFORE = datetime.timedelta(hours=24)

_VERIFY_FLAGS = {"leaf": ssl.VERIFY_CRL_CHECK_LEAF, "chain": ssl.VERIFY_CRL_CHECK_CHAIN}
_EXPIRY_POLICIES = ("fail_closed", "fail_open")


def _pem(crls):
    return b"".join(
        b"-----BEGIN X509 CRL-----\n" + base64.encodebytes(der) + b"-----END X509 CRL-----\n" for der in crls
    )


class CrlKeeper:
    """Tracks the configured CRL file across config polls.

    A changed file that parses and hasn't expired replaces the CRL in force; anything else is refused
    and the previous CRL stays. The CRL in force is written to a private copy, so a bad replacement
    on disk never reaches the SSLContext.
    """

    def __init__(self, audit):
        self._audit = audit
        self._seen = None  # the file's bytes when last read
        self._pem = None  # the CRL in force
        self._next_update = None  # its earliest nextUpdate, or None
        self._warned_for = None  # the nextUpdate already warned about
        self._copy = None

    def refresh(self, config, now=None):
        """Re-read the CRL file. Returns the CRL state to build the SSLContext from: (pem or None, flags).

        Raises ValueError if there's no CRL to fall back on and the file can't be used.
        """
        if not config.crl_file:
            self._seen = self._pem = self._next_update = None
            return None, 0
        if config.crl_check not in _VERIFY_FLAGS:
            raise ValueError(f"CRL check depth must be leaf or chain, not {config.crl_check!r}")
        if config.crl_expiry not in _EXPIRY_POLICIES:
            raise ValueError(f"CRL expiry behaviour must be fail_closed or fail_open, not {config.crl_expiry!r}")
        now = now or datetime.datetime.now(datetime.timezone.utc)
        self._read(config.crl_file, now)
        flags = _VERIFY_FLAGS[config.crl_check]
        if self._next_update is not None and now >= self._next_update:
            if config.crl_expiry == "fail_open":
                log.warning(
                    "CRL %s expired at %s; revocation checking is OFF (fail_open)", config.crl_file, self._next_update
                )
                self._audit.write(
                    "crl_expired",
                    policy="fail_open",
                    crl_file=config.crl_file,
                    next_update=self._next_update.isoformat(),
                    message="CRL expired: revocation checking is disabled until a fresh CRL arrives",
                )
                return None, 0
            # OpenSSL itself refuses every handshake against an expired CRL.
            log.error(
                "CRL %s expired at %s; rejecting all handshakes (fail_closed)", config.crl_file, self._next_update
            )
        elif self._next_update is not None and self._next_update - now <= WARN_BEFORE:
            if self._warned_for != self._next_update:
                self._warned_for = self._next_update
                log.warning(
                    "CRL %s reaches its nextUpdate at %s, within 24 hours; drop a fresh CRL before then",
                    config.crl_file,
                    self._next_update,
                )
        return self._pem, flags

    def load_into(self, context, state):
        """Load ``state`` (from refresh) into an SSLContext."""
        pem, flags = state
        if pem is None:
            return
        if self._copy is None:
            handle, self._copy = tempfile.mkstemp(prefix="mtls-bridge-", suffix=".crl")
            os.close(handle)
        with open(self._copy, "wb") as out:
            out.write(pem)
        context.load_verify_locations(cafile=self._copy)
        context.verify_flags |= flags

    def close(self):
        if self._copy is not None:
            os.unlink(self._copy)
            self._copy = None

    def _read(self, path, now):
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError as exc:
            self._refuse(f"cannot read CRL file {path}: {exc}")
            return
        if data == self._seen:
            return
        self._seen = data
        try:
            crls = certificate.load_crls(data)
        except certificate.CertificateError as exc:
            self._refuse(f"CRL file {path} won't parse: {exc}")
            return
        updates = [u for u in (certificate.crl_next_update(der) for der in crls) if u is not None]
        next_update = min(updates) if updates else None
        if self._pem is not None and next_update is not None and next_update <= now:
            self._refuse(f"CRL file {path} has already expired (nextUpdate {next_update})")
            return
        # At startup an expired CRL is accepted, so the expiry policy decides what happens.
        self._pem = _pem(crls)
        self._next_update = next_update
        log.info("CRL %s loaded; nextUpdate %s", path, next_update or "none")

    def _refuse(self, problem):
        if self._pem is None:
            raise ValueError(problem)
        log.error("%s; keeping the previous CRL", problem)
