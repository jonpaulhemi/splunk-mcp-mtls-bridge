"""The bridge's configuration: a plain value with no Splunk dependencies."""

import datetime
from dataclasses import dataclass, field
from typing import List, Optional

from . import identity

DEFAULT_UPSTREAM_URL = "https://127.0.0.1:8089/services/mcp"


@dataclass(frozen=True)
class Mapping:
    """Maps a cert (issuer + one typed identity) to a Splunk account and its MCP token."""

    issuer: str
    identity_type: str
    identity_value: str
    account: str
    token: str = field(repr=False)
    token_expiry: Optional[datetime.date] = None

    def __post_init__(self):
        """Raises ValueError if the issuer, type or value can't describe any certificate."""
        object.__setattr__(self, "_key", identity.mapping_key(self.issuer, self.identity_type, self.identity_value))

    @property
    def key(self):
        """The identity this mapping matches, canonicalised: (issuer, identity type, identity value)."""
        return self._key


@dataclass(frozen=True)
class Config:
    server_cert: str
    server_key: str
    ca_bundle: str
    listen_host: str = "0.0.0.0"
    listen_port: int = 8443
    server_key_password: Optional[str] = field(default=None, repr=False)
    upstream_url: str = DEFAULT_UPSTREAM_URL
    upstream_ca_bundle: Optional[str] = None
    upstream_verify_hostname: bool = True
    handshake_timeout: float = 10.0
    # How long to wait on a quiet client between and during requests, after the handshake.
    client_timeout: float = 30.0
    upstream_connect_timeout: float = 10.0
    # Longest wait for the upstream to send anything, once connected.
    upstream_timeout: float = 300.0
    # Matches the MCP Server app's own payload cap.
    max_body_bytes: int = 128 * 1024
    max_concurrent_per_identity: int = 10
    # A CRL file (PEM or DER, one CRL per issuing CA); None turns revocation checking off.
    crl_file: Optional[str] = None
    crl_check: str = "leaf"  # or "chain"
    crl_expiry: str = "fail_closed"  # or "fail_open"
    # The audit file; None writes no audit events.
    audit_log: Optional[str] = None
    # Failed handshakes from one IP within this many seconds become one audit event.
    handshake_audit_window: float = 60.0
    mappings: List[Mapping] = field(default_factory=list)

    @property
    def listen_address(self):
        return (self.listen_host, self.listen_port)
