"""The bridge's configuration: a plain value with no Splunk dependencies."""

from dataclasses import dataclass, field
from typing import List, Optional

DEFAULT_UPSTREAM_URL = "https://127.0.0.1:8089/services/mcp"


@dataclass(frozen=True)
class Mapping:
    """Maps a cert (issuer + one typed identity) to a Splunk account and its MCP token."""

    issuer: str
    identity_type: str
    identity_value: str
    account: str
    token: str = field(repr=False)


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
    upstream_timeout: float = 300.0
    # Matches the MCP Server app's own payload cap.
    max_body_bytes: int = 128 * 1024
    max_concurrent_per_identity: int = 10
    mappings: List[Mapping] = field(default_factory=list)
