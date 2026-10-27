"""Builds a Config from the app's settings and mappings, read from splunkd's REST API.

This is the only module that talks to Splunk for configuration. It uses the session key splunkd
hands the modular input, so the bridge never holds an admin credential.
"""

import datetime
import json
import logging
import ssl
import urllib.error
import urllib.parse
import urllib.request

from .config import Config, Mapping

log = logging.getLogger(__name__)

APP = "TA-mtls-bridge"
_SETTINGS = f"/servicesNS/nobody/{APP}/ta_mtls_bridge_settings/listener"
_MAPPINGS = f"/servicesNS/nobody/{APP}/ta_mtls_bridge_mappings"
_SERVER_SSL_CONFIG = "/services/configs/conf-server/sslConfig"

# Splunk's out-of-the-box sslPassword. splunkd returns the configured one encrypted, so it's the only
# password we can try for its key; anything else needs the listener key password override.
_SPLUNK_DEFAULT_KEY_PASSWORD = "password"

# How splunkd and UCC spell a checked checkbox.
_TRUTHY = {"1", "true", "yes", "t", "y"}


class ConfigError(Exception):
    """The configuration can't be used."""


class NotConfigured(ConfigError):
    """The admin hasn't finished setting up the bridge yet."""


class SessionExpired(ConfigError):
    """splunkd refused the session key."""


def load(server_uri, session_key, splunk_home):
    rest = _Rest(server_uri, session_key)
    settings = rest.entries(_SETTINGS, {"--cred--": "1"})[0]["content"]
    rows = rest.entries(_MAPPINGS, {"--cred--": "1", "count": "0"}, required=False)

    def path(value):
        return value.replace("$SPLUNK_HOME", splunk_home) if value else value

    ca_bundle = path(settings.get("ca_bundle"))
    if not ca_bundle:
        raise NotConfigured("no client CA bundle is set on the bridge's Listener settings page")

    server_cert = path(settings.get("server_cert"))
    server_key = path(settings.get("server_key"))
    password = settings.get("server_key_password") or None
    if not server_cert:
        server_cert, server_key = _splunkd_server_cert(rest, path)
    server_key = server_key or server_cert
    password = _working_key_password(server_cert, server_key, password)

    values = dict(
        server_cert=server_cert,
        server_key=server_key,
        server_key_password=password,
        ca_bundle=ca_bundle,
        upstream_ca_bundle=path(settings.get("upstream_ca_bundle") or "$SPLUNK_HOME/etc/auth/cacert.pem"),
        upstream_verify_hostname=str(settings.get("upstream_verify_hostname", "0")).lower() in _TRUTHY,
        mappings=[m for m in (_mapping(row) for row in rows) if m is not None],
    )
    # Settings left empty keep Config's defaults.
    for name in ("listen_host", "upstream_url"):
        if settings.get(name):
            values[name] = settings[name]
    if settings.get("listen_port"):
        values["listen_port"] = _int(settings, "listen_port")
    return Config(**values)


def _splunkd_server_cert(rest, path):
    ssl_config = rest.entries(_SERVER_SSL_CONFIG, {})[0]["content"]
    cert = path(ssl_config.get("serverCert") or "$SPLUNK_HOME/etc/auth/server.pem")
    return cert, path(ssl_config.get("privKeyPath"))


def _working_key_password(cert, key, password):
    candidates = [password] if password else [None, _SPLUNK_DEFAULT_KEY_PASSWORD]
    for candidate in candidates:
        try:
            # An empty password, never None, so OpenSSL can't fall back to prompting on a terminal.
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(cert, key, password=candidate or "")
        except ssl.SSLError:
            continue
        except OSError as exc:
            raise ConfigError(f"cannot read listener cert or key ({cert}, {key}): {exc}") from exc
        return candidate
    if password:
        raise ConfigError(f"cannot load listener key {key} with the configured key password")
    raise ConfigError(
        f"cannot load listener key {key}: it is encrypted with a key password other than Splunk's default; "
        "set the listener cert, key and key password on the Listener settings page"
    )


def _mapping(entry):
    content = entry["content"]
    token = content.get("token")
    if not token or set(token) == {"*"}:
        log.error("mapping %s has no readable token; skipping it", entry["name"])
        return None
    expiry = content.get("token_expiry")
    try:
        expiry = datetime.date.fromisoformat(expiry) if expiry else None
    except ValueError:
        log.warning("mapping %s has an unreadable token expiry %r", entry["name"], expiry)
        expiry = None
    return Mapping(
        issuer=content.get("issuer", ""),
        identity_type=content.get("identity_type", ""),
        identity_value=content.get("identity_value", ""),
        account=content.get("account", ""),
        token=token,
        token_expiry=expiry,
    )


def _int(settings, name):
    value = settings[name]
    try:
        return int(value)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, not {value!r}") from exc


class _Rest:
    def __init__(self, server_uri, session_key):
        self._base = server_uri.rstrip("/")
        self._session_key = session_key
        # splunkd hands the modular input its own loopback URI. Its management cert is usually
        # Splunk's per-install self-signed one, so it isn't verified on this local hop.
        self._context = ssl.create_default_context()
        self._context.check_hostname = False
        self._context.verify_mode = ssl.CERT_NONE

    def entries(self, path, params, required=True):
        query = urllib.parse.urlencode(dict(params, output_mode="json"))
        request = urllib.request.Request(
            f"{self._base}{path}?{query}", headers={"Authorization": "Splunk " + self._session_key}
        )
        try:
            with urllib.request.urlopen(request, context=self._context, timeout=30) as response:
                document = json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                raise SessionExpired("splunkd rejected the session key") from exc
            if exc.code == 404 and required:
                raise NotConfigured(f"splunkd has nothing at {path} yet") from exc
            raise ConfigError(f"splunkd returned {exc.code} for {path}") from exc
        except (OSError, ValueError) as exc:
            raise ConfigError(f"cannot read {path} from splunkd: {exc}") from exc
        entries = document.get("entry") or []
        if not entries and required:
            raise NotConfigured(f"splunkd has no entries at {path}")
        return entries
