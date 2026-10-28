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

from .config import Config, Mapping, RoleAccount, UserRule

log = logging.getLogger(__name__)

APP = "TA-mtls-bridge"
_SETTINGS = f"/servicesNS/nobody/{APP}/ta_mtls_bridge_settings/listener"
_AUDIT_SETTINGS = f"/servicesNS/nobody/{APP}/ta_mtls_bridge_settings/audit"
_MAPPINGS = f"/servicesNS/nobody/{APP}/ta_mtls_bridge_mappings"
_ROLE_ACCOUNTS = f"/servicesNS/nobody/{APP}/ta_mtls_bridge_role_accounts"
_USER_RULES = f"/servicesNS/nobody/{APP}/ta_mtls_bridge_user_rules"
_SERVER_SSL_CONFIG = "/services/configs/conf-server/sslConfig"

# The audit file, as default/inputs.conf monitors it. Kept out of var/log/splunk, which Splunk
# already sends to _internal.
AUDIT_LOG = "$SPLUNK_HOME/var/log/TA-mtls-bridge/audit.log"
_AUDIT_INPUT = f"/servicesNS/nobody/{APP}/configs/conf-inputs/" + urllib.parse.quote("monitor://" + AUDIT_LOG, safe="")
_MONITOR_RELOAD = f"/servicesNS/nobody/{APP}/data/inputs/monitor/_reload"

# Splunk's out-of-the-box sslPassword. splunkd returns the configured one encrypted, so it's the only
# password we can try for its key; anything else needs the listener key password override.
_SPLUNK_DEFAULT_KEY_PASSWORD = "password"

# How splunkd and UCC spell a checked checkbox.
_TRUTHY = {"1", "true", "yes", "t", "y"}


def _flag(value, default):
    """A checkbox or boolean conf value; ``default`` when it's missing or empty."""
    if value is None or value == "":
        return default
    return str(value).lower() in _TRUTHY


class ConfigError(Exception):
    """The configuration can't be used."""

    # The mappings, role accounts and user rules, when only the listener settings are the problem.
    access = None


class NotConfigured(ConfigError):
    """The admin hasn't finished setting up the bridge yet."""


class SessionExpired(ConfigError):
    """splunkd refused the session key."""


def load(server_uri, session_key, splunk_home):
    """The bridge's Config. A ConfigError raised because the listener settings can't be used carries
    the mappings, role accounts and user rules in ``access``, so they can still be applied."""
    rest = _Rest(server_uri, session_key)
    access = dict(
        mappings=_rows(rest, _MAPPINGS, {"--cred--": "1"}, _mapping),
        role_accounts=_rows(rest, _ROLE_ACCOUNTS, {"--cred--": "1"}, _role_account),
        user_rules=_rows(rest, _USER_RULES, {}, _user_rule),
    )
    try:
        return Config(**_listener_values(rest, splunk_home), **access)
    except SessionExpired:
        raise
    except ConfigError as exc:
        exc.access = access
        raise


def _rows(rest, path, params, build):
    """The enabled rows of a table that ``build`` can turn into something the bridge can use."""
    entries = rest.entries(path, dict(params, count="0"), required=False)
    built = (build(entry) for entry in entries if not _flag(entry["content"].get("disabled"), False))
    return [row for row in built if row is not None]


def _listener_values(rest, splunk_home):
    settings = rest.entries(_SETTINGS, {"--cred--": "1"})[0]["content"]

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
        upstream_verify_hostname=_flag(settings.get("upstream_verify_hostname"), False),
        audit_log=path(AUDIT_LOG),
        crl_file=path(settings.get("crl_file")) or None,
    )
    # Settings left empty keep Config's defaults.
    for name in ("listen_host", "upstream_url", "crl_check", "crl_expiry"):
        if settings.get(name):
            values[name] = settings[name]
    for name in ("listen_port", "max_concurrent_per_user"):
        if settings.get(name):
            values[name] = _int(settings, name)
    return values


def sync_audit_input(server_uri, session_key):
    """Point the audit file's monitor input at the configured index, or disable it, as the Audit page says.

    The audit file is written either way. Returns True if the input changed.
    """
    rest = _Rest(server_uri, session_key)
    try:
        audit = rest.entries(_AUDIT_SETTINGS, {})[0]["content"]
    except NotConfigured:
        audit = {}  # the Audit page has never been saved
    wanted = {
        "index": audit.get("audit_index") or "main",
        "disabled": "0" if _flag(audit.get("audit_forwarding"), True) else "1",
    }
    current = rest.entries(_AUDIT_INPUT, {})[0]["content"]
    current_disabled = "1" if _flag(current.get("disabled"), False) else "0"
    if current.get("index") == wanted["index"] and current_disabled == wanted["disabled"]:
        return False
    rest.post(_AUDIT_INPUT, wanted)
    rest.entries(_MONITOR_RELOAD, {}, required=False)
    log.info("audit input now %s", "disabled" if wanted["disabled"] == "1" else f"sending to index {wanted['index']}")
    return True


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
    proxies_users = _flag(content.get("proxies_users"), False)
    if proxies_users:
        # Its calls run as the role accounts its users' rules name.
        token, expiry = "", None
    else:
        token = _token(entry, "mapping")
        if token is None:
            return None
        expiry = _expiry(entry, "mapping")
    try:
        return Mapping(
            issuer=content.get("issuer", ""),
            identity_type=content.get("identity_type", ""),
            identity_value=content.get("identity_value", ""),
            account="" if proxies_users else content.get("account", ""),
            token=token,
            token_expiry=expiry,
            proxies_users=proxies_users,
        )
    except ValueError as exc:
        log.error("mapping %s can never match a certificate (%s); skipping it", entry["name"], exc)
        return None


def _role_account(entry):
    token = _token(entry, "role account")
    if token is None:
        return None
    return RoleAccount(
        name=entry["name"],
        account=entry["content"].get("account", ""),
        token=token,
        token_expiry=_expiry(entry, "role account"),
    )


def _user_rule(entry):
    content = entry["content"]
    try:
        return UserRule(
            name=entry["name"],
            match=content.get("match", ""),
            value=content.get("value", ""),
            role_account=content.get("role_account", ""),
        )
    except ValueError as exc:
        log.error("user rule %s can never match a user (%s); skipping it", entry["name"], exc)
        return None


def _token(entry, kind):
    """The row's decrypted token, or None (logged) if splunkd couldn't give one."""
    token = entry["content"].get("token")
    if not token or set(token) == {"*"}:
        log.error("%s %s has no readable token; skipping it", kind, entry["name"])
        return None
    if not all("!" <= char <= "~" for char in token):
        log.error("%s %s has a token with spaces or characters a header can't carry; skipping it", kind, entry["name"])
        return None
    return token


def _expiry(entry, kind):
    expiry = entry["content"].get("token_expiry")
    try:
        return datetime.date.fromisoformat(expiry) if expiry else None
    except ValueError:
        log.warning("%s %s has an unreadable token expiry %r", kind, entry["name"], expiry)
        return None


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
        document = self._call(f"{self._base}{path}?{query}", path, required)
        entries = document.get("entry") or []
        if not entries and required:
            raise NotConfigured(f"splunkd has no entries at {path}")
        return entries

    def post(self, path, fields):
        body = urllib.parse.urlencode(dict(fields, output_mode="json")).encode()
        self._call(f"{self._base}{path}", path, required=True, data=body)

    def _call(self, url, path, required, data=None):
        request = urllib.request.Request(url, data=data, headers={"Authorization": "Splunk " + self._session_key})
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
            raise ConfigError(f"cannot reach {path} on splunkd: {exc}") from exc
        return document
