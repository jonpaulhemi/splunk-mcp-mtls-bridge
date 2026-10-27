"""The Splunk config adapter, against splunkd REST responses served by a fake splunkd."""

import datetime

import pytest
from cryptography.hazmat.primitives import serialization

from mtls_bridge import splunk_config

from harness import SESSION_KEY


def _write_combined_pem(test_pki, path, password=None):
    """Write a server.pem the way Splunk ships it: cert followed by its private key."""
    key = serialization.load_pem_private_key(test_pki.server.key.read_bytes(), password=None)
    encryption = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)
    path.write_bytes(test_pki.server.cert.read_bytes() + key_pem)
    return path


def _load(splunkd, splunk_home):
    return splunk_config.load(splunkd.uri, SESSION_KEY, str(splunk_home))


def test_settings_and_mappings_become_a_config(test_pki, splunkd, splunk_home):
    _write_combined_pem(test_pki, splunk_home / "etc" / "auth" / "server.pem")

    config = _load(splunkd, splunk_home)

    assert config.listen_host == "0.0.0.0"
    assert config.listen_port == 9443
    assert config.ca_bundle == str(test_pki.ca.cert_path)
    assert config.upstream_url == "https://127.0.0.1:8089/services/mcp"
    assert config.upstream_verify_hostname is False
    assert config.upstream_ca_bundle == str(splunk_home / "etc" / "auth" / "cacert.pem")
    assert [(m.account, m.identity_type, m.identity_value) for m in config.mappings] == [
        ("svc_agent_a", "URI", "spiffe://bridge.test/agent-a"),
        ("svc_agent_b", "DNS", "agent-b.bridge.test"),
    ]
    assert config.mappings[0].issuer == "CN=Bridge Test CA,O=Bridge Test,C=US"
    assert config.mappings[0].token == "eyJraWQiOiJzcGx1bmsuc2VjcmV0IiwiYWxnIjoiSFM1MTIifQ.agent-a"
    assert config.mappings[0].token_expiry == datetime.date(2027, 4, 25)


def test_reads_decrypted_rows_with_the_session_key(test_pki, splunkd, splunk_home):
    _write_combined_pem(test_pki, splunk_home / "etc" / "auth" / "server.pem")

    _load(splunkd, splunk_home)

    by_path = {path: (query, headers) for path, query, headers in splunkd.requests}
    mappings_query, mappings_headers = by_path["/servicesNS/nobody/TA-mtls-bridge/ta_mtls_bridge_mappings"]
    assert mappings_query["--cred--"] == ["1"]
    assert mappings_query["count"] == ["0"]
    assert mappings_query["output_mode"] == ["json"]
    assert mappings_headers["Authorization"] == "Splunk " + SESSION_KEY
    settings_query, _ = by_path["/servicesNS/nobody/TA-mtls-bridge/ta_mtls_bridge_settings/listener"]
    assert settings_query["--cred--"] == ["1"]


def test_listener_defaults_to_splunkd_server_cert(test_pki, splunkd, splunk_home):
    server_pem = _write_combined_pem(test_pki, splunk_home / "etc" / "auth" / "server.pem")

    config = _load(splunkd, splunk_home)

    assert config.server_cert == str(server_pem)
    assert config.server_key == str(server_pem)
    assert config.server_key_password is None


def test_default_cert_key_protected_by_splunks_default_password(test_pki, splunkd, splunk_home):
    _write_combined_pem(test_pki, splunk_home / "etc" / "auth" / "server.pem", password="password")

    config = _load(splunkd, splunk_home)

    assert config.server_key_password == "password"


def test_default_cert_with_a_separate_key_file(test_pki, splunkd, splunk_home):
    splunkd.content_overrides["conf_server_sslconfig.json"] = {
        "serverCert": str(test_pki.server.cert),
        "privKeyPath": str(test_pki.server.key),
    }

    config = _load(splunkd, splunk_home)

    assert config.server_cert == str(test_pki.server.cert)
    assert config.server_key == str(test_pki.server.key)


def test_listener_cert_override_wins(test_pki, splunkd, splunk_home):
    splunkd.content_overrides["settings_listener.json"] = {
        "server_cert": str(test_pki.server.cert),
        "server_key": str(test_pki.server.key),
    }

    config = _load(splunkd, splunk_home)

    assert config.server_cert == str(test_pki.server.cert)
    assert config.server_key == str(test_pki.server.key)
    assert not any(path.endswith("conf-server/sslConfig") for path, _, _ in splunkd.requests)


def test_default_key_with_an_unknown_password_is_refused_clearly(test_pki, splunkd, splunk_home):
    _write_combined_pem(test_pki, splunk_home / "etc" / "auth" / "server.pem", password="changed-by-admin")

    with pytest.raises(splunk_config.ConfigError, match="key password"):
        _load(splunkd, splunk_home)


def test_missing_ca_bundle_means_not_configured(test_pki, splunkd, splunk_home):
    splunkd.content_overrides["settings_listener.json"] = {"ca_bundle": None}

    with pytest.raises(splunk_config.NotConfigured):
        _load(splunkd, splunk_home)


def test_expired_session_key_is_reported(test_pki, splunkd, splunk_home):
    with pytest.raises(splunk_config.SessionExpired):
        splunk_config.load(splunkd.uri, "stale-key", str(splunk_home))


def test_no_mappings_yet_gives_an_empty_mapping_list(test_pki, splunkd, splunk_home):
    _write_combined_pem(test_pki, splunk_home / "etc" / "auth" / "server.pem")
    splunkd.empty.add("mappings.json")

    assert _load(splunkd, splunk_home).mappings == []


def test_mapping_whose_token_could_not_be_decrypted_is_skipped(test_pki, splunkd, splunk_home):
    _write_combined_pem(test_pki, splunk_home / "etc" / "auth" / "server.pem")
    # UCC's masked placeholder is what a list returns without --cred--=1, or when decryption fails.
    splunkd.content_overrides["mappings.json"] = {"token": "******"}

    assert [m.account for m in _load(splunkd, splunk_home).mappings] == ["svc_agent_b"]
