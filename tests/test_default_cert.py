"""The bridge warns when its listener serves Splunk's default self-signed server cert."""

import logging

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import pki
from harness import make_config, running_bridge

DEFAULT_CERT_WARNING = "Splunk's default server certificate"


def _splunk_default_cert(directory):
    """A cert shaped like the one Splunk generates at install: issued by SplunkCommonCA."""
    ca = pki.make_ca(
        directory,
        "SplunkCommonCA",
        org="Splunk",
        extra=[
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, "support@splunk.com"),
        ],
    )
    # Deliberately not at Splunk's default path: detection goes by issuer, not file name.
    return pki.issue(ca, directory, "listener", "SplunkServerDefaultCert", eku=ExtendedKeyUsageOID.SERVER_AUTH)


def test_default_splunk_cert_warns_at_startup(test_pki, upstream, tmp_path, caplog):
    cert = _splunk_default_cert(tmp_path)
    config = make_config(test_pki, upstream, server_cert=str(cert.cert), server_key=str(cert.key))
    with caplog.at_level(logging.WARNING, logger="mtls_bridge"), running_bridge(config):
        pass

    [warning] = [r for r in caplog.records if DEFAULT_CERT_WARNING in r.getMessage()]
    assert warning.levelno == logging.WARNING
    assert "listener cert" in warning.getMessage()


def test_default_cert_swapped_in_at_the_same_path_warns(test_pki, upstream, tmp_path, caplog):
    default = _splunk_default_cert(tmp_path)
    cert, key = tmp_path / "server.crt", tmp_path / "server.key"
    cert.write_bytes(test_pki.server.cert.read_bytes())
    key.write_bytes(test_pki.server.key.read_bytes())
    config = make_config(test_pki, upstream, server_cert=str(cert), server_key=str(key))
    with caplog.at_level(logging.WARNING, logger="mtls_bridge"), running_bridge(config) as bridge:
        assert DEFAULT_CERT_WARNING not in caplog.text
        cert.write_bytes(default.cert.read_bytes())
        key.write_bytes(default.key.read_bytes())
        bridge.apply(config)

    assert DEFAULT_CERT_WARNING in caplog.text


def test_splunk_style_combined_pem_is_recognised(test_pki, upstream, tmp_path, caplog):
    # Splunk's server.pem holds the cert, then its key, then the CA.
    default = _splunk_default_cert(tmp_path)
    combined = tmp_path / "server.pem"
    ca = tmp_path / "SplunkCommonCA.pem"
    combined.write_bytes(default.cert.read_bytes() + default.key.read_bytes() + ca.read_bytes())
    config = make_config(test_pki, upstream, server_cert=str(combined), server_key=str(combined))
    with caplog.at_level(logging.WARNING, logger="mtls_bridge"), running_bridge(config):
        pass

    assert DEFAULT_CERT_WARNING in caplog.text


def test_pki_cert_does_not_warn(test_pki, upstream, caplog):
    with caplog.at_level(logging.WARNING, logger="mtls_bridge"), running_bridge(make_config(test_pki, upstream)):
        pass

    assert DEFAULT_CERT_WARNING not in caplog.text
