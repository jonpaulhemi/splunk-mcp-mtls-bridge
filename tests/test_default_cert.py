"""The bridge warns when its listener serves Splunk's default self-signed server cert."""

import json
import logging
import shutil
import subprocess
import sys

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import pki
from harness import ROOT, make_config, running_bridge

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


def test_pki_cert_does_not_warn(test_pki, upstream, caplog):
    with caplog.at_level(logging.WARNING, logger="mtls_bridge"), running_bridge(make_config(test_pki, upstream)):
        pass

    assert DEFAULT_CERT_WARNING not in caplog.text


def test_version_comes_from_the_installed_apps_manifest(tmp_path):
    # ucc-gen stamps the release tag's version into app.manifest; the daemon reports what it finds there.
    app = tmp_path / "TA-mtls-bridge"
    shutil.copytree(ROOT / "package" / "bin", app / "bin")
    manifest = json.loads((ROOT / "package" / "app.manifest").read_text())
    manifest["info"]["id"]["version"] = "9.8.7"
    (app / "app.manifest").write_text(json.dumps(manifest))

    code = "import mtls_bridge; print(mtls_bridge.__version__)"
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", f"import sys; sys.path.insert(0, 'bin'); {code}"],
        cwd=str(app),
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == "9.8.7", result.stderr
