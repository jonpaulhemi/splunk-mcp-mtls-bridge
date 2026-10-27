"""Optional CRL revocation: a CRL file dropped on disk, checked on every config poll."""

import datetime
import json
import logging
import ssl
import time

import pytest

from mtls_bridge.config import Mapping
from mtls_bridge.server import ApplyError

import pki
from harness import Client, make_config, running_bridge

HOUR = datetime.timedelta(hours=1)


@pytest.fixture
def ca_bundle(test_pki, tmp_path):
    """Trusts the test CA and its intermediate."""
    path = tmp_path / "clients.pem"
    path.write_bytes(test_pki.ca.cert_path.read_bytes() + test_pki.intermediate.cert_path.read_bytes())
    return path


@pytest.fixture
def crl_path(tmp_path):
    return tmp_path / "clients.crl"


def _mappings(test_pki):
    return [
        Mapping(test_pki.ca.issuer_dn, "URI", pki.MAPPED_URI, "svc_agent_a", token="t-a"),
        Mapping(test_pki.ca.issuer_dn, "URI", pki.REVOKED_URI, "svc_agent_r", token="t-r"),
        Mapping(test_pki.intermediate.issuer_dn, "URI", pki.INTERMEDIATE_URI, "svc_agent_i", token="t-i"),
    ]


def _config(test_pki, upstream, ca_bundle, crl_path, tmp_path, **overrides):
    values = dict(
        ca_bundle=str(ca_bundle),
        crl_file=str(crl_path),
        mappings=_mappings(test_pki),
        audit_log=str(tmp_path / "audit.log"),
    )
    values.update(overrides)
    return make_config(test_pki, upstream, **values)


def _status(bridge, test_pki, issued):
    try:
        return Client(bridge.address, test_pki.ca.cert_path, issued).rpc("tools/list")[0]
    except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
        return "handshake failed"


def _leaf_crls(test_pki, revoked=()):
    """CRLs for both issuing CAs, which leaf checking needs for every client's issuer."""
    return pki.crl(test_pki.ca, revoked) + pki.crl(test_pki.intermediate)


def _audit(tmp_path):
    path = tmp_path / "audit.log"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def test_revoked_cert_fails_the_handshake_and_others_still_work(test_pki, upstream, ca_bundle, crl_path, tmp_path):
    crl_path.write_bytes(_leaf_crls(test_pki, revoked=[test_pki.revoked.cert]))
    with running_bridge(_config(test_pki, upstream, ca_bundle, crl_path, tmp_path)) as bridge:
        assert _status(bridge, test_pki, test_pki.revoked) == "handshake failed"
        assert _status(bridge, test_pki, test_pki.mapped) == 200
        assert _status(bridge, test_pki, test_pki.via_intermediate) == 200

    [failure] = [e for e in _audit(tmp_path) if e["event"] == "handshake_failure"]
    assert "revoked" in failure["reason"]


def test_without_a_crl_path_revocation_is_not_checked(test_pki, upstream, ca_bundle, crl_path, tmp_path):
    crl_path.write_bytes(_leaf_crls(test_pki, revoked=[test_pki.revoked.cert]))
    config = _config(test_pki, upstream, ca_bundle, crl_path, tmp_path, crl_file=None)
    with running_bridge(config) as bridge:
        assert _status(bridge, test_pki, test_pki.revoked) == 200


def test_revoked_intermediate_blocks_its_leaves_only_in_chain_mode(test_pki, upstream, ca_bundle, crl_path, tmp_path):
    crl_path.write_bytes(pki.crl(test_pki.ca, revoked=[test_pki.intermediate]) + pki.crl(test_pki.intermediate))
    with running_bridge(_config(test_pki, upstream, ca_bundle, crl_path, tmp_path, crl_check="leaf")) as bridge:
        assert _status(bridge, test_pki, test_pki.via_intermediate) == 200
    with running_bridge(_config(test_pki, upstream, ca_bundle, crl_path, tmp_path, crl_check="chain")) as bridge:
        assert _status(bridge, test_pki, test_pki.via_intermediate) == "handshake failed"
        assert _status(bridge, test_pki, test_pki.mapped) == 200


def test_new_crl_is_swapped_in_on_the_next_poll(test_pki, upstream, ca_bundle, crl_path, tmp_path):
    crl_path.write_bytes(_leaf_crls(test_pki))
    config = _config(test_pki, upstream, ca_bundle, crl_path, tmp_path)
    with running_bridge(config) as bridge:
        assert _status(bridge, test_pki, test_pki.revoked) == 200
        crl_path.write_bytes(_leaf_crls(test_pki, revoked=[test_pki.revoked.cert]))
        bridge.apply(config)
        assert _status(bridge, test_pki, test_pki.revoked) == "handshake failed"


@pytest.mark.parametrize(
    "replacement",
    [
        lambda test_pki: b"-----BEGIN X509 CRL-----\nbm90IGEgQ1JM\n-----END X509 CRL-----\n",
        lambda test_pki: pki.crl(test_pki.ca, next_update=-HOUR, this_update=-2 * HOUR)
        + pki.crl(test_pki.intermediate, next_update=-HOUR, this_update=-2 * HOUR),
    ],
    ids=["malformed", "expired"],
)
def test_bad_replacement_keeps_the_previous_crl(test_pki, upstream, ca_bundle, crl_path, tmp_path, caplog, replacement):
    crl_path.write_bytes(_leaf_crls(test_pki, revoked=[test_pki.revoked.cert]))
    config = _config(test_pki, upstream, ca_bundle, crl_path, tmp_path)
    with running_bridge(config) as bridge:
        crl_path.write_bytes(replacement(test_pki))
        with caplog.at_level(logging.ERROR, logger="mtls_bridge"):
            bridge.apply(config)

        assert "keeping the previous CRL" in caplog.text
        assert _status(bridge, test_pki, test_pki.revoked) == "handshake failed"
        assert _status(bridge, test_pki, test_pki.mapped) == 200


def test_crl_nearing_next_update_warns(test_pki, upstream, ca_bundle, crl_path, tmp_path, caplog):
    crl_path.write_bytes(pki.crl(test_pki.ca, next_update=12 * HOUR) + pki.crl(test_pki.intermediate))
    with caplog.at_level(logging.WARNING, logger="mtls_bridge"):
        with running_bridge(_config(test_pki, upstream, ca_bundle, crl_path, tmp_path)):
            pass
    assert "nextUpdate" in caplog.text
    assert "within 24 hours" in caplog.text


def _expiring_crls(test_pki, seconds):
    soon = datetime.timedelta(seconds=seconds)
    return pki.crl(test_pki.ca, next_update=soon) + pki.crl(test_pki.intermediate, next_update=soon)


def test_expired_crl_fails_closed_by_default(test_pki, upstream, ca_bundle, crl_path, tmp_path):
    crl_path.write_bytes(_expiring_crls(test_pki, 2))
    config = _config(test_pki, upstream, ca_bundle, crl_path, tmp_path)
    with running_bridge(config) as bridge:
        assert _status(bridge, test_pki, test_pki.mapped) == 200
        time.sleep(2.5)  # past the CRL's nextUpdate
        bridge.apply(config)
        assert _status(bridge, test_pki, test_pki.mapped) == "handshake failed"
        assert _status(bridge, test_pki, test_pki.via_intermediate) == "handshake failed"


def test_expired_crl_fails_open_with_a_repeated_audit_warning(test_pki, upstream, ca_bundle, crl_path, tmp_path):
    crl_path.write_bytes(_expiring_crls(test_pki, 2))
    config = _config(test_pki, upstream, ca_bundle, crl_path, tmp_path, crl_expiry="fail_open")
    with running_bridge(config) as bridge:
        time.sleep(2.5)  # past the CRL's nextUpdate
        bridge.apply(config)
        bridge.apply(config)
        assert _status(bridge, test_pki, test_pki.mapped) == 200
        # Revocation is off while the CRL is stale.
        assert _status(bridge, test_pki, test_pki.via_intermediate) == 200

    warnings = [e for e in _audit(tmp_path) if e["event"] == "crl_expired"]
    assert len(warnings) == 2
    assert warnings[0]["policy"] == "fail_open"


def test_unreadable_crl_at_startup_is_refused(test_pki, upstream, ca_bundle, crl_path, tmp_path):
    crl_path.write_bytes(b"garbage")
    with pytest.raises(ValueError):
        running_bridge(_config(test_pki, upstream, ca_bundle, crl_path, tmp_path)).__enter__()


def test_deleted_crl_file_keeps_the_previous_crl(test_pki, upstream, ca_bundle, crl_path, tmp_path, caplog):
    crl_path.write_bytes(_leaf_crls(test_pki, revoked=[test_pki.revoked.cert]))
    config = _config(test_pki, upstream, ca_bundle, crl_path, tmp_path)
    with running_bridge(config) as bridge:
        crl_path.unlink()
        with caplog.at_level(logging.ERROR, logger="mtls_bridge"):
            bridge.apply(config)
        assert "keeping the previous CRL" in caplog.text
        assert _status(bridge, test_pki, test_pki.revoked) == "handshake failed"
        assert _status(bridge, test_pki, test_pki.mapped) == 200


def test_bad_crl_settings_are_refused(test_pki, upstream, ca_bundle, crl_path, tmp_path):
    crl_path.write_bytes(_leaf_crls(test_pki))
    with running_bridge(_config(test_pki, upstream, ca_bundle, crl_path, tmp_path)) as bridge:
        with pytest.raises(ApplyError, match="leaf or chain"):
            bridge.apply(_config(test_pki, upstream, ca_bundle, crl_path, tmp_path, crl_check="deep"))
