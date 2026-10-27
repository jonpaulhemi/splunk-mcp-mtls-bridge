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


def _audit(tmp_path):
    path = tmp_path / "audit.log"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def _use(crl_path, source):
    crl_path.write_bytes(source.read_bytes())


def test_revoked_cert_fails_the_handshake_and_others_still_work(test_pki, upstream, ca_bundle, crl_path, tmp_path):
    _use(crl_path, test_pki.crls["valid"])
    with running_bridge(_config(test_pki, upstream, ca_bundle, crl_path, tmp_path)) as bridge:
        assert _status(bridge, test_pki, test_pki.revoked) == "handshake failed"
        assert _status(bridge, test_pki, test_pki.mapped) == 200
        assert _status(bridge, test_pki, test_pki.via_intermediate) == 200

    [failure] = [e for e in _audit(tmp_path) if e["event"] == "handshake_failure"]
    assert "revoked" in failure["reason"]


def test_without_a_crl_path_revocation_is_not_checked(test_pki, upstream, ca_bundle, crl_path, tmp_path):
    _use(crl_path, test_pki.crls["valid"])
    config = _config(test_pki, upstream, ca_bundle, crl_path, tmp_path, crl_file=None)
    with running_bridge(config) as bridge:
        assert _status(bridge, test_pki, test_pki.revoked) == 200


def test_revoked_intermediate_blocks_its_leaves_only_in_chain_mode(test_pki, upstream, ca_bundle, crl_path, tmp_path):
    _use(crl_path, test_pki.crls["revoked_intermediate"])
    with running_bridge(_config(test_pki, upstream, ca_bundle, crl_path, tmp_path, crl_check="leaf")) as bridge:
        assert _status(bridge, test_pki, test_pki.via_intermediate) == 200
    with running_bridge(_config(test_pki, upstream, ca_bundle, crl_path, tmp_path, crl_check="chain")) as bridge:
        assert _status(bridge, test_pki, test_pki.via_intermediate) == "handshake failed"
        assert _status(bridge, test_pki, test_pki.mapped) == 200


def test_new_crl_is_swapped_in_on_the_next_poll(test_pki, upstream, ca_bundle, crl_path, tmp_path):
    crl_path.write_bytes(pki.crl(test_pki.ca) + pki.crl(test_pki.intermediate))
    config = _config(test_pki, upstream, ca_bundle, crl_path, tmp_path)
    with running_bridge(config) as bridge:
        assert _status(bridge, test_pki, test_pki.revoked) == 200
        _use(crl_path, test_pki.crls["valid"])
        bridge.apply(config)
        assert _status(bridge, test_pki, test_pki.revoked) == "handshake failed"


@pytest.mark.parametrize("replacement", ["malformed", "expired"])
def test_bad_replacement_keeps_the_previous_crl(test_pki, upstream, ca_bundle, crl_path, tmp_path, caplog, replacement):
    _use(crl_path, test_pki.crls["valid"])
    config = _config(test_pki, upstream, ca_bundle, crl_path, tmp_path)
    with running_bridge(config) as bridge:
        _use(crl_path, test_pki.crls[replacement])
        with caplog.at_level(logging.ERROR, logger="mtls_bridge"):
            bridge.apply(config)

        assert "keeping the previous CRL" in caplog.text
        assert _status(bridge, test_pki, test_pki.revoked) == "handshake failed"
        assert _status(bridge, test_pki, test_pki.mapped) == 200


def test_crl_that_is_not_valid_yet_is_refused(test_pki, upstream, ca_bundle, crl_path, tmp_path, caplog):
    _use(crl_path, test_pki.crls["valid"])
    config = _config(test_pki, upstream, ca_bundle, crl_path, tmp_path)
    with running_bridge(config) as bridge:
        crl_path.write_bytes(pki.crl(test_pki.ca, this_update=HOUR) + pki.crl(test_pki.intermediate))
        with caplog.at_level(logging.ERROR, logger="mtls_bridge"):
            bridge.apply(config)
        assert "isn't valid yet" in caplog.text
        assert _status(bridge, test_pki, test_pki.mapped) == 200


def test_bad_crl_file_on_first_enable_stays_refused(test_pki, upstream, ca_bundle, crl_path, tmp_path):
    _use(crl_path, test_pki.crls["malformed"])
    with running_bridge(_config(test_pki, upstream, ca_bundle, crl_path, tmp_path, crl_file=None)) as bridge:
        enabled = _config(test_pki, upstream, ca_bundle, crl_path, tmp_path)
        for _ in range(2):  # the second poll sees the same bytes
            with pytest.raises(ApplyError, match="CRL"):
                bridge.apply(enabled)
        assert bridge.config.crl_file is None


def test_crl_nearing_next_update_warns(test_pki, upstream, ca_bundle, crl_path, tmp_path, caplog):
    _use(crl_path, test_pki.crls["near_expiry"])
    with caplog.at_level(logging.WARNING, logger="mtls_bridge"):
        with running_bridge(_config(test_pki, upstream, ca_bundle, crl_path, tmp_path)):
            pass
    assert "nextUpdate" in caplog.text
    assert "within 24 hours" in caplog.text


def test_expired_crl_fails_closed_for_every_client_by_default(test_pki, upstream, ca_bundle, crl_path, tmp_path):
    # Only the root CA's CRL expires; clients of the intermediate are refused too.
    crl_path.write_bytes(
        pki.crl(test_pki.ca, next_update=datetime.timedelta(seconds=2)) + pki.crl(test_pki.intermediate)
    )
    config = _config(test_pki, upstream, ca_bundle, crl_path, tmp_path)
    with running_bridge(config) as bridge:
        assert _status(bridge, test_pki, test_pki.mapped) == 200
        time.sleep(2.5)  # past the CRL's nextUpdate
        bridge.apply(config)
        assert _status(bridge, test_pki, test_pki.mapped) == "handshake failed"
        assert _status(bridge, test_pki, test_pki.via_intermediate) == "handshake failed"

        _use(crl_path, test_pki.crls["valid"])
        bridge.apply(config)
        assert _status(bridge, test_pki, test_pki.mapped) == 200

    events = _audit(tmp_path)
    assert [e["policy"] for e in events if e["event"] == "crl_expired"] == ["fail_closed"]
    assert any("fail_closed" in e["reason"] for e in events if e["event"] == "handshake_failure")


def test_expired_crl_fails_open_and_every_audit_event_warns(test_pki, upstream, ca_bundle, crl_path, tmp_path):
    soon = datetime.timedelta(seconds=2)
    crl_path.write_bytes(
        pki.crl(test_pki.ca, [test_pki.revoked.cert], next_update=soon) + pki.crl(test_pki.intermediate)
    )
    config = _config(test_pki, upstream, ca_bundle, crl_path, tmp_path, crl_expiry="fail_open")
    with running_bridge(config) as bridge:
        time.sleep(2.5)  # past the CRL's nextUpdate
        bridge.apply(config)
        # Revocation is off while the CRL is stale.
        assert _status(bridge, test_pki, test_pki.revoked) == 200
        assert _status(bridge, test_pki, test_pki.mapped) == 200

    events = _audit(tmp_path)
    assert [e["policy"] for e in events if e["event"] == "crl_expired"] == ["fail_open"]
    calls = [e for e in events if e["event"] == "call"]
    assert len(calls) == 2
    assert all("fail_open" in call["warning"] for call in calls)


def test_unreadable_crl_at_startup_is_refused(test_pki, upstream, ca_bundle, crl_path, tmp_path):
    _use(crl_path, test_pki.crls["malformed"])
    with pytest.raises(ValueError):
        running_bridge(_config(test_pki, upstream, ca_bundle, crl_path, tmp_path)).__enter__()


def test_deleted_crl_file_keeps_the_previous_crl(test_pki, upstream, ca_bundle, crl_path, tmp_path, caplog):
    _use(crl_path, test_pki.crls["valid"])
    config = _config(test_pki, upstream, ca_bundle, crl_path, tmp_path)
    with running_bridge(config) as bridge:
        crl_path.unlink()
        with caplog.at_level(logging.ERROR, logger="mtls_bridge"):
            bridge.apply(config)
        assert "keeping the previous CRL" in caplog.text
        assert _status(bridge, test_pki, test_pki.revoked) == "handshake failed"
        assert _status(bridge, test_pki, test_pki.mapped) == 200


def test_bad_crl_settings_are_refused(test_pki, upstream, ca_bundle, crl_path, tmp_path):
    _use(crl_path, test_pki.crls["valid"])
    with running_bridge(_config(test_pki, upstream, ca_bundle, crl_path, tmp_path)) as bridge:
        with pytest.raises(ApplyError, match="leaf or chain"):
            bridge.apply(_config(test_pki, upstream, ca_bundle, crl_path, tmp_path, crl_check="deep"))
