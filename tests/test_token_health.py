"""Admins see expiring and rejected tokens in the log, the audit file and on /health, never the tokens."""

import dataclasses
import datetime
import json
import logging

from mtls_bridge import __version__
from mtls_bridge.config import Mapping

import pki
from harness import MAPPED_TOKEN, client_of, make_config, running_bridge, wait_for

TODAY = datetime.date.today()


def _expiring_in(days, **overrides):
    def build(test_pki, upstream):
        mapping = dataclasses.replace(
            make_config(test_pki, upstream).mappings[0], token_expiry=TODAY + datetime.timedelta(days=days)
        )
        return make_config(test_pki, upstream, mappings=[mapping], **overrides)

    return build


def _expiry_events(path):
    return [e for e in map(json.loads, path.read_text().splitlines()) if e["event"] == "token_expiry"]


def _initializes(upstream):
    return [r for r in upstream.received if r.json().get("method") == "initialize"]


def _token_status(bridge, test_pki):
    _, health = client_of(bridge, test_pki, test_pki.mapped).health()
    return health["mappings"][0]["token_status"]


def test_token_expiring_in_ten_days_warns_once_a_day(test_pki, upstream, tmp_path, caplog):
    audit = tmp_path / "audit.log"
    config = _expiring_in(10, audit_log=str(audit))(test_pki, upstream)
    with caplog.at_level(logging.WARNING, logger="mtls_bridge"), running_bridge(config) as bridge:
        for _ in range(3):  # three config polls on one day
            bridge.check_tokens()
        status, health = client_of(bridge, test_pki, test_pki.mapped).health()
        bridge.check_tokens(today=TODAY + datetime.timedelta(days=1))

    assert status == 200
    [mapping] = health["mappings"]
    assert mapping["account"] == "svc_agent_a"
    assert mapping["token_expiry"] == (TODAY + datetime.timedelta(days=10)).isoformat()
    assert mapping["days_remaining"] == 10
    assert mapping["expiry_status"] == "expiring"
    assert health["status"] == "warning"
    first, second = _expiry_events(audit)
    assert (first["user"], first["days_remaining"], first["status"]) == ("svc_agent_a", 10, "expiring")
    assert second["days_remaining"] == 9
    warnings = [r for r in caplog.records if "svc_agent_a" in r.getMessage() and "expires" in r.getMessage()]
    assert len(warnings) == 2


def test_token_expiring_later_is_quiet(test_pki, upstream, tmp_path):
    audit = tmp_path / "audit.log"
    with running_bridge(_expiring_in(30, audit_log=str(audit))(test_pki, upstream)) as bridge:
        bridge.check_tokens()
        _, health = client_of(bridge, test_pki, test_pki.mapped).health()

    assert health["mappings"][0]["expiry_status"] == "ok"
    assert health["status"] == "ok"
    assert not audit.exists() or _expiry_events(audit) == []


def test_expired_token_still_forwards_and_still_warns(test_pki, upstream, tmp_path):
    audit = tmp_path / "audit.log"
    with running_bridge(_expiring_in(-3, audit_log=str(audit))(test_pki, upstream)) as bridge:
        bridge.check_tokens()
        client = client_of(bridge, test_pki, test_pki.mapped)
        status, _, _ = client.rpc("tools/list")
        _, health = client.health()

    assert status == 200
    assert health["mappings"][0]["expiry_status"] == "expired"
    assert health["mappings"][0]["days_remaining"] == -3
    [event] = _expiry_events(audit)
    assert event["status"] == "expired"


def test_new_token_the_upstream_rejects_is_flagged_without_a_client_request(test_pki, upstream):
    upstream.status = 401
    with running_bridge(make_config(test_pki, upstream)) as bridge:
        bridge.check_tokens()
        wait_for(lambda: bridge.health()["mappings"][0]["token_status"] == "invalid")
        [check] = _initializes(upstream)
        assert check.headers["Authorization"] == "Bearer " + MAPPED_TOKEN
        assert "X-Forwarded-For" not in check.headers
        upstream.status = 200
        assert _token_status(bridge, test_pki) == "invalid"
        assert bridge.health()["status"] == "degraded"


def test_unchanged_token_is_checked_once(test_pki, upstream):
    with running_bridge(make_config(test_pki, upstream)) as bridge:
        bridge.check_tokens()
        wait_for(lambda: bridge.health()["mappings"][0]["token_status"] == "ok")
        bridge.apply(make_config(test_pki, upstream))
        bridge.check_tokens()
        bridge.check_tokens()

    assert len(_initializes(upstream)) == 1


def test_token_check_is_retried_when_the_upstream_was_unreachable(test_pki, upstream, unused_port):
    config = make_config(test_pki, upstream, upstream_url=f"https://127.0.0.1:{unused_port}/services/mcp")
    with running_bridge(config) as bridge:
        bridge.check_tokens()
        wait_for(lambda: not bridge.tokens_checking())
        assert bridge.health()["mappings"][0]["token_status"] == "unchecked"
        bridge.apply(make_config(test_pki, upstream))
        bridge.check_tokens()
        wait_for(lambda: bridge.health()["mappings"][0]["token_status"] == "ok")


def test_forwarding_401_flags_the_mapping_and_a_changed_token_clears_it(test_pki, upstream):
    with running_bridge(make_config(test_pki, upstream)) as bridge:
        client = client_of(bridge, test_pki, test_pki.mapped)
        upstream.status = 401
        status, _, _ = client.rpc("tools/list")
        assert status == 502
        assert _token_status(bridge, test_pki) == "invalid"

        rotated = dataclasses.replace(make_config(test_pki, upstream).mappings[0], token="rotated-token")
        upstream.status = 200
        bridge.apply(make_config(test_pki, upstream, mappings=[rotated]))
        assert _token_status(bridge, test_pki) == "unchecked"
        client.rpc("tools/list")
        assert _token_status(bridge, test_pki) == "ok"


def test_successful_call_clears_a_401_flag(test_pki, upstream):
    with running_bridge(make_config(test_pki, upstream)) as bridge:
        client = client_of(bridge, test_pki, test_pki.mapped)
        upstream.status = 401
        client.rpc("tools/list")
        upstream.status = 200
        client.rpc("tools/list")
        assert _token_status(bridge, test_pki) == "ok"


def test_health_reports_version_and_crl_and_never_tokens(test_pki, upstream):
    config = make_config(test_pki, upstream, crl_file=str(test_pki.crls["valid"]))
    with running_bridge(config) as bridge:
        status, headers, data = client_of(bridge, test_pki, test_pki.mapped).request("GET", path="/health")

    assert status == 200
    assert headers["Content-Type"] == "application/json"
    health = json.loads(data)
    assert health["version"] == __version__
    assert health["crl"]["present"] is True
    assert datetime.datetime.fromisoformat(health["crl"]["next_update"]) > datetime.datetime.now(datetime.timezone.utc)
    assert MAPPED_TOKEN.encode() not in data
    assert b'token"' not in data.replace(b"token_", b"")


def test_health_without_a_crl(test_pki, upstream):
    with running_bridge(make_config(test_pki, upstream)) as bridge:
        _, health = client_of(bridge, test_pki, test_pki.mapped).health()

    assert health["crl"] == {"present": False, "next_update": None, "expired": False}
    assert health["mappings"][0]["token_expiry"] is None
    assert health["mappings"][0]["days_remaining"] is None


def test_health_lists_every_mapping(test_pki, upstream):
    other = Mapping(
        issuer=test_pki.other_ca.issuer_dn,
        identity_type="URI",
        identity_value=pki.MAPPED_URI,
        account="svc_other",
        token="other-token",
    )
    config = make_config(test_pki, upstream)
    with running_bridge(dataclasses.replace(config, mappings=[*config.mappings, other])) as bridge:
        _, health = client_of(bridge, test_pki, test_pki.mapped).health()

    assert [m["account"] for m in health["mappings"]] == ["svc_agent_a", "svc_other"]
    assert b"other-token" not in json.dumps(health).encode()


def test_health_refuses_unmapped_certs(test_pki, upstream):
    with running_bridge(make_config(test_pki, upstream)) as bridge:
        status, health = client_of(bridge, test_pki, test_pki.unmapped).health()

    assert status == 403
    assert "mappings" not in health


def test_other_gets_are_still_refused(test_pki, upstream):
    with running_bridge(make_config(test_pki, upstream)) as bridge:
        status, _, _ = client_of(bridge, test_pki, test_pki.mapped).request("GET", path="/services/mcp")

    assert status == 405
