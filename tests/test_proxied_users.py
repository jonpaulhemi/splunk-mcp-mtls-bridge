"""A client mapped as proxying users names each call's user in X-ProxiedEntitiesChain; the bridge forwards
the call with the token of the role account that user's rule points at."""

import dataclasses
import json

import pytest

from mtls_bridge.config import Mapping, RoleAccount, UserRule

import pki
from harness import (
    ANALYST_TOKEN,
    ENGINEER_TOKEN,
    JOHN,
    MAPPED_TOKEN,
    client_of,
    make_proxy_config,
    running_bridge,
    wait_for,
)

HEADER = "X-ProxiedEntitiesChain"
_proxy_config = make_proxy_config


@pytest.fixture
def audit_path(tmp_path):
    return tmp_path / "audit.log"


@pytest.fixture
def proxy(test_pki, upstream, audit_path):
    with running_bridge(_proxy_config(test_pki, upstream, audit_log=str(audit_path))) as bridge:
        yield bridge


def _events(path, count=1):
    """The audit events, once ``count`` have been written: each is written after its response goes out."""
    wait_for(lambda: path.exists() and len(path.read_text().splitlines()) >= count)
    return [json.loads(line) for line in path.read_text().splitlines()]


def _proxy_client(bridge, test_pki):
    return client_of(bridge, test_pki, test_pki.unmapped)


@pytest.mark.parametrize(
    "header, token",
    [
        (JOHN, ANALYST_TOKEN),
        ("CN=Jane Doe,OU=Users,O=Org,C=US", ENGINEER_TOKEN),
        (f"<{JOHN}>", ANALYST_TOKEN),
        ("cn=john smith, ou=USERS, o=org, c=us", ANALYST_TOKEN),
        (" <CN=John Smith,OU=Users,O=Org,C=US> ", ANALYST_TOKEN),
    ],
)
def test_named_user_is_forwarded_with_their_role_accounts_token(proxy, test_pki, upstream, header, token):
    status, _, body = _proxy_client(proxy, test_pki).rpc("tools/list", request_id=4, headers={HEADER: header})

    assert status == 200
    assert body["id"] == 4
    [forwarded] = upstream.received
    assert forwarded.headers["Authorization"] == "Bearer " + token
    assert HEADER.lower() not in {name.lower() for name in forwarded.headers}


def test_proxied_call_is_audited_with_the_user_rule_and_role_account(proxy, test_pki, audit_path):
    _proxy_client(proxy, test_pki).rpc("tools/list", headers={HEADER: f"<{JOHN}>"})

    [event] = _events(audit_path)
    assert event["event"] == "call"
    assert (event["identity_type"], event["identity"]) == ("URI", "spiffe://bridge.test/agent-b")
    assert event["user"] == "mcp_analyst"
    assert event["user_dn"] == "CN=john smith,OU=users,O=org,C=us"
    assert event["user_rule"] == "john"
    assert event["role_account"] == "analysts"
    assert ANALYST_TOKEN not in audit_path.read_text()


def _refused(bridge, test_pki, upstream, audit_path, client, headers):
    status, headers_out, body = client.rpc("tools/list", request_id=9, headers=headers)
    assert status == 403
    assert headers_out["Content-Type"] == "application/json"
    assert body["id"] == 9
    assert body["error"]["message"]
    assert upstream.received == []
    [event] = _events(audit_path)
    assert event["event"] == "rejection"
    assert event["status"] == 403
    return body, event


def test_proxying_client_without_a_user_is_refused(proxy, test_pki, upstream, audit_path):
    body, event = _refused(proxy, test_pki, upstream, audit_path, _proxy_client(proxy, test_pki), {})

    assert event["reason"] == "proxied_user_missing"
    assert "user_dn" not in event
    assert HEADER in body["error"]["message"]


@pytest.mark.parametrize(
    "header",
    [
        "",
        "   ",
        f"<{JOHN}><CN=Proxy,O=Org>",
        f"<{JOHN}",
        f"{JOHN}>",
        "<>",
        "John Smith",
        "FOO=bar,O=Org",
        "CN=" + "x" * 5000,
    ],
)
def test_malformed_user_header_is_refused(proxy, test_pki, upstream, audit_path, header):
    _, event = _refused(proxy, test_pki, upstream, audit_path, _proxy_client(proxy, test_pki), {HEADER: header})

    assert event["reason"] == "proxied_user_malformed"
    # HTTP drops the spaces around a header value.
    assert event["user_dn"] == header.strip()[:4096]


def test_user_no_rule_matches_is_refused(proxy, test_pki, upstream, audit_path):
    stranger = "CN=Eve,OU=Users,O=Org,C=US"
    body, event = _refused(proxy, test_pki, upstream, audit_path, _proxy_client(proxy, test_pki), {HEADER: stranger})

    assert event["reason"] == "user_unmatched"
    assert event["user_dn"] == stranger
    assert "rule" in body["error"]["message"]


def test_client_not_proxying_users_may_not_name_one(proxy, test_pki, upstream, audit_path):
    client = client_of(proxy, test_pki, test_pki.mapped)
    _, event = _refused(proxy, test_pki, upstream, audit_path, client, {HEADER: JOHN})

    assert event["reason"] == "proxied_user_not_allowed"
    assert event["user_dn"] == JOHN


def test_client_not_proxying_users_still_uses_its_own_account(proxy, test_pki, upstream):
    status, _, _ = client_of(proxy, test_pki, test_pki.mapped).rpc("tools/list")

    assert status == 200
    assert upstream.received[0].headers["Authorization"] == "Bearer " + MAPPED_TOKEN


def test_rule_whose_role_account_is_missing_matches_no_one(test_pki, upstream, audit_path):
    config = _proxy_config(
        test_pki, upstream, audit_log=str(audit_path), user_rules=[UserRule("john", "dn", JOHN, "gone")]
    )
    with running_bridge(config) as bridge:
        status, _, _ = _proxy_client(bridge, test_pki).rpc("tools/list", headers={HEADER: JOHN})

    assert status == 403
    assert upstream.received == []
    assert _events(audit_path)[0]["reason"] == "user_unmatched"


def test_ping_and_health_need_no_user(proxy, test_pki, upstream):
    client = _proxy_client(proxy, test_pki)

    status, _, body = client.rpc("ping", request_id=2)
    health_status, health = client.health()

    assert (status, body) == (200, {"jsonrpc": "2.0", "id": 2, "result": {}})
    assert health_status == 200
    assert upstream.received == []
    # A proxying client has no token of its own to report.
    assert [m["account"] for m in health["mappings"]] == ["svc_agent_a"]


def test_changed_rules_apply_without_a_restart(test_pki, upstream):
    config = _proxy_config(test_pki, upstream)
    with running_bridge(config) as bridge:
        client = _proxy_client(bridge, test_pki)
        client.rpc("tools/list", headers={HEADER: JOHN})
        bridge.apply(dataclasses.replace(config, user_rules=[UserRule("john", "dn", JOHN, "engineers")]))
        client.rpc("tools/list", headers={HEADER: JOHN})
        bridge.apply(dataclasses.replace(config, user_rules=[]))
        status, _, _ = client.rpc("tools/list", headers={HEADER: JOHN})

    assert [r.headers["Authorization"] for r in upstream.received] == [
        "Bearer " + ANALYST_TOKEN,
        "Bearer " + ENGINEER_TOKEN,
    ]
    assert status == 403


def test_user_rule_that_is_not_a_dn_cannot_be_built():
    with pytest.raises(ValueError):
        UserRule("bad", "dn", "John Smith", "analysts")


def test_flagged_mapping_needs_no_account_or_token(test_pki):
    mapping = Mapping(test_pki.ca.issuer_dn, "URI", pki.MAPPED_URI, proxies_users=True)

    assert (mapping.account, mapping.token, mapping.proxies_users) == ("", "", True)


def test_client_not_proxying_users_may_not_name_one_even_in_a_ping(proxy, test_pki, upstream, audit_path):
    client = client_of(proxy, test_pki, test_pki.mapped)
    status, _, _ = client.rpc("ping", headers={HEADER: JOHN})

    assert status == 403
    assert _events(audit_path)[0]["reason"] == "proxied_user_not_allowed"


def test_changed_role_accounts_apply_without_a_restart(test_pki, upstream):
    config = _proxy_config(test_pki, upstream)
    with running_bridge(config) as bridge:
        client = _proxy_client(bridge, test_pki)
        client.rpc("tools/list", headers={HEADER: JOHN})
        bridge.apply(dataclasses.replace(config, role_accounts=[RoleAccount("analysts", "mcp_analyst", "renewed")]))
        client.rpc("tools/list", headers={HEADER: JOHN})
        bridge.apply(dataclasses.replace(config, role_accounts=[]))
        status, _, _ = client.rpc("tools/list", headers={HEADER: JOHN})

    assert [r.headers["Authorization"] for r in upstream.received] == ["Bearer " + ANALYST_TOKEN, "Bearer renewed"]
    assert status == 403


def _attribute_config(test_pki, upstream, audit_path, rules):
    return _proxy_config(test_pki, upstream, audit_log=str(audit_path), user_rules=rules)


@pytest.mark.parametrize(
    "header",
    [
        JOHN,
        "CN=Jane Doe,OU=Users,O=Org,C=US",
        "cn=someone, ou=USERS, o=org",
        "CN=Multi,OU=Users+OU=Staff,O=Org",
        "O=Org,OU=Users,CN=Reversed",
    ],
)
def test_attribute_rule_matches_every_dn_holding_its_attributes(test_pki, upstream, audit_path, header):
    rules = [UserRule("org_users", "attributes", "OU=Users,O=Org", "analysts")]
    with running_bridge(_attribute_config(test_pki, upstream, audit_path, rules)) as bridge:
        status, _, _ = _proxy_client(bridge, test_pki).rpc("tools/list", headers={HEADER: header})

    assert status == 200
    assert upstream.received[0].headers["Authorization"] == "Bearer " + ANALYST_TOKEN
    event = _events(audit_path)[0]
    assert (event["user_rule"], event["role_account"]) == ("org_users", "analysts")


@pytest.mark.parametrize(
    "header",
    ["CN=Eve,OU=Contractors,O=Org", "CN=Eve,OU=Users,O=Other", "CN=Eve,OU=Users", "CN=Users,O=Org"],
)
def test_attribute_rule_needs_all_its_attributes(test_pki, upstream, audit_path, header):
    rules = [UserRule("org_users", "attributes", "OU=Users,O=Org", "analysts")]
    with running_bridge(_attribute_config(test_pki, upstream, audit_path, rules)) as bridge:
        status, _, _ = _proxy_client(bridge, test_pki).rpc("tools/list", headers={HEADER: header})

    assert status == 403
    assert _events(audit_path)[0]["reason"] == "user_unmatched"


def test_repeated_attribute_must_each_be_present(test_pki, upstream, audit_path):
    rules = [UserRule("staff_users", "attributes", "OU=Users,OU=Staff", "analysts")]
    with running_bridge(_attribute_config(test_pki, upstream, audit_path, rules)) as bridge:
        client = _proxy_client(bridge, test_pki)
        only_one, _, _ = client.rpc("tools/list", headers={HEADER: "CN=A,OU=Users,O=Org"})
        both, _, _ = client.rpc("tools/list", headers={HEADER: "CN=B,OU=Staff,OU=Users,O=Org"})

    assert (only_one, both) == (403, 200)


def test_exact_dn_rule_wins_over_attribute_rules(test_pki, upstream, audit_path):
    rules = [
        UserRule("org_users", "attributes", "OU=Users,O=Org", "analysts"),
        UserRule("all_org", "attributes", "O=Org", "analysts"),
        UserRule("john", "dn", JOHN, "engineers"),
    ]
    with running_bridge(_attribute_config(test_pki, upstream, audit_path, rules)) as bridge:
        status, _, _ = _proxy_client(bridge, test_pki).rpc("tools/list", headers={HEADER: JOHN})

    assert status == 200
    assert upstream.received[0].headers["Authorization"] == "Bearer " + ENGINEER_TOKEN
    assert _events(audit_path)[0]["user_rule"] == "john"


def test_two_matching_attribute_rules_are_ambiguous(test_pki, upstream, audit_path):
    rules = [
        UserRule("org_users", "attributes", "OU=Users,O=Org", "analysts"),
        UserRule("all_org", "attributes", "O=Org", "engineers"),
    ]
    with running_bridge(_attribute_config(test_pki, upstream, audit_path, rules)) as bridge:
        status, _, body = _proxy_client(bridge, test_pki).rpc("tools/list", headers={HEADER: JOHN})

    assert status == 403
    assert "rule" in body["error"]["message"]
    assert upstream.received == []
    event = _events(audit_path)[0]
    assert (event["reason"], event["user_dn"]) == ("user_ambiguous", JOHN)


def test_attribute_rule_that_is_not_a_dn_cannot_be_built():
    with pytest.raises(ValueError):
        UserRule("bad", "attributes", "Users", "analysts")


def test_exact_rule_whose_role_account_is_missing_does_not_fall_through(test_pki, upstream, audit_path):
    """An exact rule still wins when its role account didn't load: John gets no access, not the group's."""
    rules = [
        UserRule("org_users", "attributes", "OU=Users,O=Org", "analysts"),
        UserRule("john", "dn", JOHN, "gone"),
    ]
    with running_bridge(_attribute_config(test_pki, upstream, audit_path, rules)) as bridge:
        status, _, _ = _proxy_client(bridge, test_pki).rpc("tools/list", headers={HEADER: JOHN})

    assert status == 403
    assert upstream.received == []
    assert _events(audit_path)[0]["reason"] == "user_unmatched"
