"""The User rules and Role accounts REST handlers refuse rows that can't work, with Splunk's validation error."""

import pytest
from handler_stubs import load_handler, refused

ROLE_ACCOUNTS_CONF = "ta_mtls_bridge_role_accounts"
USER_RULES_CONF = "ta_mtls_bridge_user_rules"
ROLE_ACCOUNTS = {"analysts": {"account": "mcp_analyst"}, "engineers": {"account": "mcp_engineer"}}


def _rule(match="dn", value="CN=John Smith,OU=Users,O=Org,C=US", role_account="analysts"):
    return {"match": match, "value": value, "role_account": role_account}


@pytest.fixture
def rules_handler(monkeypatch):
    return load_handler(
        monkeypatch, "mtls_bridge_user_rules_handler", "UserRulesHandler", {ROLE_ACCOUNTS_CONF: ROLE_ACCOUNTS}
    )


def _role_accounts_handler(monkeypatch, rules):
    confs = {ROLE_ACCOUNTS_CONF: ROLE_ACCOUNTS}
    if rules is not None:
        confs[USER_RULES_CONF] = rules
    return load_handler(monkeypatch, "mtls_bridge_role_accounts_handler", "RoleAccountsHandler", confs)


@pytest.mark.parametrize(
    "row",
    [
        _rule(),
        _rule(match="attributes", value="OU=Analysts,O=Org"),
        _rule(role_account="engineers"),
    ],
)
def test_a_good_rule_saves(rules_handler, row):
    handler = rules_handler("john", row, {})
    handler.handleCreate(None)
    assert handler.saved == "create"


@pytest.mark.parametrize(
    "row, words",
    [
        (_rule(value="John Smith"), "RFC 4514"),
        (_rule(value="FOO=bar,O=Org"), "FOO"),
        (_rule(match="attributes", value="Analysts"), "RFC 4514"),
        (_rule(match="regex"), "match"),
        (_rule(role_account="gone"), "gone"),
        (_rule(role_account=""), "role account"),
    ],
)
def test_a_rule_that_cannot_work_is_a_validation_error(rules_handler, row, words):
    assert words in refused(rules_handler("john", row, {}), lambda h: h.handleCreate)


@pytest.mark.parametrize(
    "row",
    [
        _rule(value="cn=john smith, ou=USERS, o=org, c=us", role_account="engineers"),
        _rule(match="attributes", value="o=ORG, ou=users"),
    ],
)
def test_a_rule_duplicating_another_is_a_validation_error(rules_handler, row):
    stored = {"john": _rule(), "org_users": _rule(match="attributes", value="OU=Users,O=Org")}
    message = refused(rules_handler("new_rule", row, stored), lambda h: h.handleCreate)
    assert "already" in message


def test_an_exact_rule_and_an_attribute_rule_may_share_a_value(rules_handler):
    stored = {"john": _rule(value="CN=John Smith,O=Org")}
    handler = rules_handler("org_john", _rule(match="attributes", value="CN=John Smith,O=Org"), stored)
    handler.handleCreate(None)
    assert handler.saved == "create"


@pytest.mark.parametrize("edit", [_rule(), {"role_account": "engineers"}])
def test_editing_a_rule_without_changing_what_it_matches_saves(rules_handler, edit):
    handler = rules_handler("john", edit, {"john": _rule()})
    handler.handleEdit(None)
    assert handler.saved == "edit"


def test_an_edit_that_duplicates_another_rule_is_a_validation_error(rules_handler):
    stored = {"john": _rule(), "jane": _rule(value="CN=Jane Doe,OU=Users,O=Org,C=US")}
    handler = rules_handler("jane", {"value": "CN=John Smith,OU=Users,O=Org,C=US"}, stored)
    assert "john" in refused(handler, lambda h: h.handleEdit)


def test_no_role_accounts_yet_means_no_rule_can_be_saved(monkeypatch):
    handler_class = load_handler(monkeypatch, "mtls_bridge_user_rules_handler", "UserRulesHandler", {})
    assert "analysts" in refused(handler_class("john", _rule(), {}), lambda h: h.handleCreate)


def test_a_role_account_rules_use_cannot_be_deleted(monkeypatch):
    rules = {
        "john": _rule(),
        "org_users": _rule(match="attributes", value="O=Org"),
        "jane": _rule(role_account="engineers"),
    }
    handler = _role_accounts_handler(monkeypatch, rules)("analysts", {}, ROLE_ACCOUNTS)
    message = refused(handler, lambda h: h.handleRemove)
    assert "john" in message and "org_users" in message
    assert "jane" not in message


@pytest.mark.parametrize("rules", [None, {}, {"jane": _rule(role_account="engineers")}])
def test_a_role_account_no_rule_uses_can_be_deleted(monkeypatch, rules):
    handler = _role_accounts_handler(monkeypatch, rules)("analysts", {}, ROLE_ACCOUNTS)
    handler.handleRemove(None)
    assert handler.saved == "remove"
