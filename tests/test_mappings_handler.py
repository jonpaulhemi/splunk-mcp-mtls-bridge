"""The Mappings REST handler refuses bad rows with Splunk's validation error (HTTP 400), not a 500 (#38)."""

import pytest
from handler_stubs import load_handler
from handler_stubs import refused as _refused

ISSUER = "CN=Bridge Test CA,O=Bridge Test,C=US"


def _row(identity_value="spiffe://bridge.test/agent-a", account="svc_agent", issuer=ISSUER, identity_type="URI"):
    return {
        "issuer": issuer,
        "identity_type": identity_type,
        "identity_value": identity_value,
        "account": account,
        "token": "token",
        "token_expiry": "2027-01-31",
    }


@pytest.fixture
def handler_class(monkeypatch):
    return load_handler(monkeypatch, "mtls_bridge_mappings_handler", "MappingsHandler")


def test_duplicate_create_is_a_validation_error(handler_class):
    handler = handler_class("agent_b", _row(), {"agent_a": _row()})
    message = _refused(handler, lambda h: h.handleCreate)
    assert "agent_a" in message


def test_edit_that_collides_with_another_row_is_a_validation_error(handler_class):
    stored = {"agent_a": _row(), "agent_b": _row(identity_value="spiffe://bridge.test/agent-b")}
    handler = handler_class("agent_b", {"identity_value": "spiffe://bridge.test/agent-a"}, stored)
    assert "agent_a" in _refused(handler, lambda h: h.handleEdit)


@pytest.mark.parametrize(
    "row",
    [
        _row(issuer="not a DN"),
        _row(identity_type="IP", identity_value="999.1.1.1"),
        _row(identity_type="SERIAL"),
    ],
)
def test_malformed_row_is_a_validation_error(handler_class, row):
    _refused(handler_class("agent_b", row, {}), lambda h: h.handleCreate)


def test_editing_a_row_without_changing_its_identity_saves(handler_class):
    handler = handler_class("agent_a", {"account": "svc_other"}, {"agent_a": _row()})
    handler.handleEdit(None)
    assert handler.saved == "edit"


def test_different_identities_may_share_an_account(handler_class):
    handler = handler_class("agent_b", _row(identity_value="spiffe://bridge.test/agent-b"), {"agent_a": _row()})
    handler.handleCreate(None)
    assert handler.saved == "create"


@pytest.mark.parametrize("missing", ["account", "token", "token_expiry"])
def test_row_that_does_not_proxy_users_needs_an_account_and_token(handler_class, missing):
    row = {**_row(), missing: ""}
    assert "proxies users" in _refused(handler_class("agent_a", row, {}), lambda h: h.handleCreate)


def test_row_that_proxies_users_needs_no_account_or_token(handler_class):
    row = {**_row(), "account": "", "token": "", "token_expiry": "", "proxies_users": "1"}
    handler = handler_class("agent_a", row, {})
    handler.handleCreate(None)
    assert handler.saved == "create"


def test_turning_off_proxies_users_needs_an_account_and_token(handler_class):
    stored = {"agent_a": {**_row(), "account": "", "token": "", "token_expiry": "", "proxies_users": "1"}}
    handler = handler_class("agent_a", {"proxies_users": "0"}, stored)
    _refused(handler, lambda h: h.handleEdit)
