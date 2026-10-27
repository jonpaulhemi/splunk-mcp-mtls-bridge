"""The Mappings REST handler refuses bad rows with Splunk's validation error (HTTP 400), not a 500.

splunkd's admin framework only maps exceptions derived from splunk.admin.AdminManagerException to their
status; anything else becomes HTTP 500 (#38). Splunk's libraries aren't installed here, so stand-ins
reproduce that class hierarchy and the UCC base handler's interface.
"""

import importlib
import sys
import types

import pytest

ISSUER = "CN=Bridge Test CA,O=Bridge Test,C=US"


def _row(identity_value="spiffe://bridge.test/agent-a", account="svc_agent", issuer=ISSUER, identity_type="URI"):
    return {"issuer": issuer, "identity_type": identity_type, "identity_value": identity_value, "account": account}


class _AdminManagerException(Exception):
    pass


class _ArgValidationException(_AdminManagerException):
    pass


class _BaseHandler:
    """Stands in for splunktaucclib's AdminExternalHandler: records what reached it."""

    def __init__(self, name, payload, stored):
        self.callerArgs = types.SimpleNamespace(id=name)
        self.payload = payload
        self.handler = types.SimpleNamespace(
            all=lambda count: [types.SimpleNamespace(name=n, content=c) for n, c in stored.items()]
        )
        self.saved = None

    def handleCreate(self, confInfo):
        self.saved = "create"

    def handleEdit(self, confInfo):
        self.saved = "edit"


@pytest.fixture
def handler_class(monkeypatch):
    admin = types.ModuleType("splunk.admin")
    admin.AdminManagerException = _AdminManagerException
    admin.ArgValidationException = _ArgValidationException
    splunk = types.ModuleType("splunk")
    splunk.admin = admin
    admin_external = types.ModuleType("splunktaucclib.rest_handler.admin_external")
    admin_external.AdminExternalHandler = _BaseHandler
    for name, module in {
        "splunk": splunk,
        "splunk.admin": admin,
        "splunktaucclib": types.ModuleType("splunktaucclib"),
        "splunktaucclib.rest_handler": types.ModuleType("splunktaucclib.rest_handler"),
        "splunktaucclib.rest_handler.admin_external": admin_external,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.delitem(sys.modules, "mtls_bridge_mappings_handler", raising=False)
    return importlib.import_module("mtls_bridge_mappings_handler").MappingsHandler


def _refused(handler, action):
    with pytest.raises(_AdminManagerException) as refusal:
        action(handler)(None)
    assert handler.saved is None
    return str(refusal.value)


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
