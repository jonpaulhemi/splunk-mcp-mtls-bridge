"""Stand-ins for the Splunk libraries the REST handlers import, which aren't installed here.

splunkd's admin framework only maps exceptions derived from splunk.admin.AdminManagerException to their
status; anything else becomes HTTP 500 (#38). The stand-ins reproduce that class hierarchy, the UCC base
handler's interface, and splunkd's REST API for reading other pages' rows.
"""

import importlib
import json
import sys
import types

import pytest


class AdminManagerException(Exception):
    pass


class ArgValidationException(AdminManagerException):
    pass


class ResourceNotFound(Exception):
    pass


class BaseHandler:
    """Stands in for splunktaucclib's AdminExternalHandler: records what reached it."""

    def __init__(self, name, payload, stored):
        self.callerArgs = types.SimpleNamespace(id=name)
        self.payload = payload
        self.handler = types.SimpleNamespace(
            all=lambda count: [types.SimpleNamespace(name=n, content=c) for n, c in stored.items()]
        )
        self.saved = None

    def getSessionKey(self):
        return "session-key"

    def handleCreate(self, confInfo):
        self.saved = "create"

    def handleEdit(self, confInfo):
        self.saved = "edit"

    def handleRemove(self, confInfo):
        self.saved = "remove"


def load_handler(monkeypatch, module_name, class_name, confs=None):
    """The handler class from ``module_name``, importing against the stand-ins. ``confs`` maps a conf
    file name to its rows ({name: content}), as splunkd's configs endpoint serves them; a conf not in it
    doesn't exist."""
    confs = confs or {}

    def simple_request(path, sessionKey=None, getargs=None, method="GET", raiseAllErrors=False):
        assert sessionKey == "session-key"
        conf = path.rsplit("/conf-", 1)[1]
        if conf not in confs:
            raise ResourceNotFound(path)
        entries = [{"name": name, "content": content} for name, content in confs[conf].items()]
        return types.SimpleNamespace(status=200), json.dumps({"entry": entries}).encode()

    admin = types.ModuleType("splunk.admin")
    admin.AdminManagerException = AdminManagerException
    admin.ArgValidationException = ArgValidationException
    rest = types.ModuleType("splunk.rest")
    rest.simpleRequest = simple_request
    splunk = types.ModuleType("splunk")
    splunk.admin, splunk.rest, splunk.ResourceNotFound = admin, rest, ResourceNotFound
    admin_external = types.ModuleType("splunktaucclib.rest_handler.admin_external")
    admin_external.AdminExternalHandler = BaseHandler
    for name, module in {
        "splunk": splunk,
        "splunk.admin": admin,
        "splunk.rest": rest,
        "splunktaucclib": types.ModuleType("splunktaucclib"),
        "splunktaucclib.rest_handler": types.ModuleType("splunktaucclib.rest_handler"),
        "splunktaucclib.rest_handler.admin_external": admin_external,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)
    for name in (module_name, "mtls_bridge_conf_rows"):
        monkeypatch.delitem(sys.modules, name, raising=False)
    return getattr(importlib.import_module(module_name), class_name)


def refused(handler, action):
    """The message of the validation error ``action(handler)`` raises; nothing must have been saved."""
    with pytest.raises(AdminManagerException) as refusal:
        action(handler)(None)
    assert isinstance(refusal.value, ArgValidationException)
    assert handler.saved is None
    return str(refusal.value)
