"""REST handler for the User rules page: refuses rules that can never match, duplicate another rule, or name a
role account that doesn't exist."""

import mtls_bridge_conf_rows as conf_rows
from splunk import admin
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler

from mtls_bridge.users import user_rule_problem


class UserRulesHandler(AdminExternalHandler):
    def handleCreate(self, confInfo):
        self._check(self.payload, self._rows())
        super().handleCreate(confInfo)

    def handleEdit(self, confInfo):
        if self.payload.get("disabled") is None:
            rows = self._rows()
            # An edit may send only the changed fields.
            self._check({**rows.get(self.callerArgs.id, {}), **self.payload}, rows)
        super().handleEdit(confInfo)

    def _rows(self):
        return {entity.name: entity.content for entity in self.handler.all(count=0)}

    def _check(self, row, rows):
        role_accounts = conf_rows.rows(self.getSessionKey(), conf_rows.ROLE_ACCOUNTS)
        problem = user_rule_problem(self.callerArgs.id, row, rows, role_accounts)
        if problem:
            # Only AdminManagerException subclasses reach the client as their HTTP status (400 here).
            raise admin.ArgValidationException(problem)
