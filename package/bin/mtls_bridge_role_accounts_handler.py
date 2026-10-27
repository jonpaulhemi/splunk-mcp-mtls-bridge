"""REST handler for the Role accounts page: refuses to delete a role account that user rules still use."""

import mtls_bridge_conf_rows as conf_rows
from splunk import admin
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler

from mtls_bridge.users import rules_using


class RoleAccountsHandler(AdminExternalHandler):
    def handleRemove(self, confInfo):
        using = rules_using(self.callerArgs.id, conf_rows.rows(self.getSessionKey(), conf_rows.USER_RULES))
        if using:
            # Only AdminManagerException subclasses reach the client as their HTTP status (400 here).
            raise admin.ArgValidationException(
                f"user rules {', '.join(using)} send users to this role account; "
                "point them at another role account or delete them first"
            )
        super().handleRemove(confInfo)
