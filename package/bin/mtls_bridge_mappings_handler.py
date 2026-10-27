"""REST handler for the Mappings page: refuses rows that can never match, that match another row's certs, or
that lack the account and token a client not proxying users runs as."""

from splunk import admin
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler

from mtls_bridge.identity import mapping_row_problem

# How splunkd and UCC spell a checked checkbox.
_TRUTHY = {"1", "true", "yes", "t", "y"}
_CREDENTIAL_FIELDS = {"account": "Splunk account", "token": "MCP token", "token_expiry": "token expiry date"}


class MappingsHandler(AdminExternalHandler):
    def handleCreate(self, confInfo):
        self._check(self.payload)
        super().handleCreate(confInfo)

    def handleEdit(self, confInfo):
        # Enabling or disabling a row changes no identity. Disabled rows still count as taken.
        if self.payload.get("disabled") is None:
            rows = self._rows()
            # An edit may send only the changed fields.
            self._check({**rows.get(self.callerArgs.id, {}), **self.payload}, rows)
        super().handleEdit(confInfo)

    def _rows(self):
        return {entity.name: entity.content for entity in self.handler.all(count=0)}

    def _check(self, row, rows=None):
        problem = _credential_problem(row) or mapping_row_problem(
            self.callerArgs.id, row, self._rows() if rows is None else rows
        )
        if problem:
            # splunkd turns only AdminManagerException subclasses into their HTTP status; UCC's RestError
            # isn't one, so it came back as a 500.
            raise admin.ArgValidationException(problem)


def _credential_problem(row):
    """The page only asks for these when the box is unchecked, so a request that skips the page is checked here."""
    if str(row.get("proxies_users", "")).lower() in _TRUTHY:
        return None
    missing = [label for field, label in _CREDENTIAL_FIELDS.items() if not row.get(field)]
    if missing:
        return f"enter the {', '.join(missing)}; only a mapping that proxies users can leave them empty"
    return None
