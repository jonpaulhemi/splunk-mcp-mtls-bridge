"""REST handler for the Mappings page: refuses rows that can never match, or that match another row's certs."""

from splunktaucclib.rest_handler.admin_external import AdminExternalHandler
from splunktaucclib.rest_handler.error import RestError

from mtls_bridge.identity import mapping_row_problem


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
        problem = mapping_row_problem(self.callerArgs.id, row, self._rows() if rows is None else rows)
        if problem:
            raise RestError(400, problem)
