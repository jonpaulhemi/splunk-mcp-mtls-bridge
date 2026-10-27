Responses in the shape splunkd's REST API returns them (`output_mode=json`), trimmed to the fields
the bridge reads. They were written from splunkd's documented format and UCC's REST handler
behaviour, not captured from a live server; the live-server task (#25) checks them against one.

`{PKI}` and `{SPLUNK_HOME}` are replaced by the tests with temporary paths.
