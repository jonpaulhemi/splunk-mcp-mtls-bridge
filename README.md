# splunk-mcp-mtls-bridge

A Splunk app that terminates mTLS from MCP clients and forwards their calls to the Splunk MCP Server app with a mapped account's bearer token. See `docs/DESIGN.md`.

## Development

The daemon lives in `package/bin/mtls_bridge` and uses only the Python 3.9 standard library.

```sh
python3.9 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest
```

To run the bridge outside Splunk, write a JSON file holding the `Config` fields and run `python -m mtls_bridge bridge.json` from `package/bin`.
