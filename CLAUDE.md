# splunk-mcp-mtls-bridge

A Splunk app that terminates mTLS from MCP clients (NPE certs), maps each cert to a local Splunk account, and forwards calls to the official Splunk MCP Server app with that account's bearer token. Design decisions: `docs/DESIGN.md`.

## Agent skills

### Issue tracker

Issues and specs live in this repo's GitHub Issues, managed with the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `CONTEXT.md` and `docs/adr/` at the repo root, created lazily. See `docs/agents/domain.md`.
