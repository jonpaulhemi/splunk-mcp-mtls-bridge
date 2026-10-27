# Splunk MCP mTLS Bridge: Design

Status: agreed in the design session on 2026-10-26, pending J's final confirmation.

## Purpose

The official Splunk MCP Server app only accepts `Authorization: Bearer <encrypted MCP token>`. This Splunk app terminates mutual TLS from MCP clients, which are non-person entity (NPE) certs. It maps each cert to a local Splunk account's MCP token and forwards the call to the MCP Server app.

```
MCP client (NPE cert) --mTLS--> bridge :8443 --HTTPS + Bearer--> splunkd 127.0.0.1:8089/services/mcp
```

## Scope (v1)

- Self-managed Splunk Enterprise 9.1+, on a standalone search head that also runs the MCP Server app.
- Search head clustering, OCSP and token auto-rotation are out of scope.

## Architecture

- **Process:** a long-running Python daemon that splunkd launches as a modular input, so splunkd starts, restarts and stops it.
- **Runtime:** Splunk's bundled Python 3.9+, standard library only (`ssl`, `http.server` with threading, `http.client`). No third-party dependencies. Must pass AppInspect.
- **Config UI:** UCC-generated setup pages. Tokens are stored in `storage/passwords` and never in plain-text conf files.

## Listener (inbound mTLS)

- Bind address is `0.0.0.0:8443` by default and is configurable.
- Server cert and key default to splunkd's own server cert and key, and can be overridden.
- TLS 1.2 is the minimum, with a modern cipher list. `CERT_REQUIRED` is set.
- Client CAs come from a configurable CA bundle. Revocation is checked against a CRL file.
- A cert that fails CA validation or is revoked fails the TLS handshake.

## Identity and mapping

- The caller identity is the SAN value, falling back to the Subject CN.
- A mapping row is keyed on **issuer DN + identity**, so it survives renewal from the same CA. Fingerprints are not pinned.
- Each row maps to one local Splunk account and that account's encrypted MCP token.
- A valid cert with no mapping, or one whose token has expired, gets HTTP 403 with a JSON-RPC error body.

## Forwarding (upstream)

- Requests go to `https://127.0.0.1:8089/services/mcp`.
- The bridge removes any client `Authorization` header and injects the mapped bearer token.
- It adds `X-Forwarded-For` and `X-MTLS-Identity` headers.
- splunkd's cert is verified against a configurable CA. Hostname checking can be turned off for localhost.
- Streamable HTTP responses, including SSE, are streamed through without buffering.
- Each `Mcp-Session-Id` is tied to the identity that created it. If a different identity uses it, the request gets a 403.

## Limits

- The request body is capped at 1 MB by default.
- Each identity can have at most 10 concurrent requests by default.
- Both limits are configurable.

## Tokens

- An admin pastes each token into its mapping row. The bridge never holds an admin credential.
- When a token is close to expiry, the bridge logs a warning and reports it on `/health`.

## Health endpoint

- `/health` is on the mTLS listener and requires a mapped cert.
- It returns status and how close each token is to expiry. It never returns token values.

## Audit logging

- **Recorded fields:** identity, issuer, mapped user, MCP method, tool name, tool arguments (truncated to about 4 KB), result status and latency.
- Every rejection is recorded too.
- Results and tokens are never logged.
- Events go to a local log file with sourcetype `mtls_bridge:audit`.
- The index defaults to `main` and is configurable. Sending to an index can be switched off, and the local file is still written.

## Testing and CI

- **Unit tests:** pytest.
- **Integration test:** runs against a fake MCP upstream, using generated test certs (CA, server, mapped client, unmapped client, revoked client).
- **App checks:** AppInspect runs in CI.

## Packaging and install

- The release artifact is a single `.tgz` built with UCC (`ucc-gen build` then `ucc-gen package`).
- It installs through Splunk Web under Apps > Manage Apps > Install app from file. No CLI or file copying is needed.
- After install, Splunk asks for a restart, and you then configure everything in the app's setup pages.
- CI attaches the `.tgz` to each GitHub release.

## Repository

`jonpaulhemi/splunk-mcp-mtls-bridge`. All work goes through pull requests.
