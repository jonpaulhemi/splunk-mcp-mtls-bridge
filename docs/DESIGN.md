# Splunk MCP mTLS Bridge: Design

Status: agreed 2026-10-26, revised 2026-10-27 after the wayfinder map (#3). The full spec is issue #2. Each decision's detail lives in its closed map ticket.

## Purpose

The official Splunk MCP Server app only accepts `Authorization: Bearer <encrypted MCP token>`. This app terminates mutual TLS from non-person entity (NPE) MCP clients, maps each cert to a local Splunk account's MCP token, and forwards the call to the MCP Server app.

```
MCP client (NPE cert) --mTLS--> bridge :8443 --HTTPS + Bearer--> splunkd 127.0.0.1:8089/services/mcp
```

## Scope (v1)

- Splunk Enterprise **10.4+**, on a standalone search head that also runs the MCP Server app.
- Search head clustering, Splunk Cloud, OCSP, CRL fetching over HTTP, token auto-rotation and a client-side helper are out of scope.

## Architecture

- **Process:** our own single-instance modular input script (`interval = 30`, a lock file, SIGTERM handling and orphan detection), started and restarted by splunkd.
- **Config:** the bridge reads its config and secrets with splunkd's session key and polls every 30–60s, so changes apply live. On a 401 it exits and splunkd relaunches it.
- **Runtime:** the daemon uses Splunk's bundled Python and the standard library only. The UCC REST handlers use pinned, bundled pure-Python libs.
- **Config UI:** UCC 6.3.0 or later. Tokens are encrypted in `storage/passwords`.

## Listener (inbound mTLS)

- **Bind address:** `0.0.0.0:8443` by default.
- **TLS:** TLS 1.2 minimum with TLS 1.3 available, a modern cipher list, and `CERT_REQUIRED` against a configurable CA bundle.
- **Server cert:** defaults to splunkd's `[sslConfig] serverCert`. Cert, key and key password can be overridden. The bridge warns at startup if it's serving Splunk's default self-signed cert.
- **CRL:** optional. Checking is leaf by default, with chain as an option. A replacement file is swapped in on the config poll, and one that won't parse or has expired is refused. The bridge warns 24 hours before `nextUpdate`, and expiry handling is a setting: `fail_closed` (the default) or `fail_open`.

## Identity and mapping

- **Mapping row:** issuer DN (RFC 4514; case, spacing and the order inside a multi-valued RDN are ignored, and a type without a short name such as emailAddress matches as text or `#hex`), identity type (URI, DNS, email, UPN, IP or CN), identity value, Splunk account, encrypted MCP token and token expiry date.
- **Matching:** a row matches if the cert carries that value in any field of that type. Matching two rows is rejected as ambiguous. The Mappings page refuses a row that duplicates another or can never match.
- **Case rules:** DNS, email and UPN are case-insensitive. URI and CN are exact. IPs are canonicalised.
- **Revocation without a CRL:** deleting a row revokes the cert at the bridge immediately.
- **Finding values:** the unmapped-cert audit event and the `bin/inspect-cert` script show the exact values to enter.

## Forwarding (upstream)

- The bridge POSTs to `https://127.0.0.1:8089/services/mcp`. `initialize`, `tools/list` and `tools/call` all travel as POST.
- **Answered locally:** `ping` (to protect the shared upstream rate limit) and `/health`. GET and DELETE get 405.
- **Request headers:** it strips the client `Authorization` header, injects the bearer token, and sends `Host`, `X-Forwarded-For`, `X-MCP-Request-Id` and `traceparent`.
- **Responses:** it streams them through and strips `WWW-Authenticate`. An upstream 401 becomes a 502 JSON-RPC "bridge credential invalid" error, and the mapping is flagged.
- **Sessions:** none. The upstream is stateless.
- **Limits:** a 128 KiB body cap, 10 concurrent requests per identity, and a 300 s upstream timeout.

## Tokens

- The admin pastes the token and enters its expiry date. The bridge never holds an admin credential.
- Warnings start 14 days ahead, in the operational log, on `/health` and in a daily audit event.
- Each new or changed token gets one check at config load. An upstream 401 flags it as invalid. Past the date, the bridge keeps forwarding and warns.

## Audit logging

- **Per call:** identity, issuer, mapped user, method, tool, arguments (truncated to about 4 KB), status, latency and request ID.
- **Handshake failures:** peer IP and port and OpenSSL's reason, collapsed to one event per IP per minute with a count.
- **Post-handshake rejections:** issuer, identity, serial, SHA-256 fingerprint and the reason.
- **Never logged:** results or tokens.
- **Destination:** a local file with sourcetype `mtls_bridge:audit`. The index defaults to `main` and is configurable, and index forwarding can be switched off.

## Clients

- README recipes cover Claude Code (`CLAUDE_CODE_CLIENT_CERT` and `CLAUDE_CODE_CLIENT_KEY`), the MCP Python and TypeScript SDKs, and `mcp-remote` behind ghostunnel.
- Custom connectors in claude.ai, Desktop and Cowork can't connect.
- **Cert profile:** the CA needs `basicConstraints CA:TRUE` and `keyUsage keyCertSign,cRLSign`. Client certs need EKU `clientAuth`. Keys must be RSA 2048+ or ECDSA P-256+.

## Testing and CI

- **Automated tests:** pytest, with a black-box integration test (real mTLS clients against the bridge in front of a fake upstream), plus tests for the config adapter using recorded REST responses.
- **AppInspect:** runs in CI.
- **Live-server test:** deferred to a late build task on J's test server.

## Packaging and install

- The release is a single `.tgz` from `ucc-gen package`. It installs via Apps > Manage Apps > Install app from file, followed by a restart.
- CI attaches the `.tgz` to each GitHub release.

## Repository

`jonpaulhemi/splunk-mcp-mtls-bridge`. All work goes through pull requests.
