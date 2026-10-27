# mTLS Bridge for Splunk MCP (TA-mtls-bridge)

The official Splunk MCP Server app only accepts a bearer token. This app lets non-person clients (services and agents) use it with X.509 client certificates instead.

The bridge listens for mutual TLS and maps each client certificate to a local Splunk account. It then forwards the client's MCP calls to the MCP Server app with that account's encrypted MCP token. Clients never see a token. Splunk RBAC applies per mapped account, and every call and rejection is audited.

```
MCP client --mTLS--> bridge (:8443) --bearer token--> Splunk MCP Server app (splunkd :8089)
```

Design decisions are in [`docs/DESIGN.md`](docs/DESIGN.md).

## Requirements

- Splunk Enterprise 10.4 or later, on a standalone search head that also runs the Splunk MCP Server app.
- A PKI that issues the client certificates and, ideally, the bridge's listener certificate.

Search head clusters, Splunk Cloud and OCSP are out of scope.

## Install

1. Download `TA-mtls-bridge-<version>.tgz` from the [releases page](https://github.com/jonpaulhemi/splunk-mcp-mtls-bridge/releases).
2. In Splunk Web, go to **Apps > Manage Apps > Install app from file**, upload the `.tgz` and restart Splunk.
3. Open **mTLS Bridge for Splunk MCP > Configuration** and work through the tabs below.

The bridge starts within a minute of the Listener tab getting a client CA bundle. After that it picks up every change within 30 seconds, with no restart. Its operational log is `$SPLUNK_HOME/var/log/splunk/ta_mtls_bridge.log`.

## Configure

### Listener

| Field | What to enter |
| --- | --- |
| Bind address, Port | Where clients connect (default `0.0.0.0:8443`). Open the port in the host firewall. |
| Client CA bundle | A PEM file with every CA that issues client certificates. Only certs that chain to one of these are accepted. |
| Listener certificate, key, key password | The cert clients see. Leave these empty to reuse splunkd's server cert (`[sslConfig] serverCert`). |
| Client CRL file, CRL check depth, When the CRL expires | Revocation checking. See [CRL](#crl) below. |
| MCP Server URL, CA bundle, hostname check | Where the MCP Server app listens. The defaults suit an MCP Server app on the same search head. |

**Install a listener cert from your PKI.** Splunk's default server cert is self-signed, and every Splunk install shares its CA. If the listener serves it, the bridge logs a warning in its operational log at startup. Fix this either way:

- install a PKI-issued cert for splunkd; or
- set a separate cert, key and key password on this tab.

Clients must trust the CA that issued the listener cert.

### Mappings

Each row maps one client certificate to one Splunk account.

| Field | What to enter |
| --- | --- |
| Issuer DN | The DN of the CA that issued the client cert, in RFC 4514 form, for example `CN=Example MCP Client CA,O=Example Corp`. It is matched case-insensitively. |
| Identity type, Identity | Which certificate field identifies the client (`URI`, `DNS`, `EMAIL`, `UPN`, `IP` or `CN`) and its value. The row matches if any field of that type holds the value. DNS, email and UPN ignore case; URI and CN are exact. |
| Splunk account | The local account this client acts as. |
| MCP token | That account's encrypted MCP token from the MCP Server app. It is stored encrypted in Splunk's credential store. |
| Token expiry date | The token's expiry date, as `YYYY-MM-DD`. |

A cert that matches no row, or more than one row, is refused with HTTP 403. Deleting a row revokes that client at the next poll.

**Finding the issuer and identity values.** Either of these gives you values in the exact form the Mappings tab expects:

- Run the bundled script on the client's cert with any Python 3.9 or later:

  ```
  $ python3 $SPLUNK_HOME/etc/apps/TA-mtls-bridge/bin/inspect-cert client.pem
  Issuer: CN=Example MCP Client CA,O=Example Corp
  Serial: 777C79B60C6FC5AA13697D4C0D3FAFF78420088F
  SHA-256: 84d189bafdddf8abf6b724b9d11eaf928519c51a8d3da1283dd1792b8f52cfe4

  Identities (type: value):
  URI: spiffe://example.com/agents/report-bot
  CN: report-bot
  ```

- Or let the client connect once and search its rejection:

  ```
  sourcetype=mtls_bridge:audit event=rejection reason=unmapped
  ```

  The event carries `issuer` and an `identities` list in the same form.

**Tokens.** Create an encrypted MCP token for the mapped account in the Splunk MCP Server app (see Splunk's [MCP Server admin settings](https://help.splunk.com/en/splunk-enterprise/mcp-server-for-splunk-platform/connecting-to-mcp-server-and-admin-settings)). Paste it into the row and enter the expiry date you chose. Splunk doesn't let the bridge read a token's expiry, so it relies on the date you enter.

The bridge checks each new or changed token once with an MCP `initialize`. It also tracks what the MCP Server answers on real calls:

- A token the MCP Server rejects (HTTP 401) is flagged `invalid` on `/health` and in the operational log. Clients using it get HTTP 502 "bridge credential invalid".
- From 14 days before the expiry date, the bridge warns in the operational log, on `/health`, and in a daily `token_expiry` audit event.
- Past the expiry date it keeps forwarding and keeps warning.

### Audit

Every call, every rejection and every burst of failed handshakes is written as one JSON line to `$SPLUNK_HOME/var/log/TA-mtls-bridge/audit.log`, sourcetype `mtls_bridge:audit`. Each event's `event` field is `call`, `rejection`, `handshake_failure`, `token_expiry` or `crl_expired`. Tool arguments are cut at about 4 KB. Tool results and tokens are never logged.

| Field | What to enter |
| --- | --- |
| Send the audit log to an index | Turn off to stop Splunk indexing the file. The bridge keeps writing it locally. |
| Audit index | The index for audit events (default `main`). It must already exist. |

### CRL

CRL checking is optional. When it's off, deleting a mapping is how you revoke a client.

- **Client CRL file:** a CRL file (PEM or DER) that your PKI tooling keeps up to date. It must hold a current CRL from **every CA that issues client certs**, because OpenSSL refuses a cert whose issuer has no CRL. In chain mode it also needs one from every CA in their chains.
- **CRL check depth:** `leaf` (the default) checks only the client cert. `chain` checks every cert in its chain.
- **When the CRL expires:** `fail_closed` (the default) refuses every handshake until a fresh CRL arrives. `fail_open` stops checking revocation and adds a warning to every audit event.

The bridge re-reads the file every 30 seconds. It refuses a replacement that won't parse or has already expired, and keeps enforcing the previous one. It warns 24 hours before `nextUpdate`.

## Client certificate profile

The bridge relies on OpenSSL's defaults (TLS 1.2 or later).

- **CA certs:** `basicConstraints = critical, CA:TRUE` and `keyUsage = critical, keyCertSign, cRLSign`.
- **Client certs:** `extendedKeyUsage = clientAuth`, plus the identity you map, usually a URI SAN such as a SPIFFE ID.
- **Keys:** RSA 2048 bits or more, or ECDSA P-256 or stronger.

### Example: a test CA with openssl

Use your own PKI in production. For a test, this config and these commands make a CA and a client cert that fit the profile:

```ini
# pki.cnf
[req]
distinguished_name = dn
prompt = no
[dn]
O = Example Corp
CN = Example MCP Client CA
[ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[client]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = URI:spiffe://example.com/agents/report-bot
authorityKeyIdentifier = keyid
```

```sh
openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout ca.key -out ca.pem -days 1825 -config pki.cnf -extensions ca
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout client.key -out client.csr -subj "/O=Example Corp/CN=report-bot"
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out client.pem -days 365 -extfile pki.cnf -extensions client
```

For an RSA key, use `-newkey rsa:2048` in place of `-newkey ec -pkeyopt ec_paramgen_curve:P-256`. Put `ca.pem` in the client CA bundle. Then map issuer `CN=Example MCP Client CA,O=Example Corp`, identity type `URI` and identity `spiffe://example.com/agents/report-bot`.

## Client recipes

In each recipe:

- `bridge.example.com:8443` is the bridge;
- `client.pem` and `client.key` are the client's cert and key;
- `listener-ca.pem` is the CA that issued the bridge's listener cert.

The MCP endpoint is `https://bridge.example.com:8443/services/mcp`. Each recipe was tried against a running bridge in front of an MCP server, with the versions noted.

### Claude Code

Claude Code presents a client cert from environment variables:

```sh
export CLAUDE_CODE_CLIENT_CERT=/path/to/client.pem
export CLAUDE_CODE_CLIENT_KEY=/path/to/client.key
export CLAUDE_CODE_CLIENT_KEY_PASSPHRASE=...           # only if the key is encrypted
export NODE_EXTRA_CA_CERTS=/path/to/listener-ca.pem    # if the listener CA isn't publicly trusted
claude mcp add --transport http splunk https://bridge.example.com:8443/services/mcp
claude mcp list   # splunk: ... (HTTP) - ✓ Connected
```

(Tried with Claude Code 2.1.311.)

### MCP Python SDK

```python
import asyncio
import ssl

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def main():
    tls = ssl.create_default_context(cafile="listener-ca.pem")
    tls.load_cert_chain("client.pem", "client.key")
    async with httpx2.AsyncClient(verify=tls, timeout=httpx2.Timeout(30, read=300)) as http:
        async with streamable_http_client("https://bridge.example.com:8443/services/mcp", http_client=http) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                print([tool.name for tool in (await session.list_tools()).tools])


asyncio.run(main())
```

(Tried with `mcp` 2.3.0 on Python 3.13.)

### MCP TypeScript SDK

```js
import { readFileSync } from "node:fs";
import { Agent, fetch } from "undici";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const agent = new Agent({
  connect: {
    ca: readFileSync("listener-ca.pem"),
    cert: readFileSync("client.pem"),
    key: readFileSync("client.key"),
  },
});
const transport = new StreamableHTTPClientTransport(new URL("https://bridge.example.com:8443/services/mcp"), {
  fetch: (url, init) => fetch(url, { ...init, dispatcher: agent }),
});
const client = new Client({ name: "report-bot", version: "1.0.0" });
await client.connect(transport);
console.log((await client.listTools()).tools.map((tool) => tool.name));
await client.close();
```

(Tried with `@modelcontextprotocol/sdk` 1.32.2 and `undici` 8.12.3 on Node 22.)

### mcp-remote behind ghostunnel

For clients that only speak stdio or plain HTTP, run [ghostunnel](https://github.com/ghostunnel/ghostunnel) on the client host as a local forward proxy that adds the client cert:

```sh
ghostunnel client --listen localhost:8080 --target bridge.example.com:8443 \
  --cert client.pem --key client.key --cacert listener-ca.pem
```

Then point the client at the local port with [`mcp-remote`](https://www.npmjs.com/package/mcp-remote):

```json
{
  "mcpServers": {
    "splunk": {
      "command": "npx",
      "args": ["mcp-remote", "http://localhost:8080/services/mcp", "--allow-http", "--transport", "http-only"]
    }
  }
}
```

`--transport http-only` stops mcp-remote falling back to SSE, which the bridge doesn't serve. Anyone on the client host who can reach `localhost:8080` acts as this client, so keep ghostunnel bound to localhost. (Tried with ghostunnel 1.8.4 and mcp-remote 0.15.2.)

## Limits and caveats

- **Custom connectors in claude.ai, Claude Desktop and Cowork can't connect.** They can't present a client certificate.
- **Rate limit:** the MCP Server app allows 240 requests a minute per Splunk account. Every cert mapped to the same account shares that budget.
- **Request size and concurrency:** request bodies are capped at 128 KiB (HTTP 413 above that), with 10 concurrent requests per mapped identity (HTTP 429 above that).
- **Answered by the bridge:** `ping` is answered locally. A GET on `/health` from a mapped cert returns the bridge's status and version, its CRL state, and each mapping's account, expiry date and token status. It never includes tokens. Other GETs, and DELETE, get HTTP 405.
- **Out of scope:** search head clusters, Splunk Cloud and OCSP.

## Development

The daemon lives in `package/bin/mtls_bridge` and uses only the Python standard library. It must run on 3.9 and 3.13, the versions Splunk 10.4 runs. splunkd starts it through the `mtls_bridge_daemon` modular input in `package/bin/mtls_bridge_daemon.py`. UCC generates the setup pages from `globalConfig.json`.

To run the tests:

```sh
python3.9 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest
```

To build the installable app and run AppInspect, as CI does:

```sh
.venv/bin/pip install -r requirements-build.txt
PATH=.venv/bin:$PATH scripts/build_app.sh 0.1.0
```

This writes `output/TA-mtls-bridge-0.1.0.tgz`.

To release, push a tag such as `v0.2.0`. CI tests it, builds the app at version 0.2.0 and attaches `TA-mtls-bridge-0.2.0.tgz` to a GitHub release for the tag.

To run the bridge outside Splunk, write a JSON file holding the `Config` fields and run `python -m mtls_bridge bridge.json` from `package/bin`.
