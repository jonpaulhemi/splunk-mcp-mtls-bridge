# Which MCP clients can present a client certificate

Research for issue #7. Checked on 2026-10-27.

The question: the bridge requires each non-person-entity (NPE) MCP client to present an X.509 client certificate over MCP streamable HTTP. The certificate may chain to a private CA. Which common MCP clients can do this today, and how?

## Summary

| Client (version checked) | Client cert + key | Custom CA | How | Tested |
|---|---|---|---|---|
| Claude Code CLI 2.1.311 | Yes, built in | Yes | `CLAUDE_CODE_CLIENT_CERT`, `CLAUDE_CODE_CLIENT_KEY` (and optionally `CLAUDE_CODE_CLIENT_KEY_PASSPHRASE`), plus `NODE_EXTRA_CA_CERTS` | Yes |
| Claude Desktop / claude.ai custom connectors | **No** | No | Connectors connect from Anthropic's cloud and have no client-cert setting | Docs only |
| Claude Desktop local servers (`claude_desktop_config.json`) | Only through a stdio shim | Yes | `mcp-remote` pointed at a local mTLS forward proxy | Yes (with `mcp-remote`) |
| `mcp-remote` 0.15.2 (npm) | **No flag** | Yes | `NODE_EXTRA_CA_CERTS`. For the cert: a local forward proxy, or an unsupported `undici` preload | Yes |
| TypeScript SDK `@modelcontextprotocol/sdk` 1.32.2 (and `@modelcontextprotocol/client` 2.4.0) | Yes, in code | Yes | `StreamableHTTPClientTransport` option `fetch` (or `requestInit.dispatcher`) with an `undici` `Agent` | Yes (1.32.2) |
| Python SDK `mcp` 2.3.0 (httpx2) | Yes, in code | Yes | `streamable_http_client(url, http_client=httpx2.AsyncClient(verify=ssl_ctx))` | Yes |
| Python SDK `mcp` 1.30.0 (httpx) | Yes, in code | Yes | `streamable_http_client(url, http_client=httpx.AsyncClient(verify=ssl_ctx))` | Yes, via LangChain |
| LangChain `langchain-mcp-adapters` 0.3.2 | Yes, in code | Yes | `httpx_client_factory` in the `streamable_http` connection dict | Yes |
| OpenAI Agents SDK `openai-agents` 0.24.0 | Yes, in code | Yes | `MCPServerStreamableHttp(params={"httpx_client_factory": ...})` | Yes |

In short:

- Every SDK and framework can present a client certificate, but only through code: you build the TLS context or HTTP client yourself.
- **Claude Code** is the only client with zero-code support, through environment variables.
- **`mcp-remote`** cannot present a certificate.
- **Claude's custom connectors** cannot present a certificate at all.

For those last two, the gap is covered by a **local plain-HTTP-to-mTLS forward proxy** on loopback. Off-the-shelf tools do this (ghostunnel client mode, stunnel). It also took about 30 lines of Python standard library in the lab.

## Method

- **Sources:** I read the published package sources (npm tarballs and PyPI wheels at the versions in the table), the `mcp-remote` README shipped in its tarball, and Anthropic's docs: `code.claude.com/docs/en/network-config.md`, `env-vars.md`, `mcp.md`, and support article 11175166. I checked versions against `registry.npmjs.org` and `pypi.org` on the date above. GitHub API access to the upstream repos was not available in this session, so the source quoted is the published artifact, not `main`.
- **Lab:** I ran a local test with a private CA, a server cert for `localhost`, and a client cert (`CN=npe-agent-1`, SAN `URI:spiffe://test/npe-agent-1`, EKU `clientAuth`).
  - The test server was a minimal MCP streamable-HTTP server (`ssl.CERT_REQUIRED`) that echoes the peer CN from `tools/call`.
  - Each client in the "Tested" column completed `initialize`, `tools/list` or `tools/call`, and got back `cn=npe-agent-1`.
  - The server always returned JSON responses, not SSE. Streaming SSE through the forward proxy was **not** exercised.

## Per-client findings

### Claude Code (CLI 2.1.311)

**Supported with no code.** The network-config page documents:

```bash
export CLAUDE_CODE_CLIENT_CERT=/path/to/client-cert.pem
export CLAUDE_CODE_CLIENT_KEY=/path/to/client-key.pem
export CLAUDE_CODE_CLIENT_KEY_PASSPHRASE="..."   # optional
export NODE_EXTRA_CA_CERTS=/path/to/private-ca.pem
```

Source: `code.claude.com/docs/en/network-config.md`, sections "mTLS authentication" and "Custom CA certificates". `CLAUDE_CODE_CERT_STORE` (default `bundled,system`) also lets it trust a CA that is installed in the OS store.

The docs present this for "enterprise environments" and don't say whether it covers MCP HTTP transports. **The lab shows it does.**

- With only `NODE_EXTRA_CA_CERTS` set, `claude mcp list` against `claude mcp add --transport http lab https://localhost:8443/mcp` failed: `EPROTO: The TLS handshake failed`.
- With the two `CLAUDE_CODE_CLIENT_*` variables added, it reported `√ Connected`.
- The server logged `initialize`, `notifications/initialized` and `tools/list` from `ua=claude-code/2.1.311` with `cert_cn=npe-agent-1`.

Caveats:

- **One certificate per process.** The same pair is used for every TLS connection Claude Code makes, including the API. A user who needs different NPE identities for different servers needs separate processes or the forward-proxy pattern. A corporate mTLS gateway in front of the API that expects a different cert would conflict.
- **Rotation.** Claude Code re-reads the files when it applies settings, and re-reads them after a connection-level error (v2.1.232+). Rotation by replacing the files in place works without a restart. Source: same page.
- **Cloud sessions** (Claude Code on the web) ignore `CLAUDE_CODE_CLIENT_CERT`, `CLAUDE_CODE_CLIENT_KEY`, `CLAUDE_CODE_CLIENT_KEY_PASSPHRASE` and `NODE_EXTRA_CA_CERTS` when they come from a settings-file `env` block. Source: same page. Those sessions cannot be NPE clients of the bridge.
- **Desktop Code tab / Cowork** sessions whose provider connection the app manages read these variables only from managed settings and `~/.claude/settings.json`. Source: same page.

### Claude Desktop and claude.ai custom connectors

**Not supported.** Support article 11175166, "Getting started with custom connectors using remote MCP", says:

> When you add a custom connector, Claude connects to your remote MCP server from Anthropic's cloud infrastructure, rather than from your local device. This is true across every Claude client, including claude.ai, Claude Desktop, Cowork, and the mobile apps.

The only authentication settings it lists are OAuth ("Sign in now / when needed / No sign in", OAuth client choice) and fixed "Request headers". There is no client-certificate option.

Even with one, the bridge would have to be reachable from Anthropic's IP ranges. That conflicts with the NPE-on-a-private-network model.

The same article notes that local servers in `claude_desktop_config.json` "are a separate mechanism and do use your local network". That path works through a stdio shim; see `mcp-remote` below.

### `mcp-remote` 0.15.2 (npm)

**There is no client-certificate option.** I checked three places:

- **README:** it has no cert or key flags. It documents `NODE_EXTRA_CA_CERTS` only for trust, under "VPN Certs".
- **CLI parsing:** `dist/chunk-UZ6Y4QJH.js`, around lines 33694–33733, builds an `undici` dispatcher from `--connect-timeout`, `--ipv4`, `--body-timeout`, `--headers-timeout` and `--enable-proxy` only.
- **Search:** there is no `cert`/`key`/mTLS handling anywhere in `dist/`.

What works:

- **Custom CA:** `NODE_EXTRA_CA_CERTS=/path/ca.pem`, set in the `env` block of `claude_desktop_config.json` as its README shows.
- **Client cert, recommended:** point it at a loopback forward proxy, e.g. `npx mcp-remote http://127.0.0.1:18080/mcp`. It allows plain `http:` for `localhost` or `127.0.0.1` without `--allow-http` (source: `isLocalhost` check around line 33938). Tested: `initialize` and `tools/call` returned `cn=npe-agent-1` through the lab proxy.
- **Client cert, unsupported hack:** preload a module that installs a global `undici` dispatcher:

  ```bash
  NODE_OPTIONS="--import /path/preload-mtls.mjs"
  ```

  where `preload-mtls.mjs` runs `setGlobalDispatcher(new Agent({ connect: { cert, key, ca } }))`. Tested: it works, because `mcp-remote` uses `undici`'s `fetch` with the global dispatcher. It is fragile:
  - `mcp-remote` replaces the global dispatcher when any timeout, `--ipv4` or `--enable-proxy` flag is passed.
  - The preload must be able to resolve `undici`.
  - Nothing promises the behaviour across versions.

  Don't document this as the supported path.

### TypeScript SDK (`@modelcontextprotocol/sdk` 1.32.2, `@modelcontextprotocol/client` 2.4.0)

**Supported in code.** `StreamableHTTPClientTransportOptions` has:

- `requestInit?: RequestInit`
- `fetch?: FetchLike`, documented as "Custom fetch implementation used for all network requests".

Sources: `dist/esm/client/streamableHttp.d.ts` in 1.32.2, and `dist/index.d.cts` (around line 2310) in client 2.4.0.

Node's `fetch` has no TLS options of its own, so use an `undici` `Agent`. The following was tested on Node 22.22.0:

```js
import { readFileSync } from "node:fs";
import { Agent, fetch as undiciFetch } from "undici";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const dispatcher = new Agent({ connect: {
  cert: readFileSync("client.pem"), key: readFileSync("client.key"), ca: readFileSync("private-ca.pem") } });
const transport = new StreamableHTTPClientTransport(new URL("https://bridge:8443/mcp"), {
  fetch: (url, init) => undiciFetch(url, { ...init, dispatcher }),
});
```

`requestInit: { dispatcher }` with Node's global `fetch` also worked in the lab. It depends on the npm `undici` being compatible with the copy bundled in Node, so prefer passing `undici`'s own `fetch` as above.

### Python SDK (`mcp` 2.3.0, and 1.30.0 for v1)

**Supported in code.**

- In 2.3.0, `mcp.client.streamable_http.streamable_http_client(url, *, http_client: httpx2.AsyncClient | None = None, ...)` takes a pre-built client: "To configure headers, authentication, or other HTTP settings, create an httpx2.AsyncClient and pass it here." Source: `mcp/client/streamable_http.py`, line 713.
- 2.x depends on **`httpx2`** (`Requires-Dist: httpx2>=2.10.0`), not `httpx`.
- In `httpx2` 2.16.0, `cert=` is deprecated and `verify=<str>` cannot be combined with it. The supported form is `verify=<ssl.SSLContext>` with `load_cert_chain()`. Source: `httpx2/_config.py`, `create_ssl_context`.

Tested:

```python
ctx = ssl.create_default_context(cafile="private-ca.pem")
ctx.load_cert_chain("client.pem", "client.key")
async with httpx2.AsyncClient(verify=ctx, timeout=httpx2.Timeout(30, read=300)) as http:
    async with streamable_http_client("https://bridge:8443/mcp", http_client=http) as (r, w, *_):
        ...
```

1.x (latest 1.30.0) has the same `http_client=` parameter, typed as `httpx.AsyncClient` (`httpx` 0.28.1); use the same `verify=ctx` pattern.

`SSL_CERT_FILE` and `SSL_CERT_DIR` are honoured for trust by both `httpx` and `httpx2` (`httpcore2/_ssl.py`). They **replace** the default store rather than adding to it, and there is no environment variable for a client certificate.

**Python 3.13+ strict verification.** Since Python 3.13, `ssl.create_default_context()` adds `VERIFY_X509_STRICT` (see `Lib/ssl.py`). In the lab, a private CA without a `keyUsage` extension was rejected:

```
certificate verify failed: CA cert does not include key usage extension
```

Re-issuing the CA with `basicConstraints=critical,CA:TRUE` and `keyUsage=critical,keyCertSign,cRLSign` fixed it.

### LangChain MCP adapters (`langchain-mcp-adapters` 0.3.2)

**Supported in code.**

- `StreamableHttpConnection` has `httpx_client_factory: NotRequired[McpHttpClientFactory | None]`.
- The factory is called as `factory(headers=..., timeout=httpx.Timeout(...), auth=...)`, and its client is passed to `streamable_http_client(url, http_client=client)`.
- Source: `langchain_mcp_adapters/sessions.py`, lines 164–190 and 340–365.
- It pins `mcp<2.0.0`, so the factory must return an **`httpx`** (not `httpx2`) client.

Tested:

```python
def mtls_factory(headers=None, timeout=None, auth=None):
    ctx = ssl.create_default_context(cafile="private-ca.pem")
    ctx.load_cert_chain("client.pem", "client.key")
    return httpx.AsyncClient(verify=ctx, headers=headers, timeout=timeout, auth=auth)

MultiServerMCPClient({"splunk": {"transport": "streamable_http",
    "url": "https://bridge:8443/mcp", "httpx_client_factory": mtls_factory}})
```

### OpenAI Agents SDK (`openai-agents` 0.24.0)

**Supported in code.**

- `MCPServerStreamableHttpParams` has `httpx_client_factory: NotRequired[HttpClientFactory]`.
- The docstring says: "Return `httpx.AsyncClient` with MCP v1 or `httpx2.AsyncClient` with MCP v2". Under MCP v2 a wrapper raises `UserError` if the factory returns anything else.
- Source: `agents/mcp/server.py`, lines 306–355 and 2249–2270.
- With a fresh install it resolves `mcp` 2.3.0, so use `httpx2`.

Tested with `MCPServerStreamableHttp(params={"url": ..., "httpx_client_factory": mtls_factory})`, where `mtls_factory` returns `httpx2.AsyncClient(verify=ctx, headers=headers, timeout=timeout, auth=auth, follow_redirects=False)`. `list_tools()` and `call_tool()` returned `cn=npe-agent-1`.

### Not checked

Cursor, VS Code / Copilot, Windsurf and other IDE clients. Assume they need the forward-proxy pattern unless shown otherwise.

## Workarounds for clients without certificate support

1. **Local plain-HTTP-to-mTLS forward proxy (recommended).** It listens on `127.0.0.1:<port>`, presents the NPE cert to the bridge, and passes the streamable HTTP request and response through unchanged.
   - **ghostunnel client mode** does exactly this. From its README: `ghostunnel client --listen localhost:8080 --target <bridge>:8443 --keystore client-combined.pem --cacert ca.pem`. It accepts PKCS#12 or a combined PEM, and refuses non-loopback listeners without `--unsafe-listen`. Not run in this lab.
   - **stunnel** in `client = yes` mode is equivalent. Also not run.
   - A ~30-line stdlib Python version (`http.server` with `http.client` over an `ssl` context with `load_cert_chain`) worked in the lab with `mcp-remote`. Responses were relayed chunked, flushing each read. SSE was not tested.
2. **stdio shim.** `mcp-remote` (or any stdio-to-HTTP bridge) pointed at the forward proxy above. This is what Claude Desktop's local config needs.
3. **The `undici` preload for `mcp-remote`.** It works but is fragile; see above. Not recommended.

Notes on the forward-proxy pattern:

- **Any local process can use the identity.** Every process on the host that can reach the loopback port acts as that NPE. That's acceptable for a dedicated NPE host, but it must be stated. Bind to loopback only.
- **Key file:** keep the key at `0600`, owned by the service account.
- **Host header:** through ghostunnel or stunnel, the `Host` header the bridge sees is the local proxy address. The bridge should not reject requests on `Host` mismatch.

## Recommendation

**Don't ship a client-side helper in v1. Document the recipes, and point to ghostunnel as the generic answer.**

- The SDKs and frameworks an NPE integration is most likely to use already support client certs, and Claude Code supports them with no code. A helper would only serve `mcp-remote`, Claude Desktop's local config and IDE clients.
- ghostunnel and stunnel cover that case. They are maintained, handle rotation and logging, and need nothing from us.
- A stdlib forward proxy is small enough to add later as `bin/mtls-bridge-client.py` if users ask. It would reuse the bridge's own streaming code. Open a follow-up issue rather than expanding v1.
- Revisit if a target client turns out to have no HTTP option and no stdio shim.

**The README must document:**

1. The CA bundle a client needs to trust the bridge. By default that's splunkd's server cert chain (see DESIGN "Listener").
2. **Requirements for the private CA and client certs:**
   - The CA has `basicConstraints=critical,CA:TRUE` and `keyUsage=critical,keyCertSign,cRLSign`. Python 3.13+ clients reject a CA without them.
   - Client certs carry EKU `clientAuth`.
   - Client certs carry the SAN, or CN, the mapping uses.
   - The bridge's integration-test fixtures should be generated the same way.
3. A recipe per client:
   - **Claude Code:** the four environment variables. Include the one-cert-per-process caveat, and note that this doesn't work from Claude Code cloud sessions.
   - **Python SDK 2.x:** `httpx2` plus an `SSLContext`, as above.
   - **Python SDK 1.x / LangChain:** `httpx` factory.
   - **OpenAI Agents SDK:** `httpx_client_factory`, with the client type matching the installed MCP major version.
   - **TypeScript SDK:** `undici` `Agent` passed through `fetch`.
   - **`mcp-remote` / Claude Desktop local config:** ghostunnel client mode on loopback, then `mcp-remote http://127.0.0.1:<port>/mcp`, with `NODE_EXTRA_CA_CERTS` only if `mcp-remote` talks to the bridge directly over TLS.
4. **An explicit statement** that claude.ai, Claude Desktop and Cowork **custom connectors cannot connect**: they originate from Anthropic's cloud and cannot present a client certificate.
5. **The security notes** for the forward-proxy pattern: loopback only, key permissions, shared local identity.
