# Splunk MCP Server app: sessions, streaming and tokens

Research for issue #4. It describes how the official **Splunk MCP Server app v2.1.0** (`Splunk_MCP_Server`, build `7c9228de-42757463`, per `default/app.conf`) handles endpoints, sessions, streaming, client identity, logging and tokens. It also lists what this means for the mTLS bridge.

**Sources.** The main source is the app's own v2.1.0 package, which we read but did not run. Citations look like `bin/mcp_server.py:44`, with paths relative to the app root. We quote only short excerpts as evidence. Splunk's public docs are cited where they add something. Where the code and the docs disagree, the code wins, because it is what runs.

## TL;DR: what changes for the bridge

1. **There is no `Mcp-Session-Id` and no SSE.** The app is stateless JSON request/response over `POST` only. Binding sessions to identities has nothing upstream to bind. Either drop it or make it purely bridge-side.
2. **`GET` and `DELETE` return 405** (`bin/mcp_message.py:220-226`). This is spec-compliant: no server-initiated stream, no client-side session termination.
3. **Every upstream response is one JSON document.** `handleStream` is a no-op (`bin/mcp_server.py:413-425`). Unbuffered SSE pass-through is harmless but never used.
4. **The token is opaque.** It is RSA-encrypted (PKCS#1 v1.5) ciphertext of a Splunk JWT. Without the app's private key you cannot read its username or expiry. The mint response returns **only** `{"token": ...}`, with no expiry and no token id. The bridge must get expiry from somewhere else. See "Where can the bridge get token expiry?" below.
5. **Upstream rate limiting treats all bridge traffic as one source IP (127.0.0.1).** A pre-check runs on every request against the per-IP unauthenticated bucket (60/min by default). Unauthenticated traffic, including every `ping`, can therefore return 429 for **all** bridge clients. Also, every identity mapped to the same Splunk account shares one authenticated bucket (240/min).
6. **The upstream payload limit is 128 KiB**, plus a 256 KiB limit on the whole request envelope. The bridge's default body cap of 1 MB should drop to 128 KiB.
7. **The 401 `WWW-Authenticate` header is built from the inbound `Host` header.** It points at an OAuth PRM URL that is useless to mTLS clients, and the upstream returns 500 if `Host` is missing. The bridge must always send `Host` and should rewrite or strip `WWW-Authenticate`.
8. **The app ignores `X-Forwarded-For` and `X-MTLS-Identity`.** For correlation it reads only `X-MCP-Request-Id` (≤128 printable chars) and `traceparent`, so the bridge should set those.

---

## 1. Endpoint, port and methods

| Path | Served by | Auth at splunkd | Methods the app accepts |
|---|---|---|---|
| `/services/mcp` | splunkd (mgmt port, default **8089**), persistent REST handler | `requireAuthentication = false`: the app does its own auth | **POST** only |
| `/en-US/splunkd/__raw/services/mcp` | Splunk Web proxy to the same handler | same | POST (the `web.conf` expose list) |
| `/services/.well-known/oauth-protected-resource` | splunkd persistent handler | none | GET |

Evidence:

- **Handler definition.** `default/restmap.conf:1-13` defines `[script:mcp_script]` with `match = /mcp`, `scripttype = persist`, `requireAuthentication = false`, `passSystemAuth = true`, `passHttpHeaders = true` and `passPayload = true`. There is no separate listener: it is a splunkd persistent REST handler (`MCPRestHandler(PersistentServerConnectionApplication)`, `bin/mcp_server.py:41`).
- **Splunk Web exposure.** `default/web.conf:1-3` has `[expose:mcp]` with `methods = POST`. This only governs the Splunk Web `__raw` proxy. The bridge should call splunkd on 8089 directly, as the design already says.
- **Method enforcement in code.** `bin/mcp_message.py:220-226` reads:
  ```python
  if http_method == "GET":   ... return 405, {"message": "Method not allowed"}
  if http_method != "POST":  ... return 405, {"message": f"HTTP method {http_method} not allowed"}
  ```
  `DELETE` therefore gets 405. No `Allow` header is set.
- **The app picks the path prefix by port.** It derives the path from the listening port: `/services/...` when the request came in on the mgmt port, otherwise `/en-US/splunkd/__raw/services/...` (`bin/util/splunk_util.py:124-147`).

### OAuth protected-resource metadata (PRM)

- The endpoint is `/.well-known/oauth-protected-resource`, under `/services/` on splunkd (`default/restmap.conf:241-254`, `default/web.conf:46-48`).
- It only returns a document when **Splunk Cloud SCS/SIS** config exists: `authentication.conf [oauth2_settings] issuer_uri`, `server.conf [scs] tenantHostname/tenant`, and `authentication.conf [authentication] resourceGroup`. Otherwise it returns `404 "PRM not configured"` (`bin/oauth_protected_resource_metadata_handler.py:131-138, 186-256`).
- On a self-managed Enterprise search head it will normally return 404.
- **What matters for the proxy is the 401 path.** Every 401 from `/services/mcp` carries a header built from the request's `Host` (`bin/mcp_server.py:468-477`):
  ```python
  host = next(v for k, v in req_headers if str(k).lower() == "host")
  base_url = f"https://{host}".rstrip("/")
  headers["WWW-Authenticate"] = f'Bearer resource_metadata="{base_url}{prm_path}", scope="openid"'
  ```
  - With `Host: 127.0.0.1:8089`, the header advertises `https://127.0.0.1:8089/services/.well-known/oauth-protected-resource`.
  - If the bridge forwards the client's `Host`, the port is not 8089. The header then points at `https://<bridge-host>/en-US/splunkd/__raw/services/.well-known/...`, which the bridge does not serve.
  - The `next()` call has no default. A request **without `Host`** that ends in 401 therefore raises inside `handle()` and becomes a **500 "Internal server error"** (`bin/mcp_server.py:304-319`).
  - mTLS clients can't act on an OAuth challenge anyway. The bridge should strip or rewrite `WWW-Authenticate`, and treat an upstream 401 as "the bridge's stored token is bad" (see §5).

## 2. Sessions (`Mcp-Session-Id`)

- **The app neither issues nor reads `Mcp-Session-Id`.** No file under `bin/` (excluding the vendored `lib/`, `splunklib/` and `rsa/`) references `mcp-session`, `session_id` or similar. The only "session" references are Splunk session keys.
- **The `initialize` response is fixed and stateless.** It returns `protocolVersion: "2025-11-25"`, `capabilities: {"tools": {}}` and `serverInfo`, whatever the client requested. No state is stored (`bin/mcp_message.py:610-639`).
- **Every request is authenticated on its own.** The bearer token is decrypted and checked against `services/authentication/current-context` on every call (`bin/auth.py:510-626`, called from `bin/mcp_server.py:199-203`).
- **Server-side state** is limited to:
  - in-memory admission counters per persistent process (`bin/request_admission.py`);
  - file-based tool-call rate-limit counters (`bin/rate_limit_manager.py:280-330`);
  - a KV Store token registry, where `last_used_at` is updated on each authenticated call (`bin/mcp_message.py:484-494`).

  None of this is tied to an MCP session.
- **`notifications/initialized` returns HTTP 202** with an empty payload (`bin/mcp_message.py:546-550`). Any other notification falls through to a JSON-RPC "Method not found" error with HTTP 200 (`bin/mcp_message.py:551-556`).
- **`ping` skips authentication entirely** and returns `{"message":"pong"}` (`bin/mcp_message.py:408-411`). It is also skipped in admission pre-validation (`bin/mcp_server.py:386-387`).
- **JSON-RPC batches (arrays) are not supported.** `rpc_req.get(...)` fails on a list, and the request becomes a 500 (`bin/mcp_server.py:148`). MCP 2025-06-18 and later dropped batching, so this is moot.

**Implication.** Bridge-side session binding has no upstream session to protect. Upstream, a session is just a sequence of independently authenticated POSTs, and each one is already authorised by the cert-to-account mapping. Two options:

- (a) Remove the binding requirement.
- (b) If clients need a session id, have the bridge mint its own `Mcp-Session-Id` on `initialize`, check it on later requests, and never forward it upstream.

## 3. SSE vs JSON, streaming, buffering

- **Responses are always JSON.** `_build_response` always sets `Content-Type: application/json` and returns `{"status", "headers", "payload"}` to splunkd as one value (`bin/mcp_server.py:452-482`).
- **Streaming is explicitly unsupported.** `handleStream` logs "Stream handling requested but not supported" and returns `None` (`bin/mcp_server.py:413-425`).
- **No long-lived streams.** There is no `GET` stream (405) and no SSE. The longest calls are tool executions:
  - splunkd REST calls time out at `timeout = 60.0` s (`default/mcp.conf:11`, range 1–300 per `README/mcp.conf.spec:7-10`);
  - Splunk AI Assistant tools use `saia_timeout = 200.0` s (`default/mcp.conf:16`).
- **Buffering.** The persistent-handler contract returns the whole response in one go, so splunkd receives it fully buffered. Whether splunkd *could* stream persistent-handler output doesn't matter here, because this app never produces incremental output.
- **Headers the app does not check:** `Accept`, `MCP-Protocol-Version`, `Content-Type` (the app parses the payload as JSON regardless), `Origin`. None of these appear in `bin/mcp_message.py:259-270`, which only reads `authorization` and `traceparent`, or in `extract_request_id`, which reads `x-mcp-request-id`.

**Implication.** The bridge's SSE path will never run against this upstream. Keep it simple and correct, but don't optimise it. The upstream read timeout must be at least ~200 s plus margin, or SAIA tool calls will be cut off.

## 4. Client identity headers and what the app logs

**Identity headers.**

- `X-Forwarded-For`, `X-Real-IP`, `Forwarded` and `X-MTLS-Identity` are never read. A grep of `bin/` for `forwarded` finds nothing outside vendored code.
- Source IP is taken only from splunkd's `connection.src_ip` (`bin/mcp_server.py:154-155, 284-288`). For the bridge it will always be `127.0.0.1`.
- The headers the app does read:
  - `Authorization` (`bin/mcp_message.py:267-268`);
  - `traceparent`, which is logged and **propagated** to downstream splunkd calls (`bin/mcp_message.py:269-272`, `bin/splunk_api.py:577-581`);
  - `X-MCP-Request-Id`, used as the log `request_id` if it is 1–128 printable characters, otherwise the app generates a UUID4 (`bin/mcp_message.py:160-185`, `bin/constants.py:104`, `bin/logging_config.py:87-90`);
  - `Host`, only on 401 (§1).

**Inbound auth schemes.** `Bearer ` and `Splunk ` prefixes are stripped (`bin/mcp_message.py:275-278`).

- `Basic` is decoded and **sent to `/services/auth/login`** to get a session key (`bin/mcp_message.py:281-317`).
- That session key then fails decryption, because only encrypted tokens, or SIS/CUI OAuth tokens, are accepted (`bin/auth.py:572-595`). The result is a 401.
- So the design's "strip inbound Authorization" also stops clients from making the upstream attempt password logins.

**Logs.** There are two JSON log files, both in `_internal` (`default/inputs.conf`, `default/props.conf`):

- **`mcp_server.log`** (sourcetype `mcp_server`). Every record carries the request context (`bin/logging_config.py:105-110, 177-235`):
  - `request_id`, `app_version`, `source_ip` (127.0.0.1 for us);
  - `traceparent`, `rpc_method`, `rpc_id`, `tool_name`;
  - `username` (plain), `user_id` (SHA-256/16), `auth_method` (`token` or `oauth`), `tenant_id`;
  - `status`, `execution_time_seconds`, `is_error`.

  Messages include "Request received, size=…" and "Response sent, status=…" (`bin/mcp_server.py:105-109, 323`), and "Token validated successfully for user: …" (`bin/mcp_message.py:443-446`).
- **`mcp_monitoring_dashboard.log`** (sourcetype `mcp_monitoring_dashboard`). Telemetry events for auth success/failure, tool call complete/error, rate-limit rejections and token lifecycle audit, with the same context fields (`bin/logging_config.py:112-170`).
- **Tool arguments and results are not logged** by the MCP layer. Only tool name, status code and timing are (`bin/mcp_message.py:805-827`).

**Implication.** The upstream audit already records *which Splunk user* called *which method and tool*, and when. It does **not** record the cert identity or the real client IP. The bridge's audit log is the only place that links cert, user and request. Set `X-MCP-Request-Id` to the bridge's own request id, and optionally `traceparent`, so a bridge audit event can be joined to `index=_internal sourcetype=mcp_server request_id=…`. `X-Forwarded-For` and `X-MTLS-Identity` do no harm, but nothing upstream consumes them.

## 5. The encrypted token: format, validation and expiry

### Format

- A token is created by `POST /services/mcp_token/tokens` (`bin/mcp_token_handler.py:358-654`). The handler creates a normal Splunk platform JWT through `services/authorization/tokens`, with `name=<user>` and `audience=mcp` (`:431-437, 515-525`). It then encrypts the JWT string with the app's RSA public key (`:572-577`).
- The encryption is raw RSA with **PKCS#1 v1.5** padding, chunked at `key_bytes - 11` bytes. Each block is base64-encoded and the blocks are joined with `.` (`bin/crypto.py:378-426`; self-description at `bin/crypto.py:492-545`: `"alg": "RSA1_5"`, "NOT a JWE"). Keys are 2048 or 4096 bit (`bin/mcp_token_handler.py:796`).
- The **private key** lives in `storage/passwords` under realm `Splunk_MCP_Server` (`bin/crypto.py:40-42, 260-312`). Its metadata includes `valid_until`.

### Validation (per request, `bin/auth.py:510-626`)

1. Empty token → 401 "No bearer token provided".
2. Webex CUI or SIS (Splunk Cloud OAuth) tokens take separate paths. These are not relevant on self-managed Enterprise.
3. Otherwise the token **must decrypt** with the current private key, or the result is 401 "Authentication failed: encrypted token required" (`:572-595`). If decryption fails, the app reloads the key at most once every 5 s (`bin/crypto.py:464-484`).
4. The **key's** effective expiry is checked with 60 s skew. Once it has passed, the result is 401 "encryption key expired" (`bin/auth.py:596-613`, `bin/constants.py:226`).
5. The decrypted JWT is validated by splunkd. The app calls `GET services/authentication/current-context` with it (`bin/auth.py:421-508`). splunkd therefore enforces the JWT's own `exp`, `nbf`, disabled and deleted state. A 401 there becomes "Invalid or expired token".
6. The decrypted JWT is decoded **without verification** to check `aud == "mcp"`, giving 403 if it doesn't match (`bin/mcp_message.py:454-483`). The `jti` is used to update `last_used_at` in the registry (`:484-494`).
7. The user needs the **`mcp_tool_execute`** capability, or the result is 403 (`bin/mcp_message.py:496-514`).

### Can a token holder read its expiry or username?

**No.** The outer token is RSA ciphertext, and the `exp` and `sub` claims are only in the inner JWT. Reading them needs the RSA private key from `storage/passwords`, which takes a privileged credential. The encrypted token is also not usable as a normal Splunk bearer token. Splunk's docs say: "Encrypted tokens cannot be used for direct Splunk API calls; they are exclusively for MCP authentication" ([Connecting to MCP Server and Admin settings](https://help.splunk.com/en/splunk-enterprise/mcp-server-for-splunk-platform/connecting-to-mcp-server-and-admin-settings)). The bridge therefore cannot call `current-context` with it.

The mint response doesn't help either. It is just `{"token": "<encrypted>"}`, plus a `message` when the expiry was capped to the key's expiry (`bin/mcp_token_handler.py:648-654`). It contains **no expiry and no token id**.

### Where can the bridge get token expiry?

| Source | What it gives | Who can read it | Can it be tied to *this* encrypted token? |
|---|---|---|---|
| `GET /services/authorization/tokens` (splunkd) | per-token `id` (=`jti`), claims `sub`, `aud`, `exp`, `nbf`, and `status` enabled/disabled ([Manage or delete authentication tokens](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.1/authenticate-into-the-splunk-platform-with-tokens/manage-or-delete-authentication-tokens)) | `list_tokens_own` or `edit_tokens_own` for one's own tokens; `list_tokens_all` or `edit_tokens_all` for everyone's ([Set up authentication with tokens, 8.2](https://docs.splunk.com/Documentation/Splunk/8.2.0/Security/Setupauthenticationwithtokens)) | Only by elimination: filter `sub=<mapped user>`, `aud=mcp`, `status=enabled`. Unambiguous only if the account has exactly one active MCP token. The app allows non-admins up to 3 (`bin/constants.py:228`). |
| KV collection `Splunk_MCP_Server/mcp_token_registry` | `token_id`, `owner_username`, `expires_at`, `disabled`, `created_by_username`, `created_at`, `last_used_at` (`default/collections.conf:26-35`, `bin/util/kvstore_utils.py:1-18`) | Roles `admin` and `sc_admin` only (`metadata/default.meta:14-16`) | Same elimination problem as above |
| `GET /services/mcp_token/tokens` (app API) | registry rows plus computed `status` (`active`, `expiring_soon` within 14 days, `expired`, `disabled`; `bin/util/token_utils.py:66-96`) | `mcp_edit_tokens_own` lists rows **created by** the caller, not owned by the caller (`bin/util/kvstore_utils.py:220-237`). `scope=all` needs `mcp_tool_admin`. | Same elimination problem |
| `GET /services/mcp_token/key-pair` | key `valid_until` | `mcp_tool_admin` (`bin/mcp_token_handler.py:63, 737-768`) | Global cap: every token dies when the key does |
| Mint time | the `expires_on` the minter asked for, capped at key expiry (`bin/mcp_token_handler.py:438-485`) | whoever mints | Exact, but only if it is recorded at mint time |
| Runtime | upstream 401 with "Invalid or expired token", "encryption key expired" or "encrypted token required" | the bridge, on every call | Exact, but reactive |

**An ordinary session key won't do the job.** The NPE account's own session key, with `list_tokens_own`, can list *that account's* tokens through `/services/authorization/tokens`. But the bridge does not hold the account's password or session key. It holds only the encrypted MCP token, which splunkd rejects as a bearer token.

The bridge's modular-input process does receive a splunkd session key at start-up. In our design that is a `splunk-system-user` key, so it is privileged. It can query `/services/authorization/tokens` (all users) and the registry. But using it means the bridge relies on a system-level credential to read token metadata.

**Recommended options, from simplest:**

- **(a)** At mapping time, the admin enters the token's expiry, and ideally its token id, both shown in Splunk Web's Tokens page. The bridge warns from that. Add a reactive check: treat an upstream 401 as "token invalid" and surface it on `/health`.
- **(b)** Use the modular-input session key to query `/services/authorization/tokens`, filtered by `sub` and `aud=mcp`. Report the **earliest** active expiry, and flag ambiguity when there is more than one.
- **(c)** A periodic authenticated probe per mapping. Use `initialize`, not `ping`, because `ping` skips auth. This detects revoked, disabled or expired tokens but gives no advance warning. It also costs authenticated quota and updates `last_used_at`.

Do **not** read the RSA private key from `storage/passwords` to decrypt tokens. It would tie the bridge to the app's internals and spread its most sensitive secret.

## 6. What a reverse proxy could break

| Area | Behaviour | Bridge action |
|---|---|---|
| `Host` | Needed for 401 responses. Missing `Host` turns a 401 into a 500 (§1). Its value leaks into `WWW-Authenticate`. | Always send `Host: 127.0.0.1:8089`. Strip or rewrite `WWW-Authenticate` on the way back. |
| `Origin` / CORS | Not checked. The app sends no CORS headers. | The bridge must do any `Origin` validation (MCP spec DNS-rebinding guidance) itself. |
| `Accept`, `MCP-Protocol-Version` | Not checked. `protocolVersion` is fixed at `2025-11-25` (`bin/mcp_message.py:629`). | Pass through. Don't depend on the upstream rejecting bad values. |
| Methods | POST only. GET and DELETE return 405 (§1). | Pass the 405s through, or answer GET and DELETE locally with 405. |
| Body size | Whole envelope ≤ **262144 B** gives 413 (`bin/mcp_server.py:44, 111-124`). JSON payload ≤ **131072 B** gives 413 (`bin/mcp_message.py:61, 239-245`). JSON depth ≤ 32 (`:62, 332-344`). | Lower the bridge's default body cap from 1 MB to **128 KiB**. |
| Timeouts | Tool-call splunkd timeout 60 s (`default/mcp.conf:11`), SAIA 200 s (`:16`). | Upstream read timeout of about 210–300 s. Client-facing idle timeout to match. |
| Rate limits: shared source IP | Phase-1 pre-check on **every** request against the `ip:<src_ip>` bucket at the unauthenticated limit, without recording (`bin/mcp_server.py:169-197`, `bin/request_admission.py:72-86`). Unauthenticated requests are recorded in that bucket (`bin/mcp_server.py:250-258`). That includes `ping`, bad tokens, and parse errors before auth. All bridge traffic arrives from 127.0.0.1. | ≥60 unauthenticated requests/min from *any* client give **429 for every client**. Answer `ping` locally, or rate-limit it per identity. Document raising `[rate_limits] tenant_unauthenticated`. |
| Rate limits: per user | The authenticated bucket is keyed by `user:<username>` (`bin/mcp_server.py:394-411`). Default 240/min (`default/mcp.conf:101`). | Every cert mapped to the same Splunk account shares 240/min. Prefer one account per identity, or document the sharing. |
| Rate limits: tools/call | `global = 600` per `window_size_minutes = 60`, across **all users**, plus per-tool limits (`default/mcp.conf:89-93`, `bin/rate_limit_manager.py:395-410`). | The bridge's per-identity limits are needed to stop one NPE starving the others. |
| Circuit breaker | 20 consecutive 5xx open the circuit for 30 s, giving 503 for **all** callers (`default/mcp.conf:109-113`, `bin/request_admission.py:105-118`). It is in-memory, per persistent process. | Map upstream 503 "Circuit breaker is open" to a clear error. Don't retry in a tight loop. |
| Fail-closed config | Any `[rate_limits]` value ≤0 except `admission_global`, or a missing system auth token, gives 503 (`bin/request_admission.py:51-52`, `bin/mcp_server.py:335-342`, `README/mcp.conf.spec:74`). | Note this in troubleshooting docs. |
| TLS | Ordinary splunkd mgmt-port TLS. The app does no client-cert or TLS checks of its own. | Verify splunkd's cert against its CA, as designed. |
| IP allowlists | None in the app. splunkd's own `server.conf [httpServer] acceptFrom` would apply if set. | localhost must be allowed. |
| Upstream 401 and 403 | 401: token missing, undecryptable, expired, key expired, or splunkd rejected it. 403: wrong `aud`, or missing `mcp_tool_execute` (§5). | Don't return 401 to the client: it can't fix it, and the challenge is OAuth. Map to 403 or 502 with a JSON-RPC error naming a "bridge token problem", and log or alert. |

## 7. mcp.conf settings relevant to the bridge

All of these are in `default/mcp.conf`, with types and ranges in `README/mcp.conf.spec`:

- **`[server] timeout`** (60 s) and **`saia_timeout`** (200 s). These set the upstream timeouts above.
- **`[server] ssl_verify`** (commented out, default true; `default/mcp.conf:28-39`, `README/mcp.conf.spec:27-29`).
  - This governs the *app's* outbound HTTPS, not the bridge.
  - No code in v2.1.0 `bin/` reads it. The app's splunkd calls hard-code `verify=False` with the comment "this is a localhost call" (`bin/splunk_api.py:589-595`).
  - It is irrelevant to the bridge.
- **`mcp_token_max_lifetime_seconds` and `mcp_token_default_lifetime_seconds`.** Both default to 15552000 s, or 180 days (`default/mcp.conf:47, 52`). Token expiry is also capped at the key's `valid_until`.
- **`token_key_reload_interval_seconds`** (300). After a key rotation, nodes pick up the new key within this interval.
- **`[rate_limits]`.** These are `window_size_minutes`, `global`, `admission_global`, `tenant_authenticated`, `tenant_unauthenticated`, `circuit_breaker_failure_threshold` and `circuit_breaker_cooldown_seconds` (`default/mcp.conf:82-113`). See §6.
- **No setting exists for allowed IPs, Origin or CORS.** The app has no such setting.
- `cui_*` settings: Webex CUI OAuth only. Not relevant.

Capabilities, defined in `default/authorize.conf:2-4` and granted to `admin` and `sc_admin` by default:

- **`mcp_tool_execute`**: needed by each mapped account.
- **`mcp_edit_tokens_own`**: needed to mint one's own token, together with Splunk's `edit_tokens_own`.
- **`mcp_tool_admin`**: needed to mint for others, together with `edit_tokens_all`, and to see `scope=all` and key status.

The public docs list "`edit_tokens_own` + `mcp_tool_admin`" for creating one's own token ([Connecting to MCP Server and Admin settings](https://help.splunk.com/en/splunk-enterprise/mcp-server-for-splunk-platform/connecting-to-mcp-server-and-admin-settings)). The v2.1.0 code gates `/mcp_token` on `mcp_tool_admin or mcp_edit_tokens_own` (`default/restmap.conf:39`), so the docs are out of date for v2.1.0.

## Open points (not verifiable from source alone)

- **Does `splunk-system-user` pass the in-handler `mcp_tool_admin` check?** This matters if the bridge would call `/services/mcp_token/key-pair` with its modular-input session key. It needs a live test.
- **Does splunkd strip or alter any request headers** before passing them to persistent handlers with `passHttpHeaders = true`? The app clearly receives `Authorization`, `Host`, `traceparent` and `X-MCP-Request-Id`. Others are unverified.
- **How many persistent processes does splunkd run** for the `splunk_mcp_server_7931` process group? That decides whether the in-memory admission and circuit-breaker state is per-process or effectively global.
