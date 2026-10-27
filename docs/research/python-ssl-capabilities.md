# What Python's `ssl` module can do on Splunk 9.1+

Research for issue #5. Researched 2026-10-27.

The bridge is a stdlib-only Python daemon that splunkd launches. It terminates mTLS, then maps issuer DN + identity to a Splunk account. This note covers what the bundled Python and OpenSSL let it do.

**How it was checked.** Claims are traced to CPython and OpenSSL source, the Python docs and Splunk docs (links in [Sources](#sources)). Behaviour was also run with a throwaway test PKI: a root CA, two issuing CAs (one of them revoked), clients with every SAN type, and CRLs (fresh, expired, missing). It ran on two interpreters:

- **Python 3.13.17 + OpenSSL 3.0.13** (Ubuntu system Python)
- **Python 3.9.25 + OpenSSL 3.5.4** (python-build-standalone via `uv`)

Both gave identical results. **Nothing was run against OpenSSL 1.0.2 or Python 3.7**, the combination Splunk 9.x actually ships. Building that combination locally was not possible in the sandbox. Every statement about 1.0.2 or 3.7 below comes from reading source and docs, and is marked as such.

## TL;DR

1. **The design's runtime assumption is wrong for 9.1 and 9.2.** Splunk 9.1 and 9.2 run Python **3.7** by default. Python 3.9 is the default only from 9.3. Every 9.x release links Python against **OpenSSL 1.0.2**, and OpenSSL 3 only arrives in 10.x. This is the biggest finding: it rules out TLS 1.3, `minimum_version`, UPN SANs and the audit hook on 9.1/9.2.
2. **CRL checks work** (`VERIFY_CRL_CHECK_LEAF` or `_CHAIN`). A missing or expired CRL **fails closed**: every client is rejected. A CRL can be reloaded without a restart.
3. **`getpeercert()` gives a parsed dict** with subject and issuer as RDN tuples, and SANs as `(type, value)` pairs. DNS, email, URI and IP are always there. otherName/UPN is decoded **only with OpenSSL ≥ 3.0**. On Splunk 9.x it reads `<unsupported>`.
4. **When a client cert fails verification, the server cannot see it through any public API.** `CERT_OPTIONAL` does not change this: a presented cert that fails still aborts the handshake. The server gets only `verify_code` and `verify_message` plus the peer address. A private hook (`SSLContext._msg_callback`, Python ≥ 3.8) can capture the raw cert. It is not available on Python 3.7.
5. **TLS 1.2 minimum and a cipher list are possible**, but on OpenSSL 1.0.2 `minimum_version` does not exist, and **setting it silently does nothing**. Use `OP_NO_*` options there. Splunk's `sslVersions` and `cipherSuite` do not apply to the bridge's socket.
6. **SSE streams without buffering** through `ThreadingHTTPServer` + `ssl`. This was verified: each event arrived at the client when it was written.

## 1. What each Splunk version bundles

| Splunk Enterprise | Default Python for apps | Other Python | OpenSSL linked to Python | Source |
|---|---|---|---|---|
| 9.1.x | 3.7 | none (no 2.7 in 9.x) | 1.0.2 (FIPS 140-2 module) | [S1], [S3] |
| 9.2.x | 3.7 | 3.9 opt-in per Lantern (see note) | 1.0.2 | [S1], [S3] |
| 9.3.x | 3.9 | 3.7 still selectable | 1.0.2 | [S1], [S2] |
| 9.4.x | 3.9 | 3.7 still selectable | 1.0.2 | [S1], [S3] |
| 10.0 / 10.1 | 3.9 (3.7 removed) | none | Platform moves to OpenSSL 3.0. Python 3.9 may still be built against OpenSSL 1 (see note) | [S4], [S3], [S5] |
| 10.2+ | 3.9 (linked to OpenSSL 3 only) | 3.13 opt-in (`python.required = 3.13` in app.conf) | 3.0 | [S5], [S6], [S7] |

Notes:

- The Splunk docs do not agree on 9.2. The Python 3 migration guide says `python3.9` is selectable "in 9.3.x" [S1]. The Lantern 10.0 upgrade article says `python.version=force_python3` can be used to test 3.9 "in 9.2 and higher" [S3]. Neither source lists 3.9 for 9.1.
- The 10.2 announcement says "the older combination of OpenSSL1 link to Python 3.9 runtime has been removed". So before 10.2 the bundled Python 3.9 could be linked against OpenSSL 1 [S5]. Exact OpenSSL patch levels (1.0.2zX) change with each maintenance release and were not pinned down.
- Splunk 9.x `sslVersions` only accepts `ssl3`, `tls1.0`, `tls1.1` and `tls1.2` [S8]. That matches OpenSSL 1.0.2, which has no TLS 1.3.

**Do not hard-code assumptions.** The daemon should log and branch on `sys.version_info`, `ssl.OPENSSL_VERSION_INFO`, `ssl.HAS_TLSv1_3`, `hasattr(ssl._ssl._SSLContext, "minimum_version")` and `hasattr(ssl.SSLContext, "_msg_callback")` at start-up.

## 2. CRL checking

**Setup.** Load the CA bundle and the CRL file into the same context with `load_verify_locations()`. A PEM file may hold several CRLs. Then set `verify_flags |= VERIFY_CRL_CHECK_LEAF` or `VERIFY_CRL_CHECK_CHAIN`. Both flags exist on OpenSSL 1.0.2 and Python 3.4+ [P1].

**Leaf vs chain**, measured:

| Case | Result |
|---|---|
| No CRL flag, revoked leaf | **accepted**. Loading a CRL alone does nothing. |
| `LEAF`, issuer's CRL loaded, good leaf | accepted |
| `LEAF`, issuer's CRL loaded, revoked leaf | rejected, `verify_code=23` "certificate revoked" (TLS 1.2 and 1.3) |
| `LEAF`, leaf issued by an **intermediate the root has revoked** | **accepted**. LEAF does not check intermediates. |
| `CHAIN`, all CRLs loaded, leaf under revoked intermediate | rejected, code 23 |
| `CHAIN`, all CRLs loaded, good leaf | accepted |
| `CHAIN`, root's CRL missing (only issuing CA's CRL loaded) | rejected, code 3 "unable to get certificate CRL" |

`CHAIN` therefore needs a current CRL from **every** CA in the path, including the root. The Python docs say the same for LEAF: "If no proper CRL has been loaded … validation will fail" [P1].

**Missing or expired CRL fails closed.** With `LEAF` and no CRL for the issuing CA, every client is rejected with code 3 "unable to get certificate CRL". With an expired CRL (`nextUpdate` in the past), every client is rejected with code 12 "CRL has expired". OpenSSL has no soft-fail or grace-period option. `verify_flags` takes a raw int, so `X509_V_FLAG_NO_CHECK_TIME` (0x200000) could be passed in, but it turns off *all* time checks, including cert expiry. That is not acceptable. So **a stale CRL is an outage for all clients**. The bridge must:

- track `nextUpdate` itself and warn on `/health` before the CRL expires
- reject a replacement CRL that is already expired

`/health` cannot be served from the mTLS listener while every client is being rejected.

**Reloading without a restart** works in two ways. Both were tested.

1. **Add to the live context.** Call `ctx.load_verify_locations(new_crl)` again. When several CRLs from the same issuer are in the store, OpenSSL uses the one with the latest `lastUpdate`. The source comment reads "If current CRL is equivalent use it if it is newer" in `get_crl_sk()`, in both 1.0.2 and 3.0 [O1]. Tests:
   - adding a newer CRL that revokes a cert caused immediate rejection on the next handshake
   - loading an older CRL after a newer one did not undo it
   - adding a fresh CRL next to an expired one made handshakes pass again

   The downsides: CRLs can never be removed (`cert_store_stats()` keeps growing), and the context is shared by threads that are handshaking.
2. **Build a new `SSLContext` and swap it in (recommended).** Wrap each accepted socket with whichever context is current, for example in `ThreadingHTTPServer.get_request()`. Live connections keep their old context, new connections use the new one, and nothing builds up. Poll the CRL file's mtime, or reload on a config change. The same swap also reloads the CA bundle and the server cert.

## 3. What `getpeercert()` exposes

`getpeercert()` returns a dict only after a successful handshake with `verify_mode != CERT_NONE`. Otherwise it returns `{}`, and with `CERT_NONE` the server never asks for a cert at all [P1], [C1]. Measured output for a client with every SAN type (Python 3.9.25 and 3.13.17 gave the same output):

```python
'subject': ((('countryName', 'US'),),
            (('organizationName', 'Test, Org "Quoted"'),),
            (('organizationalUnitName', 'Agents'), ('userId', 'u123')),   # multi-valued RDN
            (('commonName', 'agent1 été'),),                               # str, UTF-8 decoded
            (('1.2.3.4.5', 'custom-oid-attr'),)),                          # unknown OID -> dotted
'issuer':  ((('countryName', 'US'),), (('organizationName', 'Test Org'),),
            (('organizationalUnitName', 'PKI'),), (('commonName', 'Test Issuing CA 1'),)),
'serialNumber': '03E9', 'notBefore': 'Oct 26 00:49:33 2026 GMT', 'notAfter': '…',
'subjectAltName': (('DNS', 'agent1.example.com'),
                   ('email', 'agent1@example.com'),
                   ('URI', 'spiffe://example.com/ns/prod/sa/agent1'),
                   ('IP Address', '10.1.2.3'),
                   ('IP Address', '2001:DB8:0:0:0:0:0:1'),          # upper-case, not compressed
                   ('othername', 'UPN:svc-mcp@corp.example'),       # OpenSSL >= 3.0 only
                   ('Registered ID', '1.2.3.4'),
                   ('DirName', ((('commonName', 'dirname-cn'),),)))
```

**How each part is produced** (CPython `Modules/_ssl.c`, 3.7 and 3.9 [C1]):

- **DN attribute names** come from `OBJ_obj2txt(…, no_name=0)`. That gives OpenSSL's *long name* (`organizationalUnitName`, `userId`), or the dotted OID for attributes this OpenSSL build does not know. So an attribute's label depends on the OpenSSL version. For example, `organizationIdentifier` (2.5.4.97) is in OpenSSL 1.1.1's object table but not in 1.0.2's, where it would come out dotted (from reading the OpenSSL object tables, not tested). An issuer key built from these labels could change when Splunk moves from 9.x (1.0.2) to 10.x (3.0).
- **DN values** are unescaped `str`s, and the RDN structure is kept. Joining them naively (for example `", ".join`) is ambiguous: note the comma and the quotes in the test O value.
- **DNS, email, URI** are the raw IA5 strings, with NUL bytes handled.
- **IP** is formatted by CPython itself: dotted quad for IPv4, and for IPv6 eight upper-case hex groups with no `::` compression. The trailing `\n` that OpenSSL < 3 added is stripped "in all versions" [C1].
- **otherName, Registered ID, X400 and EDIParty** go through OpenSSL's `GENERAL_NAME_print()`, split at the first `:`. OpenSSL 1.0.2 and 1.1.1 print `othername:<unsupported>` for *every* otherName [O2]. OpenSSL 3.0 decodes UPN, SmtpUTF8Mailbox, XmppAddr, SRVName and NAIRealm [O2]. **So on all of Splunk 9.x a UPN-only cert reads as `('othername', '<unsupported>')`.** It cannot be told apart from any other otherName, so it cannot be used as an identity.

**Is manual DER parsing needed?** It is not needed for DNS, email, URI, IP, subject or issuer, because the dict is enough. It **is** needed for UPN on 9.x: take `getpeercert(binary_form=True)`, which returns DER and is available after a verified handshake, walk to the SAN extension (OID 2.5.29.17) and decode `[0] otherName` with type-id 1.3.6.1.4.1.311.20.2.3. That takes a small hand-written DER walker (roughly 80–120 lines). It is also the only way to get the version-independent OIDs for DN attributes. One more private but present helper: `ssl._ssl._test_decode_cert(pem_path)` turns any PEM file into the same dict as `getpeercert()`, without verifying it. It was used in §4.

**Normalising issuer + identity for exact matching**, recommended approach:

- **Issuer key.** Build a canonical string from the `issuer` tuple. Keep RDN order as given. Join multi-valued RDNs with `+` in sorted order. Escape `,+"\<>;=` and leading `#` or space as RFC 4514 does. Map the long names to short names or OIDs through a fixed table, so the key does not depend on the OpenSSL version. Store and compare that string, and show the same form in the UI. Alternatively, key on the issuing CA cert's SHA-256 fingerprint, which the admin picks from the CA bundle. That is exact, but it breaks when the CA is re-keyed, which the design wanted to avoid.
- **Identity.** Use a fixed SAN precedence, for example `URI` > `DNS` > `email` > `IP`. *Which* SAN types count, and in what order, is a design decision: a cert can carry several SAN values. Normalise per type:
  - DNS: lower-case, strip any trailing `.`
  - email: lower-case the domain part only, or the whole value if that is the policy
  - URI: as-is, or lower-case scheme and host
  - IP: `ipaddress.ip_address(v).compressed`, which turns `2001:DB8:0:0:0:0:0:1` into `2001:db8::1`

  Prefix the type (`dns:agent1.example.com`) so a DNS name and a CN with the same text cannot collide. Fall back to the CN only when there is no SAN of an accepted type.
- If UPN is needed on 9.x, it needs the DER parser. Otherwise mark UPN "10.x only".

## 4. Seeing the cert when client verification fails

**With the public API, the server cannot see it.** On a failed verification, `wrap_socket()` or `do_handshake()` raises `SSLCertVerificationError`. After that, `getpeercert()` and `getpeercert(True)` both raise `ValueError: handshake not done yet` [C1]. On Python 3.13, `get_unverified_chain()` returns `[]`. Measured on both interpreters, with TLS 1.2 and 1.3:

| Server mode / client | Server outcome |
|---|---|
| `CERT_REQUIRED`, untrusted CA | `SSLCertVerificationError`, `verify_code=20` "unable to get local issuer certificate". Cert not visible. |
| `CERT_REQUIRED`, revoked | code 23 "certificate revoked". Cert not visible. |
| `CERT_REQUIRED`, no cert | `SSLError` (no verify_code) |
| `CERT_OPTIONAL`, untrusted or revoked | **the same failure as `CERT_REQUIRED`** |
| `CERT_OPTIONAL`, no cert | handshake succeeds, `getpeercert()` is `None` |
| `CERT_NONE`, client has a cert | handshake succeeds, `getpeercert(True)` is `None` (no cert request is sent) |

What the exception **does** give: `verify_code`, `verify_message` and the peer IP and port. It does not give the subject, issuer or serial.

**`CERT_OPTIONAL` + manual verification does not work in the stdlib.** The Python docs say it plainly: in server mode "If the client chooses to send a certificate, it is verified. Any verification error immediately aborts the TLS handshake" [P1]. `ssl` has no verify callback, so you cannot accept an unverifiable cert and decide later. The only way to receive an unverified cert would be to trust everything, which `CERT_NONE` does not do (it sends no CertificateRequest), and then re-verify chain, expiry and CRL by hand in Python. That is a large, security-critical piece of hand-written crypto code, and the stdlib has no X.509 signature verification. **This is not a viable option.**

**Private workaround (tested): `SSLContext._msg_callback`.** This undocumented debugging hook exists since Python 3.8. It is missing from 3.7 [C1], [C2]. It receives every handshake message, including the client's `Certificate` message (type 11) in plaintext, for both TLS 1.2 and TLS 1.3, *before* verification runs. A test parsed the first DER cert out of that message and decoded it with `ssl._ssl._test_decode_cert`. It recovered the subject, issuer and SANs of the untrusted cert and of the revoked cert, on both interpreters. Caveats:

- It is a private API that could change. It costs a Python call for every TLS message.
- The message layout differs between TLS 1.2 and 1.3: TLS 1.3 adds a request context and per-cert extensions.
- It is not available on Python 3.7, which means Splunk 9.1 and 9.2 by default.
- The captured cert is **unverified**, so anything logged from it is a claim, not an identity.
- It was not tested against OpenSSL 1.0.2. The hook (`SSL_CTX_set_msg_callback`) exists there, and only TLS 1.2 applies.

## 5. TLS 1.2 minimum, ciphers, `sslVersions`, FIPS

- **`minimum_version`** needs OpenSSL ≥ 1.1.0g [P1]. With 1.0.2 the C attribute is not compiled in, and `ssl.py` only defines the property `if hasattr(_SSLContext, 'minimum_version')` [C2]. `SSLContext` instances have a `__dict__` (checked: assigning any unknown attribute works), so **`ctx.minimum_version = TLSVersion.TLSv1_2` raises no error and does nothing on Splunk 9.x.** Portable code:

  ```python
  if hasattr(ssl._ssl._SSLContext, "minimum_version"):
      ctx.minimum_version = ssl.TLSVersion.TLSv1_2
  else:
      ctx.options |= ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
  ```

  These options raise DeprecationWarnings on 3.10+, so only use them in the fallback branch. With Python 3.9, `PROTOCOL_TLS_SERVER` defaults to `MINIMUM_SUPPORTED` (measured), so the minimum must be set explicitly. In a test, an `openssl s_client -tls1_1` connection to a server with a 1.2 minimum was refused.
- **Ciphers.** `set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!MD5:!DSS")` left exactly the six ECDHE AES-GCM and ChaCha20 TLS 1.2 suites (measured). Unknown tokens are ignored. If nothing matches, it raises `SSLError('No cipher can be selected.')`. **TLS 1.3 suites cannot be changed with `set_ciphers`** [P1], and the stdlib has no `set_ciphersuites`. They stay at OpenSSL's defaults (AES-GCM and ChaCha20), which are modern anyway. OpenSSL 1.0.2 has no ChaCha20; the token is simply ignored there. Because the server cert defaults to splunkd's RSA cert, keep `ECDHE-RSA-*` in the list.
- **Splunk `sslVersions` / `cipherSuite`** (server.conf `[sslConfig]`, inputs.conf `[SSL]`) configure splunkd's own OpenSSL listeners. They are not passed to Python sockets. The bridge's settings are independent, unless the bridge reads these values over REST and mirrors them, which is optional.
- **FIPS.** FIPS mode is turned on with `SPLUNK_FIPS=1` in `splunk-launch.conf`. Splunk says the FIPS module "disables the use of some cryptographic algorithms in the instance of Python that Splunk software uses to run apps", for example MD5 and RC4. FIPS requires TLS ≥ 1.2 on both ends [S9], [S10]. For the bridge this means:
  - no `hashlib.md5` (use SHA-256 for any fingerprints)
  - ChaCha20 is not FIPS-approved, so expect only AES-GCM in FIPS mode
  - private keys may need PKCS#8 [S9]

  Under FIPS 140-3 (10.x, OpenSSL 3) Splunk requires Extended Master Secret. "OpenSSL version 1 and FIPS 140-2 modules do not support EMS" [S3]. The stdlib has no EMS switch: OpenSSL 3 negotiates it by default. FIPS mode was not tested here.

## 6. SSE through `ThreadingHTTPServer` + `ssl`

It works without buffering. Measured setup: `ThreadingHTTPServer`, each accepted socket wrapped in `get_request()` with `do_handshake_on_connect=False`, the handshake run in the handler's `setup()`, `protocol_version = "HTTP/1.1"`, and a manually chunked `text/event-stream` with an event every 0.5 s. The client received each event at +0.05 s, +0.51 s, +1.01 s and +1.51 s, on both interpreters.

- `StreamRequestHandler.wbufsize` is `0`, so `wfile` writes go straight to the SSL socket. Each `write()` becomes one TLS record and no flush is needed.
- **Do the handshake in the worker thread**, not by wrapping the listening socket. With a wrapped listener the handshake runs inside `accept()` on the single serving thread, so one slow or hostile client stalls all accepts. Set a socket timeout before `do_handshake()`, and catch its exceptions yourself: that is where the §4 audit record is written. If you don't, `handle_error` prints a traceback.
- Upstream, read the splunkd response with `HTTPResponse.read1()`, Python 3.5+. It returns whatever is available, while `read(n)` can wait to fill `n`. Relay each piece as one chunk.
- `ThreadingHTTPServer` exists since Python 3.7, so it is fine on every Splunk version.

## What this forces in the design

1. **Supported runtime.** Pick one:
   - (a) raise the floor to Splunk **9.3** (Python 3.9 default), or
   - (b) write for **Python 3.7** and accept the 9.1/9.2 limits: no `_msg_callback`, no `minimum_version`, no TLS 1.3, no UPN.

   In every case, assume OpenSSL 1.0.2 on all of 9.x. DESIGN.md's "bundled Python 3.9+ on 9.1+" needs correcting.
2. **Auditing failed handshakes.** "Every rejection is recorded" can only mean: timestamp, peer address, `verify_code` / `verify_message`, and the TLS reason. The rejected cert's subject, issuer and serial are not available through public APIs. Options:
   - accept that for v1 (recommended)
   - add the private `_msg_callback` capture as best-effort, feature-detected, marked "unverified", and off on 3.7
3. **Identity normalisation.**
   - Define the SAN type precedence. It is open.
   - Build a type-prefixed canonical identity and an RFC 4514-style issuer string with a fixed attribute-name→OID table, so the key survives the 9.x→10.x OpenSSL change.
   - Decide whether UPN is in scope. On 9.x it needs a hand-written DER parser over `getpeercert(True)`.
4. **CRL handling.**
   - Choose `CHAIN` if intermediates can be revoked. It needs fresh CRLs for every CA, including the root.
   - Treat CRL expiry as an outage: warn on `nextUpdate`, and refuse to load an expired replacement.
   - Reload by swapping the whole context.
5. **TLS config.** Feature-detect `minimum_version`. Document that `sslVersions` and `cipherSuite` don't apply to the bridge, and that TLS 1.3 suites cannot be configured.

## Sources

Python and CPython:

- [P1] Python 3.9 `ssl` docs, from the source of the published page: [Doc/library/ssl.rst@3.9](https://github.com/python/cpython/blob/3.9/Doc/library/ssl.rst). Covers `VERIFY_CRL_CHECK_LEAF` and `_CHAIN`, `CERT_OPTIONAL`, `minimum_version` (the "OpenSSL 1.1.0g or newer" note), `set_ciphers` (TLS 1.3 note), `getpeercert`, `SSLCertVerificationError`. Rendered: <https://docs.python.org/3.9/library/ssl.html>
- [C1] CPython `Modules/_ssl.c`: [3.9](https://github.com/python/cpython/blob/3.9/Modules/_ssl.c) and [3.7](https://github.com/python/cpython/blob/3.7/Modules/_ssl.c). See `_get_peer_alt_names`, `_asn1obj2py`, `getpeercert_impl`, `fill_and_set_sslerror`, `_msg_callback`, and the `SSL_CTRL_GET_MAX_PROTO_VERSION` guard.
- [C2] CPython `Lib/ssl.py`: [3.9](https://github.com/python/cpython/blob/3.9/Lib/ssl.py) and [3.7](https://github.com/python/cpython/blob/3.7/Lib/ssl.py). The `minimum_version` property is conditional, and `_msg_callback` is absent in 3.7.

OpenSSL:

- [O1] OpenSSL `crypto/x509/x509_vfy.c`, `get_crl_sk()` (prefers the newest CRL): [1.0.2](https://github.com/openssl/openssl/blob/OpenSSL_1_0_2-stable/crypto/x509/x509_vfy.c) and [3.0](https://github.com/openssl/openssl/blob/openssl-3.0/crypto/x509/x509_vfy.c)
- [O2] OpenSSL `GENERAL_NAME_print()`: [1.0.2 `crypto/x509v3/v3_alt.c`](https://github.com/openssl/openssl/blob/OpenSSL_1_0_2-stable/crypto/x509v3/v3_alt.c) (`othername:<unsupported>`) and [3.0 `crypto/x509/v3_san.c`](https://github.com/openssl/openssl/blob/openssl-3.0/crypto/x509/v3_san.c) (UPN etc. decoded)

Splunk:

- [S1] Splunk, *Changes to Splunk Enterprise with Python 3* (9.1 and 9.4 editions): <https://help.splunk.com/en/splunk-enterprise/administer/python-3-migration/9.1/overview/changes-to-splunk-enterprise-with-python-3>, <https://help.splunk.com/en/splunk-enterprise/administer/python-3-migration/9.4/overview/changes-to-splunk-enterprise-with-python-3>
- [S2] Splunk Community, *Upgrading your Splunk Deployment to Python 3.9*: <https://community.splunk.com/t5/Product-News-Announcements/Splunk-Platform-Upgrading-your-Splunk-Deployment-to-Python-3-9/ba-p/694436>
- [S3] Splunk Lantern, *Preparing to upgrade from 9.x to Splunk Enterprise and Cloud Platform 10.0*: <https://lantern.splunk.com/Manage_Performance_and_Health/Preparing_to_upgrade_from_9.x_to_Splunk_Enterprise_and_Cloud_Platform_10.0>
- [S4] Splunk, *Welcome to Splunk Enterprise 10.0*: <https://help.splunk.com/en/splunk-enterprise/release-notes-and-updates/release-notes/10.0/whats-new>
- [S5] Splunk Community, *Modernize your Splunk Apps: Introducing Python 3.13* (2025-10-29): <https://community.splunk.com/t5/Product-News-Announcements/Modernize-your-Splunk-Apps-Introducing-Python-3-13-in-Splunk/ba-p/754870>
- [S6] Splunk, *About upgrading to 10.2 READ THIS FIRST*: <https://help.splunk.com/en/splunk-enterprise/administer/install-and-upgrade/10.2/upgrade-or-migrate-splunk-enterprise/about-upgrading-to-10.2-read-this-first>
- [S7] Splunk, app.conf spec 10.4.4 (`python.required`): <https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.4-configuration-file-reference/app.conf>
- [S8] Splunk, inputs.conf spec 9.3.1 (`sslVersions`, `cipherSuite`): <https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.3/configuration-file-reference/9.3.1-configuration-file-reference/inputs.conf>
- [S9] Splunk, *Secure Splunk Enterprise with FIPS* (9.1): <https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.1/establish-and-maintain-compliance-with-fips-and-common-criteria-in-splunk-enterprise>
- [S10] Splunk, *Secure Splunk Enterprise with FIPS* (10.0): <https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.0/establish-and-maintain-compliance-with-fips-and-common-criteria-in-splunk-enterprise>
