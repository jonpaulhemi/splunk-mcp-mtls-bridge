# Can UCC run a long-lived bridge with per-row secret tokens?

Research for issue #6 (part of #3). Researched 2026-10-27 against UCC `splunk-add-on-ucc-framework` 6.6.0 (latest, 2026-08-21), splunktaucclib 8.2.0, solnlib 8.2.0, splunk-sdk 3.0.1, splunk-appinspect 4.3.1, and the Splunk 9.1 to 10.0 `.conf.spec` files.

**Short answer: yes, with five design changes.** UCC can hold an encrypted token in each row of a configuration table, and splunkd can run the bridge as a single long-lived modular input. The five changes, explained below:

1. **Python 3.7.** Splunk 9.1 and 9.2 run app Python on 3.7, so "Python 3.9+" in `docs/DESIGN.md` is wrong for the 9.1+ scope.
2. **The default cert's key password.** splunkd's `server.pem` holds a private key protected by `sslPassword`. Splunk stores that password encrypted, and REST returns it encrypted too, so the daemon cannot recover it unless it is still the default.
3. **"Standard library only" applies to the daemon only.** UCC's generated REST handlers need splunktaucclib, solnlib and splunk-sdk bundled in `lib/`. Those must be pinned to versions that support Python 3.7.
4. **The daemon script is ours, not UCC's.** UCC's generated input template uses splunklib and sets `use_single_instance = False`. We ship our own stdlib script in `package/bin/`, which UCC does not overwrite.
5. **Pick up config changes by polling.** Editing a mapping row does not restart the input. The daemon should poll its config, which also keeps its session key active.

Confidence labels: **[verified]** means read in a primary source (spec file, official docs, or the library's source). **[inferred]** means reasoned from primary sources but not stated in them. **[unverified]** means a community or secondary source only, so it needs an integration test.

---

## 1. One long-lived daemon as a modular input

### `interval`

- **What the values mean in `inputs.conf.spec` (9.1) for scripted inputs [verified]:**
  - `"0"` "forces this scripted input to be run continuously. As soon as the script exits, the input restarts it."
  - `"-1"` "causes the scripted input to run once on start-up."
  - Default `60.0`.
  - With a cron schedule, "the input does not run the script on start-up". ([inputs.conf.spec 9.1][inputs-spec])
- **What the modular inputs docs add [verified]:**
  - "The interval parameter specifies how long a script waits before it restarts." It also helps "to ensure that a script restarts, even if a previous instance of the script exits unexpectedly."
  - "Entering an empty value for interval results in a script only being executed on start or endpoint reload (on edit)."
  - In single-instance mode, "Splunk Enterprise reads the interval setting from the scheme default stanza only", and a per-stanza `interval` is ignored. ([Modular inputs configuration][modinput-config])
- **Restart and backoff [inferred]:** Splunk documents no exponential backoff. The only throttle on a crash loop is `interval`, which acts as a fixed delay before the restart.
- **Recommendation [inferred]:**
  - Set a positive interval of about 30 to 60 s in the scheme default stanza, for example `[mtls_bridge]\ninterval = 30` in `default/inputs.conf`.
    - It restarts a crashed daemon.
    - It rate-limits a crash loop, for example a port that is already in use.
  - Avoid `0`, which risks a hot crash loop.
  - Avoid an empty value or `-1`, because then nothing restarts the daemon after a crash.
- **`python.version` [verified]:**
  - UCC's `inputs.conf` template writes `python.version = python3` into each input's default stanza. ([inputs_conf.template][ucc-inputs-tpl])
  - `server.conf.spec` 9.3 says "python3" or "python3.7" means "the system uses Python 3.7". 9.3 is the first release to add `python3.9`, and its server-wide default is `force_python3`, which is Python 3.9.
  - The 9.1 and 9.2 specs offer only `python3|force_python3|unspecified`. ([server.conf.spec 9.1][server-spec-91], [9.3][server-spec-93], [10.0][server-spec-100])
  - **Implication [inferred]:** on 9.1 and 9.2 the daemon runs on **Python 3.7**, so the code must avoid features from 3.8 and later:
    - walrus `:=`
    - `str.removeprefix`
    - `dict |`
    - `ssl` additions after 3.7
  - `ssl.SSLContext.minimum_version`, `ssl.TLSVersion`, `VERIFY_CRL_CHECK_LEAF` and `http.server.ThreadingHTTPServer` are all available in 3.7.

### Single instance

- **Scheme setting [verified]:** declare `<use_single_instance>true</use_single_instance>` in the scheme. Without it, splunkd runs "one script instance per input stanza". In single-instance mode, "all configuration stanzas have to be included" on stdin, and the script must handle an empty `<configuration/>`. ([Create modular inputs][modinput-create])
- **UCC's template [verified]:** the template hardcodes `scheme.use_single_instance = False` and is built on `splunklib.modularinput`. ([input.template][ucc-input-tpl])
- **Using our own script [verified]:** the UCC quickstart says that once a script is placed in `package/bin`, "`ucc-gen` uses updated modular inputs from `package/bin` instead of generating new ones". ([quickstart][ucc-quickstart]) So we ship our own stdlib script at `package/bin/mtls_bridge.py`. The script:
  - answers `--scheme` with hand-written XML that sets `use_single_instance=true`;
  - accepts `--validate-arguments`;
  - otherwise parses the stdin XML with `xml.etree`.
- **Guaranteeing one instance [inferred]:**
  1. Ship exactly one stanza, for example `[mtls_bridge://bridge]`, and don't expose a UCC Inputs page. That means leaving the daemon out of globalConfig `inputs.services` and shipping `README/inputs.conf.spec` and `default/inputs.conf` in `package/`.
  2. Use `use_single_instance=true`.
  3. Take an exclusive `fcntl.flock` on a lock file under `$SPLUNK_HOME/var/run/` or the `checkpoint_dir`.
  4. Bind without `SO_REUSEPORT`. A second process then gets `EADDRINUSE` and exits non-zero. `http.server` sets `SO_REUSEADDR`, which on Linux does not allow two live listeners.

### Shutdown

- **What the docs say [verified]:** "Disabling an item shuts down a script. Enabling starts it up." On reload, "Scripts that handle all of the enabled input stanzas are restarted." The docs don't say which signal is used. ([Create modular inputs][modinput-create])
- **solnlib's pattern [verified]:** Splunk's own solnlib registers teardown handlers for `SIGTERM` and `SIGINT`, plus `SIGBREAK` on Windows. ([solnlib utils.handle_teardown_signals][solnlib-utils]) It also ships an "orphan process monitor" that compares `os.getppid()` to the parent PID recorded at start. ([solnlib orphan_process_monitor][solnlib-orphan])
- **Community reports [unverified]:** "Splunk sends a SIGTERM to the script". A Splunk employee noted that child processes can be orphaned when splunkd stops. ([Splunk Community thread][community-sigterm])
- **Recommendation [inferred]:**
  - Handle `SIGTERM` and `SIGINT` by closing the listener and draining for a few seconds.
  - Also poll `os.getppid()` and exit when it changes, which covers being orphaned.
  - Treat EOF or `EPIPE` on stdout as a stop signal.
  - Never fork children.

---

## 2. Mapping table with an encrypted token per row

- **Tables are supported [verified].** In UCC, any Configuration tab that has a `table` key is a "config", meaning many rows. A tab without one is a "setting", meaning a single stanza. ([global_config.py][ucc-globalconfig])
  - Each config tab gets a `SingleModel` REST handler with actions `edit, list, remove, create`.
  - Every entity field's `encrypted` flag is passed straight to `RestField(encrypted=...)`. Nothing in the builder limits `encrypted` to the account tab. ([global_config_builder_schema.py][ucc-rest-builder], [single_model.py][ucc-single-model])
- **Table actions [verified]:** `edit`, `clone` and `delete`, plus Add. ([table docs][ucc-table])
  - "Replace token" is just an edit with a new value.
  - UCC 6.2.0 added "preserve masked value for encrypted field on edit mode", so editing other fields keeps the stored token. ([CHANGELOG][ucc-changelog])
- **How storage works [verified], from splunktaucclib `rest_handler/credentials.py` and `handler.py`:**
  - The realm is `__REST_CREDENTIAL__#<app>#configs/conf-<conf_name>`, and the username is the row (stanza) name.
  - The stored secret is `json.dumps({<field>: <clear value>, ...})` covering all encrypted fields of that row.
  - The conf file keeps the placeholder `******`. The legacy placeholder `********` is also recognised.
  - On update, a field sent back as the placeholder keeps the stored value.
  - Delete removes the credential: `rest_credentials.delete(name)` runs "if there are encrypted fields".
  - ([credentials.py][ucclib-creds], [handler.py][ucclib-handler])
- **Long values are chunked [verified].** solnlib's `CredentialManager` splits any secret longer than 255 characters ("Splunk can only encrypt string with length <=255"). Each chunk is stored as `<user>``splunk_cred_sep``<n>`, followed by an `END_MARK` entry. ([solnlib credentials.py][solnlib-creds]) MCP tokens plus the JSON wrapper will often be over 255 characters, so a stdlib reader of raw `storage/passwords` must reassemble the chunks. That is the main reason to prefer the REST-handler read path in section 3.
- **Fields for the mapping tab:**
  - `name`, which is the stanza: a slug, because UCC requires a name.
  - `issuer_dn` (text)
  - `identity` (text)
  - `splunk_account` (text, or a single-select if we want a user lookup)
  - `token_expiry` (UCC `date` component, or text with the `date` validator, which checks ISO 8601)
  - `token` (text with `encrypted: true`)
  - ([components][ucc-components], [validators][ucc-validators])
  - The table key is `issuer DN + identity`, but UCC rows are keyed by `name`, so uniqueness of (issuer, identity) must be enforced in a custom REST handler (`restHandlerModule`/`restHandlerClass`). ([custom REST handler][ucc-custom-rh])
- **UCC version.** Use **6.3.0 or later**, and 6.6.0 is fine.
  - Encrypted table fields have worked since 5.x.
  - The masked-value-on-edit fix arrived in 6.2.0.
  - The AppInspect check `check_for_ucc_framework_version` **warns** below 6.3.0 ("can generate custom Mako templates that are deprecated in Splunk Enterprise 10.4"). ([AppInspect 4.3.1 source](#appinspect-source))
  - Page-level `capabilities` (which writes `capability.<method>` to restmap.conf) appeared in 5.70.0. ([configurations docs][ucc-config], [restmap template][ucc-restmap-tpl])
- **Limits found:**
  - None on encrypted fields in tables.
  - The only encrypted-field rule in the validator is that a `file` field that is encrypted must also be required. ([global_config_validator.py][ucc-validator])

---

## 3. Reading config and secrets at startup with the session key

- **What splunkd passes [verified]:** splunkd writes XML to stdin with `server_host`, `server_uri`, `session_key` and `checkpoint_dir`. "The session key can be used in any REST session with the local instance of splunkd." ([Create modular inputs][modinput-create])
- **Recommended read path (stdlib only) [inferred from verified code]:**
  - Call the UCC REST handler with `GET {server_uri}/servicesNS/nobody/<app>/<app>_mappings?output_mode=json&count=0&--cred--=1` and header `Authorization: Splunk <session_key>`.
  - `AdminExternalHandler.handleList` reads `--cred--` and passes `decrypt=True`, which returns rows with the clear token already merged and de-chunked. ([admin_external.py][ucclib-admin], [handler.py][ucclib-handler])
  - Use the same approach for the settings stanza (listener address, CA bundle, CRL, limits).
  - This uses no admin credential and needs no chunk logic in our code.
- **Alternative:**
  - Call `GET /servicesNS/nobody/<app>/storage/passwords?output_mode=json&count=0&search=<realm>` and read `clear_password`.
  - Then reassemble the 255-character chunks and `json.loads` the result.
- **Capabilities [verified]:**
  - `list_storage_passwords` "Lets a user read from (GET) the /storage/passwords endpoint".
  - `edit_storage_passwords` covers GET and POST.
  - `admin_all_objects` bypasses ACLs. ([authorize.conf.spec 9.1][authorize-spec])
  - The admin who edits rows in the UI needs `edit_storage_passwords` plus write access to the app, which the built-in `admin` role has.
  - Set globalConfig `configuration.capabilities` so `post`/`delete` need `admin_all_objects` and `get` needs `list_storage_passwords`.
- **Which user owns the session key [unverified]:**
  - The Splunk docs do not name it.
  - Community reports point to the internal `splunk-system-user`, which has system-level capabilities, so `list_storage_passwords` is not a problem.
  - Add an integration-test assertion with `GET /services/authentication/current-context` to confirm it.
- **Session expiry [inferred]:**
  - `server.conf [general] sessionTimeout` defaults to 1 hour of inactivity. ([server.conf.spec 9.1][server-spec-91])
  - Editing a `configs/conf-*` row does not restart the modular input.
  - So the daemon should **poll the mappings every 30 to 60 s**. That picks up adds, edits and deletes without a restart and keeps the session active.
  - On HTTP 401, the daemon exits non-zero, and splunkd relaunches it with a fresh key after `interval`.
- **Lock down access to the secrets [inferred]:**
  - UCC's generated `metadata/default.meta` is `access = read : [ * ], write : [ admin, sc_admin ]` with `export = system`. ([meta_conf.py][ucc-meta])
  - Add `[passwords]` and `[<app>_mappings]` stanzas to `package/metadata/default.meta` that restrict read to `admin`.

---

## 4. Default listener cert from splunkd's `server.conf [sslConfig]`

- **Settings [verified]:** `[sslConfig] serverCert` is "The full path to the PEM ... server certificate file", default `$SPLUNK_HOME/etc/auth/server.pem`. Its password is `sslPassword` (default `password`). ([server.conf.spec 9.1][server-spec-91])
- **There is no `privKeyPath` in `server.conf` [verified].** `privKeyPath` exists only in `web.conf` for Splunk Web. ([web.conf.spec 9.1][web-spec-91]) splunkd's `server.pem` is a combined file holding the cert, the encrypted private key and usually the CA. Python's `ssl.SSLContext.load_cert_chain(certfile=server.pem, password=...)` accepts it.
- **The password problem [verified + inferred]:**
  - Splunk encrypts clear-text passwords in its config files at startup with `splunk.secret`, and "If you display the contents of the file using REST, the password prints in encrypted format." ([Deploy secure passwords][secure-passwords])
  - So the daemon cannot recover a non-default `sslPassword` with the standard library. It would need `splunk.secret` and AES, and a third-party "splunksecrets" decryption would not pass review.
  - **Design change:** the default-cert path should try the out-of-box key password `password`. If that fails, it should not start and should log a clear message. The setup page needs explicit override fields:
    - cert path
    - key path
    - key password (`encrypted: true`)
  - Also note that the default `server.pem` is signed by Splunk's per-install CA, so MCP clients will usually need that CA or an override cert anyway.
- **Finding the path at runtime [inferred]:**
  - Call `GET {server_uri}/services/properties/server/sslConfig/serverCert`, or `/services/configs/conf-server/sslConfig?output_mode=json`, with the session key.
  - Expand `$SPLUNK_HOME` from the environment, which splunkd sets for child processes.
  - The file is readable because the daemon runs as the splunkd OS user.

---

## 5. Install from file and AppInspect

- **Install from file [verified + inferred]:**
  - A Splunk app package is "a tarred and gzipped archive". After install, "Depending on the app or add-on contents, you might need to restart Splunk Enterprise." ([Where to get more apps][get-apps])
  - Installing through Splunk Web needs `install_apps` (enforced only when `limits.conf enable_install_apps` is set) and `edit_local_apps`. ([authorize.conf.spec 9.1][authorize-spec])
  - `ucc-gen package` produces a `.tar.gz` with the app id as its top-level folder, which is the format Install-from-file expects.
  - UCC's `app.conf` sets `is_configured = false`. It also adds `[triggers] reload.<conf> = simple` for its custom confs, so editing config doesn't need a restart. ([app_conf.template][ucc-app-tpl])
  - The new modular input scheme and the restmap handlers do need the restart that Splunk prompts for.
- **The real install risk is the bundled library versions [verified]:**
  - solnlib 7.0.0b3 and later require Python 3.9 or later.
  - solnlib 8.x also pulls in `grpcio` and OpenTelemetry, which are compiled binaries.
  - splunk-sdk 3.0.0 and later require Python 3.13 or later. ([PyPI metadata][pypi-solnlib], [PyPI splunk-sdk][pypi-sdk])
  - UCC installs `package/lib/requirements.txt` with the build machine's Python (UCC itself needs 3.9 or later). ([requirements docs][ucc-reqs]) An unpinned build would therefore bundle libraries that fail on 9.1 and 9.2's Python 3.7.
  - **Pin:** `splunktaucclib==8.2.0` (supports 3.7), `solnlib==7.0.0` (last release for 3.7, no grpcio), and `splunk-sdk==2.1.1`.
- **AppInspect is not required for on-prem [inferred].** The Splunk Enterprise install docs and specs set no vetting requirement for installs from file. Vetting is a Splunkbase and Splunk Cloud gate. Keep it in CI anyway, as the design says. Note that UCC 6.6.0 **removed `splunk-appinspect` from its dependencies**, so CI must `pip install splunk-appinspect` separately. ([CHANGELOG][ucc-changelog])
- <a id="appinspect-source"></a>**AppInspect checks relevant to us [verified, read from the splunk-appinspect 4.3.1 wheel source]:**
  - **No check fails for opening a listening TCP port.** The metadata tags `socketserver.TCPServer` as `WEB_SERVER` and `socket` as `NETWORK_CONNECTION`, but no check in `default_checks/` queries either tag.
  - `check_for_possible_threading`: a **warning** for direct calls to `threading.Thread.start`, `os.fork`, `os.kill`, `multiprocessing.Process.start` and similar. Calls inside a loop get a "questionable usage ... in loop" warning. `ThreadingHTTPServer` creates threads inside the standard library, so our code may only trip this if we start threads ourselves.
  - `check_for_python_udp_network_communications`: avoid UDP, for example syslog over UDP.
  - `check_for_supported_tls`:
    - **fails** when certificate verification is explicitly disabled toward a non-local literal URL;
    - **warns** when `http.client.HTTPSConnection` or `urlopen` gets a host or URL from a variable without `cert_file`/`cafile`;
    - skips literal localhost or 127.0.0.1 URLs.
    - Expect warnings for our upstream call, or pass the URL as a literal `https://127.0.0.1:8089`.
  - `check_for_insecure_http_calls_in_python`: warns on non-https literal URLs.
  - `check_for_outdated_ssl_tls`: flags `sslVersions` other than tls1.2 or tls1.3 in our confs.
  - `check_for_ucc_framework_version`: warns below 6.3.0.
  - `check_ucc_dependencies`: an informational warning that lists the bundled solnlib and splunktaucclib versions.
  - `check_for_root_privilege_escalation` and `check_for_program_frameworks`: fail on `su`/`sudo` or `cmd` module use. We have neither.
  - `check_for_bin_files`: files outside `bin/` must not be executable.
  - `check_that_local_does_not_exist`: an install-from-file package must not contain `local/` or `local.meta`.

---

## Changes this forces in `docs/DESIGN.md`

1. **Runtime:** change "Python 3.9+" to "Python 3.7+ on 9.1/9.2 (3.9 on 9.3+)". The daemon code must stay 3.7-compatible.
2. **"Standard library only" applies to the daemon only.** The UCC REST handlers bundle splunktaucclib, solnlib and splunk-sdk, pinned to versions that support 3.7.
3. **Listener cert:** the default to splunkd's `server.pem` works only while its key password is still the default. Add cert path, key path and an encrypted key-password field.
4. **Process:** ship our own `bin/mtls_bridge.py` with these properties:
   - a hand-written scheme with `use_single_instance=true`;
   - one fixed stanza with no Inputs page;
   - `interval = 30` in the scheme default stanza;
   - SIGTERM, orphan and lock-file handling.
5. **Config reload:** poll the mappings through `<app>_mappings?--cred--=1` every 30 to 60 s, and exit on 401. Don't rely on a restart to apply edits.
6. **Mapping uniqueness:** enforce uniqueness of (issuer DN, identity) in a custom REST handler, because UCC rows are keyed by `name`.

## Sources

[inputs-spec]: https://raw.githubusercontent.com/splunk/vscode-extension-splunk/master/spec_files/9.1/inputs.conf.spec
[server-spec-91]: https://raw.githubusercontent.com/splunk/vscode-extension-splunk/master/spec_files/9.1/server.conf.spec
[server-spec-93]: https://raw.githubusercontent.com/splunk/vscode-extension-splunk/master/spec_files/9.3/server.conf.spec
[server-spec-100]: https://raw.githubusercontent.com/splunk/vscode-extension-splunk/master/spec_files/10.0/server.conf.spec
[web-spec-91]: https://raw.githubusercontent.com/splunk/vscode-extension-splunk/master/spec_files/9.1/web.conf.spec
[authorize-spec]: https://raw.githubusercontent.com/splunk/vscode-extension-splunk/master/spec_files/9.1/authorize.conf.spec
[modinput-config]: https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.2/modular-inputs/modular-inputs-configuration
[modinput-create]: https://docs.splunk.com/Documentation/Splunk/9.1.2/AdvancedDev/ModInputsScripts
[secure-passwords]: https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.1/install-splunk-enterprise-securely/deploy-secure-passwords-across-multiple-servers
[get-apps]: https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.1/meet-splunk-apps/where-to-get-more-apps-and-add-ons
[community-sigterm]: https://community.splunk.com/t5/Deployment-Architecture/Scripted-input-without-a-shell/m-p/55668
[ucc-globalconfig]: https://github.com/splunk/addonfactory-ucc-generator/blob/main/splunk_add_on_ucc_framework/global_config.py
[ucc-rest-builder]: https://github.com/splunk/addonfactory-ucc-generator/blob/main/splunk_add_on_ucc_framework/commands/rest_builder/global_config_builder_schema.py
[ucc-single-model]: https://github.com/splunk/addonfactory-ucc-generator/blob/main/splunk_add_on_ucc_framework/commands/rest_builder/endpoint/single_model.py
[ucc-validator]: https://github.com/splunk/addonfactory-ucc-generator/blob/main/splunk_add_on_ucc_framework/global_config_validator.py
[ucc-input-tpl]: https://github.com/splunk/addonfactory-ucc-generator/blob/main/splunk_add_on_ucc_framework/templates/input.template
[ucc-inputs-tpl]: https://github.com/splunk/addonfactory-ucc-generator/blob/main/splunk_add_on_ucc_framework/templates/conf_files/inputs_conf.template
[ucc-restmap-tpl]: https://github.com/splunk/addonfactory-ucc-generator/blob/main/splunk_add_on_ucc_framework/templates/conf_files/restmap_conf.template
[ucc-app-tpl]: https://github.com/splunk/addonfactory-ucc-generator/blob/main/splunk_add_on_ucc_framework/templates/conf_files/app_conf.template
[ucc-meta]: https://github.com/splunk/addonfactory-ucc-generator/blob/main/splunk_add_on_ucc_framework/meta_conf.py
[ucc-config]: https://splunk.github.io/addonfactory-ucc-generator/configurations/
[ucc-table]: https://splunk.github.io/addonfactory-ucc-generator/table/
[ucc-components]: https://splunk.github.io/addonfactory-ucc-generator/entity/components/
[ucc-validators]: https://splunk.github.io/addonfactory-ucc-generator/entity/validators/
[ucc-custom-rh]: https://splunk.github.io/addonfactory-ucc-generator/advanced/custom_rest_handler/
[ucc-quickstart]: https://splunk.github.io/addonfactory-ucc-generator/quickstart/
[ucc-reqs]: https://splunk.github.io/addonfactory-ucc-generator/advanced/requirements/
[ucc-changelog]: https://splunk.github.io/addonfactory-ucc-generator/CHANGELOG/
[ucclib-creds]: https://github.com/splunk/addonfactory-ucc-library/blob/main/splunktaucclib/rest_handler/credentials.py
[ucclib-handler]: https://github.com/splunk/addonfactory-ucc-library/blob/main/splunktaucclib/rest_handler/handler.py
[ucclib-admin]: https://github.com/splunk/addonfactory-ucc-library/blob/main/splunktaucclib/rest_handler/admin_external.py
[solnlib-creds]: https://github.com/splunk/addonfactory-solutions-library-python/blob/main/solnlib/credentials.py
[solnlib-utils]: https://github.com/splunk/addonfactory-solutions-library-python/blob/main/solnlib/utils.py
[solnlib-orphan]: https://github.com/splunk/addonfactory-solutions-library-python/blob/main/solnlib/orphan_process_monitor.py
[pypi-solnlib]: https://pypi.org/pypi/solnlib/json
[pypi-sdk]: https://pypi.org/pypi/splunk-sdk/json

- Spec files: Splunk's own mirror in `splunk/vscode-extension-splunk/spec_files/<version>/`:
  - [inputs 9.1][inputs-spec]
  - [server 9.1][server-spec-91], [server 9.3][server-spec-93], [server 10.0][server-spec-100]
  - [web 9.1][web-spec-91]
  - [authorize 9.1][authorize-spec]
- Splunk docs:
  - [Modular inputs configuration][modinput-config]
  - [Create modular inputs (9.1.2)][modinput-create]
  - [Deploy secure passwords][secure-passwords]
  - [Where to get more apps and add-ons (9.1)][get-apps]
- UCC 6.6.0 source:
  - [global_config.py][ucc-globalconfig]
  - [REST builder][ucc-rest-builder]
  - [single_model.py][ucc-single-model]
  - [validator][ucc-validator]
  - [input.template][ucc-input-tpl]
  - [inputs_conf.template][ucc-inputs-tpl]
  - [restmap template][ucc-restmap-tpl]
  - [app_conf template][ucc-app-tpl]
  - [meta_conf.py][ucc-meta]
- UCC docs:
  - [configurations][ucc-config]
  - [table][ucc-table]
  - [components][ucc-components]
  - [validators][ucc-validators]
  - [custom REST handler][ucc-custom-rh]
  - [quickstart][ucc-quickstart]
  - [requirements][ucc-reqs]
  - [CHANGELOG][ucc-changelog]
- splunktaucclib 8.2.0: [credentials.py][ucclib-creds], [handler.py][ucclib-handler], [admin_external.py][ucclib-admin]
- solnlib: [credentials.py][solnlib-creds], [utils.py][solnlib-utils], [orphan_process_monitor.py][solnlib-orphan]
- PyPI release metadata: [solnlib][pypi-solnlib], [splunk-sdk][pypi-sdk], plus `splunktaucclib` and `splunk-add-on-ucc-framework` from the same JSON API.
- splunk-appinspect 4.3.1 wheel from PyPI, read locally:
  - `default_checks/check_python_files.py`
  - `check_security.py`
  - `check_addon_ucc_framework_config.py`
  - `check_splunk_10_0_deprecated_features.py`
  - `check_source_and_binaries.py`
  - `check_application_structure.py`
  - `python_modules_metadata/`
- Secondary, flagged [unverified]: [Splunk Community thread on SIGTERM and orphaned scripted inputs][community-sigterm]
