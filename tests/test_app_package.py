"""The packaged app's own conf files: Splunk ingests the audit file the daemon writes."""

import configparser
import datetime
import json
import re
import shutil
import sys

from mtls_bridge import __version__, splunk_config
from mtls_bridge.audit import AuditLog

from harness import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import check_modinput_spec  # noqa: E402

DEFAULT = ROOT / "package" / "default"


def _conf(name):
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    parser.read(DEFAULT / name)
    return parser


def test_audit_file_is_monitored_with_the_audit_sourcetype():
    stanza = _conf("inputs.conf")["monitor://" + splunk_config.AUDIT_LOG]
    assert stanza["sourcetype"] == "mtls_bridge:audit"
    assert stanza["index"] == "main"
    assert stanza["disabled"] == "0"


def test_audit_sourcetype_parses_one_json_event_per_line(tmp_path):
    stanza = _conf("props.conf")["mtls_bridge:audit"]
    assert stanza["KV_MODE"] == "json"
    assert stanza["SHOULD_LINEMERGE"] == "false"
    # Splunk reads _time from the "time" field the bridge writes first on each line.
    audit = AuditLog(str(tmp_path / "audit.log"))
    audit.write("call", status=200)
    audit.close()
    line = (tmp_path / "audit.log").read_text()
    match = re.match(stanza["TIME_PREFIX"], line)
    assert match
    timestamp = line[match.end() :].split('"')[0]
    assert len(timestamp) <= int(stanza["MAX_TIMESTAMP_LOOKAHEAD"])
    assert datetime.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")


def test_daemon_reports_the_app_version():
    manifest = json.loads((ROOT / "package" / "app.manifest").read_text())
    global_config = json.loads((ROOT / "globalConfig.json").read_text())
    assert __version__ == manifest["info"]["id"]["version"] == global_config["meta"]["version"]


def test_daemon_input_spec_lets_splunk_discover_and_restart_the_daemon():
    assert check_modinput_spec.problems(ROOT / "package") == []


def test_spec_without_a_parameter_is_caught(tmp_path):
    # v0.1.0 shipped this, and splunkd never discovered the daemon (#37).
    app = tmp_path / "app"
    shutil.copytree(ROOT / "package" / "default", app / "default")
    (app / "README").mkdir()
    (app / "README" / "inputs.conf.spec").write_text(
        "[mtls_bridge_daemon://<name>]\n* Runs the mTLS bridge. The app ships one stanza; don't add more.\n"
    )
    assert check_modinput_spec.problems(app) == [
        "README/inputs.conf.spec declares no parameter for mtls_bridge_daemon://<name>; splunkd won't discover it",
        "README/inputs.conf.spec must declare disabled for mtls_bridge_daemon://<name>",
    ]


def test_spec_declaring_interval_is_caught(tmp_path):
    # Declaring interval gets the daemon discovered, but splunkd then ignores the scheme's restart interval (#37).
    app = tmp_path / "app"
    shutil.copytree(ROOT / "package" / "default", app / "default")
    (app / "README").mkdir()
    (app / "README" / "inputs.conf.spec").write_text(
        "[mtls_bridge_daemon://<name>]\ninterval =\n* Seconds between daemon restarts.\n"
    )
    problems = check_modinput_spec.problems(app)
    assert "README/inputs.conf.spec must not declare interval for mtls_bridge_daemon://<name>" in problems
