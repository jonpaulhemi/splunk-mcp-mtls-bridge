"""The packaged app's own conf files: Splunk ingests the audit file the daemon writes."""

import configparser
import datetime
import re

from mtls_bridge import splunk_config
from mtls_bridge.audit import AuditLog

from harness import ROOT

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
