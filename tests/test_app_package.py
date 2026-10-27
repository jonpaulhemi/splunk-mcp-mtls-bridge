"""The packaged app's own conf files: Splunk ingests the audit file the daemon writes."""

import configparser

from mtls_bridge import splunk_config

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


def test_audit_sourcetype_parses_one_json_event_per_line():
    stanza = _conf("props.conf")["mtls_bridge:audit"]
    assert stanza["KV_MODE"] == "json"
    assert stanza["SHOULD_LINEMERGE"] == "false"
    assert stanza["TIME_PREFIX"]
