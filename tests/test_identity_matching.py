"""Which mapping a client certificate resolves to: issuer plus one typed identity."""

import subprocess
import sys

import pytest

from mtls_bridge.config import Mapping

import pki
from harness import ROOT, client_of, make_config, running_bridge

INSPECT_CERT = ROOT / "package" / "bin" / "inspect-cert"


@pytest.fixture(scope="module")
def all_cas(test_pki, tmp_path_factory):
    """A CA bundle trusting every test CA."""
    bundle = tmp_path_factory.mktemp("bundle") / "cas.pem"
    bundle.write_bytes(
        b"".join(ca.cert_path.read_bytes() for ca in (test_pki.ca, test_pki.other_ca, test_pki.escaped_ca))
    )
    return bundle


def _mapping(issuer, identity_type, identity_value, account="svc"):
    return Mapping(issuer, identity_type, identity_value, account, token="token-" + account)


def _status(test_pki, upstream, all_cas, mappings, cert):
    """The HTTP status a tools/list call with ``cert`` gets from a bridge holding ``mappings``."""
    config = make_config(test_pki, upstream, ca_bundle=str(all_cas), mappings=mappings)
    with running_bridge(config) as bridge:
        status, _, body = client_of(bridge, test_pki, cert).rpc("tools/list")
    return status, body


@pytest.mark.parametrize(
    "identity_type, value",
    [
        ("URI", "spiffe://bridge.test/Agent-C"),
        ("DNS", "Agent-C.Bridge.Test"),
        ("DNS", "agent-c.bridge.test"),
        ("EMAIL", "agent.c@bridge.test"),
        ("UPN", "AGENT-C@corp.test"),
        ("IP", "10.0.0.7"),
        ("IP", "::ffff:10.0.0.7"),
        ("IP", "2001:db8::7"),
        ("IP", "2001:0db8:0000:0000:0000:0000:0000:0007"),
        ("CN", "Agent-C"),
    ],
)
def test_each_identity_type_matches_by_its_rule(test_pki, upstream, all_cas, identity_type, value):
    mappings = [_mapping(test_pki.ca.issuer_dn, identity_type, value)]
    status, _ = _status(test_pki, upstream, all_cas, mappings, test_pki.multi)
    assert status == 200


@pytest.mark.parametrize(
    "identity_type, value",
    [
        ("URI", "spiffe://bridge.test/agent-c"),  # URIs are exact
        ("CN", "agent-c"),  # so are common names
        ("DNS", "other.bridge.test"),
        ("IP", "10.0.0.8"),
        ("EMAIL", "Agent-C.Bridge.Test"),  # a DNS name isn't an email identity
    ],
)
def test_identities_that_differ_do_not_match(test_pki, upstream, all_cas, identity_type, value):
    mappings = [_mapping(test_pki.ca.issuer_dn, identity_type, value)]
    status, body = _status(test_pki, upstream, all_cas, mappings, test_pki.multi)
    assert status == 403
    assert "unmapped" in body["error"]["message"]


def test_issuer_matches_case_insensitively_with_spaces_trimmed(test_pki, upstream, all_cas):
    mappings = [_mapping("cn=BRIDGE TEST CA ,  o = bridge test, C=us", "URI", pki.MAPPED_URI)]
    status, _ = _status(test_pki, upstream, all_cas, mappings, test_pki.mapped)
    assert status == 200


def test_renewed_cert_matches_the_existing_mapping(test_pki, upstream, all_cas):
    mappings = [_mapping(test_pki.ca.issuer_dn, "URI", pki.MAPPED_URI)]
    status, _ = _status(test_pki, upstream, all_cas, mappings, test_pki.renewed)
    assert status == 200


def test_same_identity_from_another_trusted_issuer_does_not_match(test_pki, upstream, all_cas):
    mappings = [_mapping(test_pki.ca.issuer_dn, "URI", pki.MAPPED_URI)]
    status, body = _status(test_pki, upstream, all_cas, mappings, test_pki.other_ca_client)
    assert status == 403
    assert "unmapped" in body["error"]["message"]


def test_issuer_with_escaped_characters_matches(test_pki, upstream, all_cas):
    mappings = [_mapping(test_pki.escaped_ca.issuer_dn, "URI", "spiffe://bridge.test/escaped")]
    status, _ = _status(test_pki, upstream, all_cas, mappings, test_pki.escaped_client)
    assert status == 200


def test_cert_matching_two_mappings_is_rejected_as_ambiguous(test_pki, upstream, all_cas):
    mappings = [
        _mapping(test_pki.ca.issuer_dn, "URI", "spiffe://bridge.test/amb-1", account="one"),
        _mapping(test_pki.ca.issuer_dn, "URI", "spiffe://bridge.test/amb-2", account="two"),
    ]
    status, body = _status(test_pki, upstream, all_cas, mappings, test_pki.ambiguous)

    assert status == 403
    assert "ambiguous" in body["error"]["message"]
    assert upstream.received == []


def _inspect(cert):
    result = subprocess.run([sys.executable, str(INSPECT_CERT), str(cert)], capture_output=True, text=True, check=True)
    return result.stdout


def _inspected_values(output):
    """(issuer, [(type, value), ...]) parsed from inspect-cert's output."""
    issuer, identities = None, []
    for line in output.splitlines():
        label, _, value = line.partition(":")
        value = value.strip()
        if label.strip() == "Issuer":
            issuer = value
        elif label.strip() in ("URI", "DNS", "EMAIL", "UPN", "IP", "CN"):
            identities.append((label.strip(), value))
    return issuer, identities


def test_inspect_cert_prints_every_identity_by_type(test_pki):
    issuer, identities = _inspected_values(_inspect(test_pki.multi.cert))

    assert issuer == "CN=Bridge Test CA,O=Bridge Test,C=US"
    assert sorted(identities) == sorted(
        [
            ("URI", "spiffe://bridge.test/Agent-C"),
            ("DNS", "Agent-C.Bridge.Test"),
            ("EMAIL", "Agent.C@Bridge.Test"),
            ("IP", "10.0.0.7"),
            ("IP", "2001:db8::7"),
            ("UPN", "agent-c@CORP.TEST"),
            ("CN", "Agent-C"),
        ]
    )


@pytest.mark.parametrize("cert_name", ["multi", "escaped_client"])
def test_inspect_cert_output_pasted_into_a_mapping_matches(test_pki, upstream, all_cas, cert_name):
    cert = getattr(test_pki, cert_name)
    issuer, identities = _inspected_values(_inspect(cert.cert))
    for identity_type, value in identities:
        status, _ = _status(test_pki, upstream, all_cas, [_mapping(issuer, identity_type, value)], cert)
        assert status == 200, (identity_type, value)
