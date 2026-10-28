"""Validation the Mappings page runs before saving a row: one cert identity maps to one account."""

import pytest

from mtls_bridge.identity import mapping_row_problem

ISSUER = "CN=Bridge Test CA,O=Bridge Test,C=US"


def _row(issuer=ISSUER, identity_type="URI", identity_value="spiffe://bridge.test/agent-a"):
    return {"issuer": issuer, "identity_type": identity_type, "identity_value": identity_value}


def test_a_new_identity_can_be_saved():
    rows = {"agent_b": _row(identity_value="spiffe://bridge.test/agent-b")}
    assert mapping_row_problem("agent_a", _row(), rows) is None


@pytest.mark.parametrize(
    "duplicate",
    [
        _row(),
        _row(issuer="cn=bridge test ca, o=BRIDGE TEST, c=us"),
        _row(identity_type="DNS", identity_value="Agent.Bridge.Test"),
        _row(identity_type="IP", identity_value="::ffff:10.0.0.1"),
    ],
)
def test_a_row_matching_the_same_certs_as_another_is_refused(duplicate):
    existing = {
        "agent_a": _row(),
        "agent_dns": _row(identity_type="DNS", identity_value="agent.bridge.test"),
        "agent_ip": _row(identity_type="IP", identity_value="10.0.0.1"),
    }
    problem = mapping_row_problem("new_row", duplicate, existing)
    assert problem is not None
    assert "already" in problem


def test_editing_a_row_does_not_conflict_with_itself():
    assert mapping_row_problem("agent_a", _row(), {"agent_a": _row()}) is None


def test_same_identity_under_another_issuer_is_allowed():
    rows = {"agent_a": _row()}
    assert mapping_row_problem("other", _row(issuer="CN=Other Test CA,O=Bridge Test"), rows) is None


@pytest.mark.parametrize(
    "row, complaint",
    [
        (_row(issuer="Bridge Test CA"), "RFC 4514"),
        (_row(issuer="CN=Bridge Test CA,BOGUS=x"), "attribute type"),
        (_row(identity_type="IP", identity_value="10.0.0.300"), "IP"),
        (_row(identity_type="SERIAL"), "identity type"),
    ],
)
def test_a_row_that_can_never_match_is_refused(row, complaint):
    problem = mapping_row_problem("agent_a", row, {})
    assert problem is not None
    assert complaint in problem


def test_unreadable_existing_rows_are_ignored():
    rows = {"broken": _row(issuer="garbage")}
    assert mapping_row_problem("agent_a", _row(), rows) is None


def test_issuer_with_an_escaped_trailing_space_is_accepted():
    # How the bridge and inspect-cert render a CA name ending in a space.
    assert mapping_row_problem("agent_a", _row(issuer="CN=Bridge Test CA\\ ,O=Bridge Test,C=US"), {}) is None


def test_identity_values_with_stray_spaces_still_match():
    rows = {"agent_dns": _row(identity_type="DNS", identity_value="agent.bridge.test")}
    assert mapping_row_problem("new", _row(identity_type="DNS", identity_value=" Agent.Bridge.Test "), rows)


@pytest.mark.parametrize(
    "spelling",
    [
        "CN=Bridge Test CA,1.2.840.113549.1.9.1=#160e6361406272696467652e74657374,O=Bridge Test",
        "CN=Bridge Test CA,1.2.840.113549.1.9.1=ca@bridge.test,O=Bridge Test",
        "CN=Bridge Test CA,emailAddress=CA@bridge.test,O=Bridge Test",
    ],
)
def test_an_attribute_without_a_short_name_matches_in_any_common_spelling(spelling):
    rows = {"existing": _row(issuer="CN=Bridge Test CA,E=ca@bridge.test,O=Bridge Test")}
    assert "already" in mapping_row_problem("new", _row(issuer=spelling), rows)


@pytest.mark.parametrize("name", ["SERIALNUMBER", "GIVENNAME", "SN", "TITLE", "POSTALCODE", "ORGANIZATIONIDENTIFIER"])
def test_an_issuer_may_use_other_x520_attribute_names(name):
    assert mapping_row_problem("agent_a", _row(issuer=f"{name}=42,CN=Bridge Test CA"), {}) is None


def test_an_attribute_name_and_its_oid_describe_the_same_issuer():
    # How a cert renders serialNumber=42: its dotted OID and the #hex of its DER PrintableString.
    existing = {"rendered": _row(issuer="2.5.4.5=#13023432,CN=Bridge Test CA")}

    problem = mapping_row_problem("typed", _row(issuer="serialNumber=42,CN=Bridge Test CA"), existing)

    assert problem is not None and "rendered" in problem
