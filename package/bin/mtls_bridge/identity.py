"""Turns a verified peer cert into an issuer string and a set of typed identities."""

from dataclasses import dataclass
from typing import FrozenSet, Tuple

# Attribute names as Python's ssl module reports them, mapped to RFC 4514 short names.
_ATTRIBUTE_NAMES = {
    "commonName": "CN",
    "countryName": "C",
    "localityName": "L",
    "stateOrProvinceName": "ST",
    "organizationName": "O",
    "organizationalUnitName": "OU",
    "streetAddress": "STREET",
    "domainComponent": "DC",
    "userId": "UID",
}

# subjectAltName types as reported by ssl.getpeercert(), mapped to mapping identity types.
_SAN_TYPES = {
    "URI": "URI",
    "DNS": "DNS",
    "email": "EMAIL",
    "IP Address": "IP",
}


@dataclass(frozen=True)
class PeerIdentity:
    issuer: str
    identities: FrozenSet[Tuple[str, str]]


def _escape(value):
    out = []
    for i, char in enumerate(value):
        if char in ',+"\\<>;=' or (char == "#" and i == 0) or (char == " " and i in (0, len(value) - 1)):
            out.append("\\" + char)
        else:
            out.append(char)
    return "".join(out)


def rfc4514(name):
    """Render an ssl-module name (tuple of RDNs) as an RFC 4514 string, most specific RDN first."""
    rdns = []
    for rdn in reversed(name):
        parts = [f"{_ATTRIBUTE_NAMES.get(attr, attr)}={_escape(value)}" for attr, value in rdn]
        rdns.append("+".join(parts))
    return ",".join(rdns)


def from_peercert(cert):
    identities = set()
    for san_type, value in cert.get("subjectAltName", ()):
        if san_type in _SAN_TYPES:
            identities.add((_SAN_TYPES[san_type], value))
    for rdn in cert.get("subject", ()):
        for attr, value in rdn:
            if attr == "commonName":
                identities.add(("CN", value))
    return PeerIdentity(issuer=rfc4514(cert.get("issuer", ())), identities=frozenset(identities))
