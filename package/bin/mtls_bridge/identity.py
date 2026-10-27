"""Turns a verified peer cert into an issuer and typed identities, and defines how mappings compare to them."""

import ipaddress
from dataclasses import dataclass
from typing import FrozenSet, Tuple

from . import certificate

IDENTITY_TYPES = ("URI", "DNS", "EMAIL", "UPN", "IP", "CN")

# Attribute types rendered by short name in RFC 4514 strings. Any other type renders as its dotted OID.
_SHORT_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "STREET",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "0.9.2342.19200300.100.1.25": "DC",
    "0.9.2342.19200300.100.1.1": "UID",
}
_OIDS_BY_NAME = {name: oid for oid, name in _SHORT_NAMES.items()}
# Names other tools print for types the table lacks, accepted in pasted issuers.
_ALIASES = {"EMAILADDRESS": "1.2.840.113549.1.9.1", "E": "1.2.840.113549.1.9.1"}
_COMMON_NAME = "2.5.4.3"

_SPECIAL = ',+"\\<>;='


@dataclass(frozen=True)
class PeerIdentity:
    issuer: str  # RFC 4514, as the cert spells it
    identities: Tuple[Tuple[str, str], ...]  # (type, value) as the cert spells them
    serial: str  # uppercase hex
    sha256: str
    keys: FrozenSet[Tuple[str, str, str]]  # the mapping keys this cert satisfies

    def describe(self):
        """The cert's details as audit events carry them, in the form a mapping row takes."""
        return {
            "issuer": self.issuer,
            "identities": [{"type": kind, "value": value} for kind, value in self.identities],
            "serial": self.serial,
            "sha256": self.sha256,
        }


def _escape(value):
    out = []
    for i, char in enumerate(value):
        if char in _SPECIAL or (char == "#" and i == 0) or (char == " " and i in (0, len(value) - 1)):
            out.append("\\" + char)
        elif ord(char) < 0x20 or char == "\x7f":
            out.append(f"\\{ord(char):02X}")
        else:
            out.append(char)
    return "".join(out)


def rfc4514(rdns):
    """Render DER-order RDNs as an RFC 4514 string, most specific RDN first."""
    rendered = []
    for rdn in reversed(rdns):
        parts = []
        for attribute in rdn:
            name = _SHORT_NAMES.get(attribute.oid)
            if name is None or attribute.value is None:
                # RFC 4514 2.4: a type without a short name takes the #hex form of its DER value.
                parts.append(f"{name or attribute.oid}=#{attribute.der.hex()}")
            else:
                parts.append(f"{name}={_escape(attribute.value)}")
        rendered.append("+".join(parts))
    return ",".join(rendered)


def _split(text, separators):
    """Split on unescaped separator characters, keeping escapes intact."""
    parts, current, i = [], [], 0
    while i < len(text):
        char = text[i]
        if char == "\\" and i + 1 < len(text):
            current.append(text[i : i + 2])
            i += 2
            continue
        if char in separators:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
        i += 1
    parts.append("".join(current))
    return parts


def _unescape(value):
    """Unescape an RFC 4514 attribute value, dropping unescaped leading and trailing spaces."""
    chars, raw, i = [], bytearray(), 0  # chars: (text, escaped)

    def flush():
        if raw:
            try:
                chars.append((raw.decode("utf-8"), True))
            except UnicodeDecodeError:
                raise ValueError("invalid UTF-8 in hex escape") from None
            raw.clear()

    while i < len(value):
        char = value[i]
        if char == "\\":
            pair = value[i + 1 : i + 3]
            if len(pair) == 2 and all(c in "0123456789abcdefABCDEF" for c in pair):
                raw.append(int(pair, 16))
                i += 3
                continue
            flush()
            if i + 1 >= len(value):
                raise ValueError("trailing backslash")
            chars.append((value[i + 1], True))
            i += 2
            continue
        flush()
        chars.append((char, False))
        i += 1
    flush()
    while chars and chars[0] == (" ", False):
        chars.pop(0)
    while chars and chars[-1] == (" ", False):
        chars.pop()
    return "".join(text for text, _ in chars)


def _attribute_text(value):
    """An attribute value's text, whether written as an escaped string or as #hex of a DER string."""
    if not value.lstrip().startswith("#"):
        # _unescape trims unescaped edge spaces only: a cert's "\ " must survive.
        return _unescape(value)
    hex_value = value.strip()[1:]
    try:
        text = certificate.string_value(bytes.fromhex(hex_value))
    except ValueError:
        raise ValueError(f"invalid #hex attribute value {value.strip()!r}") from None
    return "#" + hex_value if text is None else text


def issuer_key(issuer):
    """The canonical form of an RFC 4514 issuer string: attribute order kept, case and spacing ignored.

    Raises ValueError if ``issuer`` isn't a distinguished name.
    """
    rdns = []
    for rdn in _split(issuer, ","):
        parts = []
        for pair in _split(rdn, "+"):
            name, equals, value = pair.partition("=")
            name = name.strip().upper()
            if not equals or not name:
                raise ValueError(f"issuer must be an RFC 4514 name such as CN=My CA,O=Example; {pair.strip()!r} is not")
            if name.startswith("OID."):
                name = name[4:]
            name = _ALIASES.get(name, name)
            if name[:1].isdigit():
                # Certs render types outside the table as dotted OIDs; accept those, or a table OID.
                name = _SHORT_NAMES.get(name, name)
            elif name not in _OIDS_BY_NAME:
                raise ValueError(f"unknown attribute type {name!r}")
            parts.append(f"{name}={_escape(_attribute_text(value).lower())}")
        rdns.append("+".join(sorted(parts)))
    if not rdns or rdns == [""]:
        raise ValueError("empty issuer")
    return ",".join(rdns)


def identity_key(identity_type, value):
    """The canonical form of an identity value of ``identity_type``. Raises ValueError if invalid."""
    if identity_type in ("DNS", "EMAIL", "UPN"):
        return value.strip().lower()
    if identity_type in ("URI", "CN"):
        return value
    if identity_type == "IP":
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError:
            raise ValueError(f"{value!r} is not an IP address") from None
        if address.version == 6 and address.ipv4_mapped:
            address = address.ipv4_mapped
        return str(address)
    raise ValueError(f"unknown identity type {identity_type!r}; use one of {', '.join(IDENTITY_TYPES)}")


def mapping_key(issuer, identity_type, identity_value):
    """The key a mapping row matches certs by. Raises ValueError if the row can never match a cert."""
    identity_type = identity_type.strip().upper()
    return (issuer_key(issuer), identity_type, identity_key(identity_type, identity_value))


def _row_key(row):
    return mapping_key(row.get("issuer", ""), row.get("identity_type", ""), row.get("identity_value", ""))


def mapping_row_problem(name, row, rows):
    """Why mapping row ``row`` can't be saved as ``name`` beside ``rows`` ({name: row}), or None if it can."""
    try:
        key = _row_key(row)
    except ValueError as exc:
        return str(exc)
    for other_name, other in rows.items():
        if other_name == name:
            continue
        try:
            other_key = _row_key(other)
        except ValueError:
            continue
        if other_key == key:
            return (
                f"mapping {other_name!r} already maps this issuer and {key[1]} identity; "
                "each certificate identity can map to only one account"
            )
    return None


def from_certificate(cert):
    """Raises ValueError if the issuer can't be named by any mapping (an empty issuer)."""
    identities = list(cert.alt_names)
    for rdn in cert.subject:
        for attribute in rdn:
            if attribute.oid == _COMMON_NAME and attribute.value is not None:
                identities.append(("CN", attribute.value))
    issuer = rfc4514(cert.issuer)
    canonical_issuer = issuer_key(issuer)
    keys = frozenset((canonical_issuer, kind, identity_key(kind, value)) for kind, value in identities)
    return PeerIdentity(issuer, tuple(identities), cert.serial_hex, cert.sha256, keys)


def from_der(der):
    return from_certificate(certificate.parse(der))
