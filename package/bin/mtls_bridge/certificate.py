"""Reads the fields the bridge needs from a DER X.509 certificate, using only the standard library.

Python's ``ssl.getpeercert()`` drops otherName SANs (so UPNs) and decoded RDN types, so the
bridge parses the peer's DER itself. Only the structure is read: the TLS handshake has already
verified the chain.
"""

import base64
import hashlib
import ipaddress
import re
from dataclasses import dataclass
from typing import Tuple

_SEQUENCE = 0x30
_SET = 0x31
_INTEGER = 0x02
_OID = 0x06
_OCTET_STRING = 0x04
_BOOLEAN = 0x01

# Context-specific tags in TBSCertificate and GeneralName.
_VERSION = 0xA0
_EXTENSIONS = 0xA3
_GN_OTHER_NAME = 0xA0
_GN_EMAIL = 0x81
_GN_DNS = 0x82
_GN_URI = 0x86
_GN_IP = 0x87

_SUBJECT_ALT_NAME = "2.5.29.17"
UPN_OID = "1.3.6.1.4.1.311.20.2.3"

# Directory string encodings, by universal tag.
_STRING_CODECS = {
    0x0C: "utf-8",  # UTF8String
    0x12: "ascii",  # NumericString
    0x13: "ascii",  # PrintableString
    0x14: "latin-1",  # TeletexString
    0x16: "ascii",  # IA5String
    0x1A: "ascii",  # VisibleString
    0x1C: "utf-32-be",  # UniversalString
    0x1E: "utf-16-be",  # BMPString
}


class CertificateError(ValueError):
    pass


@dataclass(frozen=True)
class Attribute:
    """One attribute of a distinguished name. ``value`` is text, or None if not a string type."""

    oid: str
    value: object
    der: bytes


@dataclass(frozen=True)
class Certificate:
    issuer: Tuple[Tuple[Attribute, ...], ...]  # RDNs in DER order, least specific first
    subject: Tuple[Tuple[Attribute, ...], ...]
    alt_names: Tuple[Tuple[str, str], ...]  # (kind, value): URI, DNS, EMAIL, UPN or IP
    serial: int
    sha256: str  # lowercase hex of the DER

    @property
    def serial_hex(self):
        return format(self.serial, "X")


def _read(data, offset):
    """Return (tag, content, offset after the element) for the DER element at ``offset``."""
    try:
        tag = data[offset]
        length = data[offset + 1]
        offset += 2
        if length & 0x80:
            count = length & 0x7F
            if not 0 < count <= 4:
                raise CertificateError("unsupported DER length")
            length = int.from_bytes(data[offset : offset + count], "big")
            offset += count
    except IndexError:
        raise CertificateError("truncated DER") from None
    end = offset + length
    if end > len(data):
        raise CertificateError("truncated DER")
    return tag, data[offset:end], end


def _children(data):
    offset = 0
    while offset < len(data):
        tag, content, offset = _read(data, offset)
        yield tag, content


def _expect(tag, content, wanted):
    if tag != wanted:
        raise CertificateError(f"expected DER tag {wanted:#x}, found {tag:#x}")
    return content


def _oid(content):
    if not content:
        raise CertificateError("empty OID")
    first = content[0]
    arcs = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    return ".".join(map(str, arcs))


def _text(tag, content):
    codec = _STRING_CODECS.get(tag)
    if codec is None:
        return None
    try:
        return content.decode(codec)
    except UnicodeDecodeError:
        raise CertificateError("undecodable directory string") from None


def _element(tag, content):
    """Re-encode an element, for RFC 4514's #hex form of non-string attribute values."""
    length = len(content)
    if length < 0x80:
        header = bytes([tag, length])
    else:
        raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
        header = bytes([tag, 0x80 | len(raw)]) + raw
    return header + content


def _name(content):
    rdns = []
    for tag, rdn in _children(content):
        attributes = []
        for attr_tag, pair in _children(_expect(tag, rdn, _SET)):
            parts = list(_children(_expect(attr_tag, pair, _SEQUENCE)))
            if len(parts) != 2:
                raise CertificateError("malformed name attribute")
            (oid_tag, oid), (value_tag, value) = parts
            attributes.append(
                Attribute(_oid(_expect(oid_tag, oid, _OID)), _text(value_tag, value), _element(value_tag, value))
            )
        rdns.append(tuple(attributes))
    return tuple(rdns)


def _other_name(content):
    parts = list(_children(content))
    if len(parts) != 2 or parts[0][0] != _OID or parts[1][0] != 0xA0:
        return None
    if _oid(parts[0][1]) != UPN_OID:
        return None
    inner = list(_children(parts[1][1]))
    if len(inner) != 1:
        return None
    return _text(*inner[0])


def _alt_names(content):
    names = []
    for tag, value in _children(content):
        if tag == _GN_URI:
            names.append(("URI", value.decode("ascii", "replace")))
        elif tag == _GN_DNS:
            names.append(("DNS", value.decode("ascii", "replace")))
        elif tag == _GN_EMAIL:
            names.append(("EMAIL", value.decode("ascii", "replace")))
        elif tag == _GN_IP and len(value) in (4, 16):
            names.append(("IP", str(ipaddress.ip_address(value))))
        elif tag == _GN_OTHER_NAME:
            upn = _other_name(value)
            if upn is not None:
                names.append(("UPN", upn))
    return tuple(names)


def _extensions(content):
    """Yield (oid, value) for each extension."""
    for tag, extension in _children(_expect(*_read(content, 0)[:2], _SEQUENCE)):
        parts = list(_children(_expect(tag, extension, _SEQUENCE)))
        oid = _oid(_expect(*parts[0], _OID))
        value = parts[-1]
        yield oid, _expect(*value, _OCTET_STRING)


def parse(der):
    """Parse a DER certificate into a Certificate. Raises CertificateError if it isn't one."""
    tag, certificate, _ = _read(der, 0)
    tag, tbs, _ = _read(_expect(tag, certificate, _SEQUENCE), 0)
    fields = list(_children(_expect(tag, tbs, _SEQUENCE)))
    if fields and fields[0][0] == _VERSION:
        fields = fields[1:]
    if len(fields) < 6:
        raise CertificateError("malformed TBSCertificate")
    serial = int.from_bytes(_expect(*fields[0], _INTEGER), "big", signed=True)
    issuer = _name(_expect(*fields[2], _SEQUENCE))
    subject = _name(_expect(*fields[4], _SEQUENCE))
    alt_names = ()
    for field_tag, field in fields[6:]:
        if field_tag == _EXTENSIONS:
            for oid, value in _extensions(field):
                if oid == _SUBJECT_ALT_NAME:
                    alt_names = _alt_names(_expect(*_read(value, 0)[:2], _SEQUENCE))
    return Certificate(issuer, subject, alt_names, serial, hashlib.sha256(der).hexdigest())


_PEM = re.compile(rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", re.S)


def load(path):
    """Parse the first certificate in a PEM or DER file."""
    with open(path, "rb") as handle:
        data = handle.read()
    match = _PEM.search(data)
    if match:
        try:
            data = base64.b64decode(b"".join(match.group(1).split()), validate=True)
        except ValueError:
            raise CertificateError("invalid PEM") from None
    return parse(data)
