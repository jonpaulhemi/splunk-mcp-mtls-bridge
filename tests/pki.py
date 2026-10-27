"""Generates a throwaway test PKI on disk for the integration tests."""

import datetime
import ipaddress
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass
class Issued:
    cert: Path
    key: Path


@dataclass
class CA:
    name: x509.Name
    key: ec.EllipticCurvePrivateKey
    cert: x509.Certificate
    cert_path: Path

    @property
    def issuer_dn(self):
        return self.cert.subject.rfc4514_string()


_NOW = datetime.datetime.now(datetime.timezone.utc)


def _name(cn, org="Bridge Test", extra=()):
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            *extra,
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _write_key(path, key):
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def make_ca(directory, cn, org="Bridge Test", extra=(), parent=None):
    """A CA: self-signed, or an intermediate signed by ``parent``. ``extra`` holds NameAttributes placed
    between O and CN."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = _name(cn, org, extra)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(parent.name if parent else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - datetime.timedelta(days=1))
        .not_valid_after(_NOW + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if parent:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(parent.key.public_key()), critical=False
        )
    cert = builder.sign(parent.key if parent else key, hashes.SHA256())
    path = Path(directory) / (cn.strip().replace(" ", "_") + ".pem")
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return CA(name=name, key=key, cert=cert, cert_path=path)


def issue(ca, directory, filename, cn, sans=(), eku=ExtendedKeyUsageOID.CLIENT_AUTH, rsa_key=False):
    """Issue a leaf cert. ``sans`` holds cryptography GeneralName objects."""
    if rsa_key:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:
        key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(ca.name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - datetime.timedelta(days=1))
        .not_valid_after(_NOW + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=rsa_key,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.key.public_key()),
            critical=False,
        )
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(list(sans)), critical=False)
    cert = builder.sign(ca.key, hashes.SHA256())
    directory = Path(directory)
    cert_path = directory / (filename + ".crt")
    key_path = directory / (filename + ".key")
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _write_key(key_path, key)
    return Issued(cert=cert_path, key=key_path)


@dataclass
class TestPKI:
    ca: CA
    other_ca: CA
    server: Issued
    mapped: Issued
    unmapped: Issued
    other_ca_client: Issued
    escaped_ca: CA
    escaped_client: Issued
    multi: Issued
    ambiguous: Issued
    renewed: Issued
    revoked: Issued  # for CRL tests; a CRL from ``ca`` lists it
    intermediate: CA  # signed by ``ca``
    via_intermediate: Issued  # issued by ``intermediate``


MAPPED_URI = "spiffe://bridge.test/agent-a"
REVOKED_URI = "spiffe://bridge.test/agent-r"
INTERMEDIATE_URI = "spiffe://bridge.test/agent-i"
UPN_OID = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
# An organisation name that needs RFC 4514 escaping.
ESCAPED_ORG = 'Example, "Inc"+Co'


def crl(ca, revoked=(), next_update=datetime.timedelta(days=7), this_update=datetime.timedelta(hours=-1)):
    """A PEM CRL signed by ``ca`` revoking the certs at the ``revoked`` paths (or CA objects).

    ``next_update`` and ``this_update`` are offsets from now.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca.name)
        .last_update(now + this_update)
        .next_update(now + next_update)
    )
    for item in revoked:
        cert = item.cert if isinstance(item, CA) else x509.load_pem_x509_certificate(Path(item).read_bytes())
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(cert.serial_number)
            .revocation_date(now - datetime.timedelta(hours=1))
            .build()
        )
    return builder.sign(ca.key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


def upn(value):
    """A Microsoft UPN subject alternative name."""
    encoded = value.encode()
    return x509.OtherName(UPN_OID, bytes([0x0C, len(encoded)]) + encoded)


def build(directory):
    directory = Path(directory)
    ca = make_ca(directory, "Bridge Test CA")
    other_ca = make_ca(directory, "Other Test CA")
    server = issue(
        ca,
        directory,
        "server",
        "localhost",
        sans=[x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))],
        eku=ExtendedKeyUsageOID.SERVER_AUTH,
        rsa_key=True,  # Splunk's server certs are RSA
    )
    mapped = issue(ca, directory, "mapped", "agent-a", sans=[x509.UniformResourceIdentifier(MAPPED_URI)])
    unmapped = issue(
        ca,
        directory,
        "unmapped",
        "agent-b",
        sans=[x509.UniformResourceIdentifier("spiffe://bridge.test/agent-b")],
    )
    other_ca_client = issue(
        other_ca, directory, "other_ca_client", "agent-a", sans=[x509.UniformResourceIdentifier(MAPPED_URI)]
    )
    # A trailing space, RFC 4514 specials, and an attribute with no short name (rendered as #hex).
    escaped_ca = make_ca(
        directory,
        "Escaped CA ",
        org=ESCAPED_ORG,
        extra=[x509.NameAttribute(NameOID.EMAIL_ADDRESS, "pki@bridge.test")],
    )
    escaped_client = issue(
        escaped_ca,
        directory,
        "escaped_client",
        "escaped",
        sans=[x509.UniformResourceIdentifier("spiffe://bridge.test/escaped")],
    )
    multi = issue(
        ca,
        directory,
        "multi",
        "Agent-C",
        sans=[
            x509.UniformResourceIdentifier("spiffe://bridge.test/Agent-C"),
            x509.DNSName("Agent-C.Bridge.Test"),
            x509.RFC822Name("Agent.C@Bridge.Test"),
            x509.IPAddress(ipaddress.ip_address("10.0.0.7")),
            x509.IPAddress(ipaddress.ip_address("2001:db8::7")),
            upn("agent-c@CORP.TEST"),
        ],
    )
    ambiguous = issue(
        ca,
        directory,
        "ambiguous",
        "agent-d",
        sans=[
            x509.UniformResourceIdentifier("spiffe://bridge.test/amb-1"),
            x509.UniformResourceIdentifier("spiffe://bridge.test/amb-2"),
        ],
    )
    revoked = issue(ca, directory, "revoked", "agent-r", sans=[x509.UniformResourceIdentifier(REVOKED_URI)])
    intermediate = make_ca(directory, "Bridge Intermediate CA", parent=ca)
    via_intermediate = issue(
        intermediate,
        directory,
        "via_intermediate",
        "agent-i",
        sans=[x509.UniformResourceIdentifier(INTERMEDIATE_URI)],
    )
    # Same issuer and identity as "mapped", with a new key and serial.
    renewed = issue(ca, directory, "renewed", "agent-a", sans=[x509.UniformResourceIdentifier(MAPPED_URI)])
    return TestPKI(
        revoked=revoked,
        intermediate=intermediate,
        via_intermediate=via_intermediate,
        escaped_ca=escaped_ca,
        escaped_client=escaped_client,
        multi=multi,
        ambiguous=ambiguous,
        renewed=renewed,
        ca=ca,
        other_ca=other_ca,
        server=server,
        mapped=mapped,
        unmapped=unmapped,
        other_ca_client=other_ca_client,
    )
