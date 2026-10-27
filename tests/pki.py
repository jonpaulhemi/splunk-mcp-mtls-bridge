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


def _name(cn, org="Bridge Test"):
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
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


def make_ca(directory, cn):
    key = ec.generate_private_key(ec.SECP256R1())
    name = _name(cn)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
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
        .sign(key, hashes.SHA256())
    )
    path = Path(directory) / (cn.replace(" ", "_") + ".pem")
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


MAPPED_URI = "spiffe://bridge.test/agent-a"


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
    return TestPKI(
        ca=ca,
        other_ca=other_ca,
        server=server,
        mapped=mapped,
        unmapped=unmapped,
        other_ca_client=other_ca_client,
    )
