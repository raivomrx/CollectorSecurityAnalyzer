"""Session-scoped TLS and offline encryption key generation."""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from csa_console.identifiers import utc_now


def generate_session_certificate(
    certificate_path: str | Path,
    private_key_path: str | Path,
    host: str,
    validity_hours: int = 12,
) -> str:
    """Generate a short-lived self-signed certificate and return its fingerprint."""

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, f"CSA Session {host}")]
    )
    now = utc_now()
    alternative_name: x509.GeneralName
    try:
        alternative_name = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        alternative_name = x509.DNSName(host)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=2))
        .not_valid_after(now + timedelta(hours=validity_hours))
        .add_extension(x509.SubjectAlternativeName([alternative_name]), critical=False)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .sign(key, hashes.SHA256())
    )
    key_output = Path(private_key_path)
    certificate_output = Path(certificate_path)
    key_output.parent.mkdir(parents=True, exist_ok=True)
    key_output.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_output.chmod(0o600)
    certificate_output.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    certificate_output.chmod(0o600)
    return "sha256:" + hashlib.sha256(
        certificate.public_bytes(serialization.Encoding.DER)
    ).hexdigest()


def generate_offline_keypair(
    public_key_path: str | Path,
    private_key_path: str | Path,
) -> None:
    """Generate a session-scoped RSA keypair for offline submissions."""

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_output = Path(private_key_path)
    public_output = Path(public_key_path)
    private_output.parent.mkdir(parents=True, exist_ok=True)
    private_output.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private_output.chmod(0o600)
    numbers = key.public_key().public_numbers()
    import base64

    modulus = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    exponent = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    xml = (
        "<RSAKeyValue><Modulus>"
        + base64.b64encode(modulus).decode("ascii")
        + "</Modulus><Exponent>"
        + base64.b64encode(exponent).decode("ascii")
        + "</Exponent></RSAKeyValue>"
    )
    public_output.write_text(xml, encoding="ascii")
    public_output.chmod(0o600)
