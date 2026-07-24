"""Signed submission receipt helpers."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from csa_console.canonical import canonical_bytes


def sign_receipt(receipt: dict[str, Any], private_key_path: str | Path) -> str:
    """Sign receipt metadata with the session TLS identity key."""

    private_key = serialization.load_pem_private_key(
        Path(private_key_path).read_bytes(),
        password=None,
    )
    signature = private_key.sign(
        canonical_bytes(receipt),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.DIGEST_LENGTH,
        ),
        hashes.SHA256(),
    )
    return "rsa-pss-sha256:" + base64.b64encode(signature).decode("ascii")


def verify_receipt(
    receipt: dict[str, Any],
    certificate_path: str | Path,
) -> bool:
    """Verify a Console receipt against the pinned session certificate."""

    signature_value = str(receipt.get("serverSignature", ""))
    prefix, _, encoded = signature_value.partition(":")
    if prefix != "rsa-pss-sha256" or not encoded:
        return False
    unsigned = dict(receipt)
    unsigned.pop("serverSignature", None)
    certificate = x509.load_pem_x509_certificate(
        Path(certificate_path).read_bytes()
    )
    try:
        certificate.public_key().verify(
            base64.b64decode(encoded, validate=True),
            canonical_bytes(unsigned),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.DIGEST_LENGTH,
            ),
            hashes.SHA256(),
        )
    except (InvalidSignature, ValueError):
        return False
    return True
