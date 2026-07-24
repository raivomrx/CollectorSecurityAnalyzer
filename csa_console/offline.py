"""Encrypted offline endpoint submission export and import."""

from __future__ import annotations

import base64
import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, padding as symmetric_padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from csa_console.audit import ConsoleAuditLog
from csa_console.canonical import canonical_bytes, canonical_json
from csa_console.enums import SubmissionState
from csa_console.identifiers import random_id, utc_text
from csa_console.models import SubmissionReceipt
from csa_console.package import EvidencePackageValidator, ValidatedPackage
from csa_console.pipeline import ConsoleAnalysisPipeline
from csa_console.receipts import sign_receipt
from csa_console.reporting import ConsoleReportGenerator
from csa_console.serde import model_to_dict
from csa_console.sessions import AssessmentSessionService
from csa_console.storage import AssessmentStorage
from csa_console.submission import SubmissionRejected, SubmissionService


class OfflineImportError(ValueError):
    """Report invalid or tampered offline submissions."""


@dataclass(slots=True)
class DecryptedOfflineSubmission:
    """Contain authenticated offline import material."""

    archive_bytes: bytes
    enrollment_token: str
    nonce: str
    associated_data: dict[str, Any]


def encrypt_offline_submission(
    output_path: str | Path,
    *,
    archive_bytes: bytes,
    enrollment_token: str,
    nonce: str,
    associated_data: dict[str, Any],
    public_key_xml_path: str | Path,
) -> Path:
    """Create the same hybrid offline envelope as the PowerShell Collector."""

    import re

    xml = Path(public_key_xml_path).read_text(encoding="ascii")
    modulus_match = re.search(r"<Modulus>([^<]+)</Modulus>", xml)
    exponent_match = re.search(r"<Exponent>([^<]+)</Exponent>", xml)
    if not modulus_match or not exponent_match:
        raise OfflineImportError("Offline RSA public key is invalid")
    modulus = int.from_bytes(base64.b64decode(modulus_match.group(1)), "big")
    exponent = int.from_bytes(base64.b64decode(exponent_match.group(1)), "big")
    public_key = RSAPublicNumbers(exponent, modulus).public_key()
    material = os.urandom(64)
    iv = os.urandom(16)
    inner = {
        "archive": base64.b64encode(archive_bytes).decode("ascii"),
        "enrollmentToken": enrollment_token,
        "nonce": nonce,
    }
    padder = symmetric_padding.PKCS7(128).padder()
    padded = padder.update(canonical_bytes(inner)) + padder.finalize()
    encryptor = Cipher(algorithms.AES(material[:32]), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    mac = hmac.digest(
        material[32:],
        canonical_bytes(associated_data) + iv + ciphertext,
        "sha256",
    )
    wrapped = public_key.encrypt(
        material,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )
    envelope = {
        "algorithm": "RSA-OAEP-SHA1+A256CBC-HS256",
        "associatedData": associated_data,
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "mac": base64.b64encode(mac).decode("ascii"),
        "schemaVersion": "5.0",
        "wrappedKey": base64.b64encode(wrapped).decode("ascii"),
    }
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical_bytes(envelope))
    output.chmod(0o600)
    return output


def decrypt_offline_submission(
    path: str | Path,
    private_key_path: str | Path,
) -> DecryptedOfflineSubmission:
    """Authenticate and decrypt one hybrid-encrypted offline envelope."""

    text = Path(path).read_text(encoding="utf-8")
    try:
        envelope = json.loads(text)
    except json.JSONDecodeError as error:
        raise OfflineImportError("Offline envelope contains invalid JSON") from error
    if canonical_json(envelope) != text:
        raise OfflineImportError("Offline envelope is not canonical JSON")
    if (
        envelope.get("schemaVersion") != "5.0"
        or envelope.get("algorithm") != "RSA-OAEP-SHA1+A256CBC-HS256"
    ):
        raise OfflineImportError("Offline envelope algorithm is unsupported")
    try:
        wrapped = base64.b64decode(envelope["wrappedKey"], validate=True)
        iv = base64.b64decode(envelope["iv"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
        supplied_mac = base64.b64decode(envelope["mac"], validate=True)
    except (KeyError, ValueError) as error:
        raise OfflineImportError("Offline envelope encoding is invalid") from error
    key = load_pem_private_key(Path(private_key_path).read_bytes(), password=None)
    try:
        material = key.decrypt(
            wrapped,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        )
    except ValueError as error:
        raise OfflineImportError("Offline key unwrap failed") from error
    if len(material) != 64 or len(iv) != 16:
        raise OfflineImportError("Offline envelope key material is invalid")
    aes_key, hmac_key = material[:32], material[32:]
    associated = envelope.get("associatedData")
    if not isinstance(associated, dict):
        raise OfflineImportError("Offline associated data is missing")
    mac_input = canonical_bytes(associated) + iv + ciphertext
    expected_mac = hmac.digest(hmac_key, mac_input, "sha256")
    if not hmac.compare_digest(supplied_mac, expected_mac):
        raise OfflineImportError("Offline envelope authentication failed")
    decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = symmetric_padding.PKCS7(128).unpadder()
    try:
        plaintext = unpadder.update(padded) + unpadder.finalize()
        inner = json.loads(plaintext.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OfflineImportError("Offline envelope plaintext is invalid") from error
    if canonical_json(inner).encode("utf-8") != plaintext:
        raise OfflineImportError("Offline envelope plaintext is not canonical")
    try:
        archive = base64.b64decode(inner["archive"], validate=True)
        token = str(inner["enrollmentToken"])
        nonce = str(inner["nonce"])
    except (KeyError, ValueError) as error:
        raise OfflineImportError("Offline submission binding is incomplete") from error
    return DecryptedOfflineSubmission(archive, token, nonce, associated)


class OfflineImportService:
    """Import an encrypted package through the same validation pipeline."""

    def __init__(self, storage: AssessmentStorage | None = None) -> None:
        """Create an offline import service."""

        self.storage = storage or AssessmentStorage()
        self.sessions = AssessmentSessionService(self.storage)
        self.submissions = SubmissionService(self.storage)

    def import_file(
        self,
        assessment_id: str,
        path: str | Path,
        *,
        analyze: bool = True,
    ) -> ValidatedPackage:
        """Decrypt, validate, deduplicate and optionally analyze a submission."""

        envelope = json.loads(Path(path).read_text(encoding="utf-8"))
        associated = envelope.get("associatedData", {})
        if associated.get("assessmentId") != assessment_id:
            raise OfflineImportError("Offline submission targets another assessment")
        session_id = str(associated.get("sessionId", ""))
        submission_id = str(associated.get("submissionId", ""))
        session = self.sessions.load_session(assessment_id, session_id)
        if not session.offline_private_key_path:
            raise OfflineImportError("Session offline private key is unavailable")
        decrypted = decrypt_offline_submission(
            path, session.offline_private_key_path
        )
        self.sessions.verify_token(session, decrypted.enrollment_token)
        validator = EvidencePackageValidator(
            maximum_package_size=session.maximum_package_size
        )
        package = validator.validate(
            decrypted.archive_bytes,
            enrollment_token=decrypted.enrollment_token,
            expected_assessment_id=assessment_id,
            expected_session_id=session_id,
            expected_submission_id=submission_id,
            expected_nonce=decrypted.nonce,
            expected_profile_digest=session.collection_profile_digest,
        )
        trusted_builds = {
            str(item)
            for item in session.report_configuration.get(
                "trustedCollectorBuildDigests", []
            )
        }
        if package.manifest.get("collectorBuildDigest") not in trusted_builds:
            raise OfflineImportError(
                "Collector build digest is not trusted for this session"
            )
        if package.package_digest != associated.get("packageDigest"):
            raise OfflineImportError("Offline package digest binding is invalid")
        existing = self.submissions.list_submissions(assessment_id)
        if any(
            item.get("submissionId") == submission_id
            or item.get("packageDigest") == package.package_digest
            for item in existing
        ):
            raise SubmissionRejected(
                SubmissionState.REJECTED_REPLAY,
                "Duplicate offline submission",
            )
        accepted = self.storage.path(
            assessment_id,
            "submissions",
            "accepted",
            f"{submission_id}.csa.zip",
        )
        accepted.write_bytes(decrypted.archive_bytes)
        accepted.chmod(0o600)
        existing.append(
            {
                "assessmentId": assessment_id,
                "sessionId": session_id,
                "submissionId": submission_id,
                "deviceId": package.manifest["deviceId"],
                "packageDigest": package.package_digest,
                "state": "EVIDENCE_ACCEPTED",
                "receivedAt": utc_text(),
                "transport": "OFFLINE_ENCRYPTED",
            }
        )
        existing.sort(key=lambda item: str(item["submissionId"]))
        self.storage.write_json(
            assessment_id, ("submissions", "index.json"), {"items": existing}
        )
        self.sessions.record_token_use(session)
        received_at = utc_text()
        if not session.tls_private_key_path:
            raise OfflineImportError("Session receipt signing key is unavailable")
        receipt_value: dict[str, Any] = {
            "assessmentId": assessment_id,
            "sessionId": session_id,
            "submissionId": submission_id,
            "receivedAt": received_at,
            "packageDigest": package.package_digest,
            "validationStatus": "ACCEPTED_OFFLINE",
            "serverReceiptId": random_id("RCP-"),
            "cleanupConfirmed": None,
        }
        receipt_value["serverSignature"] = sign_receipt(
            receipt_value, session.tls_private_key_path
        )
        receipt = SubmissionReceipt(
            assessment_id=assessment_id,
            session_id=session_id,
            submission_id=submission_id,
            received_at=received_at,
            package_digest=package.package_digest,
            validation_status="ACCEPTED_OFFLINE",
            server_receipt_id=str(receipt_value["serverReceiptId"]),
            server_signature=str(receipt_value["serverSignature"]),
        )
        self.storage.write_json(
            assessment_id,
            ("submissions", "accepted", f"{submission_id}.receipt.json"),
            model_to_dict(receipt),
        )
        ConsoleAuditLog(
            self.storage.path(assessment_id, "audit", "audit.jsonl")
        ).append(
            "offline_submission_imported",
            {
                "sessionId": session_id,
                "submissionId": submission_id,
                "packageDigest": package.package_digest,
            },
        )
        if analyze:
            ConsoleAnalysisPipeline(self.storage).analyze(package)
            ConsoleReportGenerator(self.storage).generate_endpoint(
                assessment_id, submission_id
            )
        return package
