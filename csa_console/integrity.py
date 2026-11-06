"""Read-only, corresponding checks for report integrity assertions."""
from __future__ import annotations
import zipfile
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from csa_console.canonical import read_json, sha256_bytes, sha256_value
from csa_console.package import EvidencePackageValidator, PAYLOAD_FILES
from csa_console.receipts import verify_receipt
from csa_console.sessions import AssessmentSessionService
from csa_console.trust_receipts import verify_trust_receipt
from csa_console.trusted_grants import TrustedGrantStore


def _trust_summary(rows, key):
    states = [row[key] for row in rows]
    if "NOT_VERIFIED" in states:
        return "NOT_VERIFIED"
    verified = [value for value in states if value.startswith("VERIFIED_")]
    if verified and len(verified) == len(states):
        return verified[0]
    if verified:
        return "PARTIAL"
    if "TEST_ONLY" in states:
        return "TEST_ONLY"
    return "NOT_EVALUATED"


def _aggregate(states):
    states = list(states)
    if "NOT_VERIFIED" in states:
        return "NOT_VERIFIED"
    if not states or "NOT_EVALUATED" in states:
        return "NOT_EVALUATED"
    return "VERIFIED"


def verify_recorded_evidence(storage, assessment_id, analyses, index):
    """Verify recorded packages/receipts and the normalized-data binding.

    This establishes consistency with the recorded session, not an independent
    publisher trust anchor. No enrollment credential is loaded or exported.
    """
    rows = []
    indexed = {row.get("submissionId"): row for row in index}
    for analysis in analyses:
        submission = analysis["submissionId"]
        row = {"submissionId": submission, "archiveIntegrity": "NOT_EVALUATED",
               "receiptVerification": "NOT_EVALUATED", "normalizedEvidenceBinding": "NOT_EVALUATED",
               "collectorBuildAllowlist": "NOT_EVALUATED", "publisherProvenance": "NOT_EVALUATED",
               "labAuthority": "NOT_EVALUATED", "tlsIdentity": "NOT_EVALUATED",
               "trustAttestationIntegrity": "NOT_EVALUATED", "trustReason": "No protected server trust receipt is recorded."}
        rows.append(row)
        path = storage.path(assessment_id, "submissions", "accepted", submission + ".csa.zip")
        # SUB.csa.zip -> SUB.receipt.json (no arbitrary input paths).
        receipt_path = path.parent / (submission + ".receipt.json")
        if not path.is_file() or not receipt_path.is_file():
            row["reason"] = "Recorded package or signed receipt is unavailable."
            continue
        try:
            data = path.read_bytes()
            validator = EvidencePackageValidator()
            members = validator._safe_members(data)
            parse = validator._parse_canonical_object
            manifest = parse(members["manifest.json"], "manifest.json")
            integrity = parse(members["integrity.json"], "integrity.json")
            binding = integrity["binding"]
            files = manifest["files"]
            declared = {item["path"]: item for item in files}
            valid = (len(declared) == len(files) and set(declared) == set(PAYLOAD_FILES)
                     and manifest.get("assessmentId") == binding.get("assessmentId") == assessment_id
                     and manifest.get("submissionId") == binding.get("submissionId") == submission
                     and manifest.get("sessionId") == binding.get("sessionId") == analysis.get("sessionId")
                     and binding["files"] == files
                     and sha256_value(binding) == integrity["packageDigest"] == manifest["packageDigest"]
                     and sha256_bytes(members["integrity.json"]) == manifest["integrityDigest"]
                     and sha256_bytes(members["signatures/submission.sig"]) == manifest["signatureDigest"])
            valid = valid and all(declared[name]["sha256"] == sha256_bytes(members[name])
                                  and declared[name]["size"] == len(members[name]) for name in PAYLOAD_FILES)
            entry = indexed.get(submission, {})
            valid = valid and entry.get("packageDigest") == manifest["packageDigest"]
            if entry.get("transportDigest"):
                valid = valid and entry["transportDigest"] == sha256_bytes(data)
            row["archiveIntegrity"] = "VERIFIED" if valid else "NOT_VERIFIED"
            session = AssessmentSessionService(storage).load_session(assessment_id, manifest["sessionId"])
            receipt = read_json(receipt_path)
            cert = session.tls_certificate_path
            if cert and Path(cert).is_file():
                certificate = x509.load_pem_x509_certificate(Path(cert).read_bytes())
                pinned = sha256_bytes(certificate.public_bytes(serialization.Encoding.DER)) == session.tls_fingerprint
                row["tlsIdentity"] = "SESSION_CERTIFICATE_PIN_RECORDED" if pinned else "NOT_VERIFIED"
                signed = pinned and verify_receipt(receipt, cert)
                signed = signed and all(receipt.get(key) == expected for key, expected in {
                    "assessmentId": assessment_id, "sessionId": manifest["sessionId"],
                    "submissionId": submission, "packageDigest": manifest["packageDigest"],
                    "validationStatus": "ACCEPTED_OFFLINE" if entry.get("transport") == "OFFLINE_ENCRYPTED" else "ACCEPTED"}.items())
                row["receiptVerification"] = "VERIFIED" if signed else "NOT_VERIFIED"
            trust_path = path.parent / (submission + ".trust.json")
            if trust_path.is_file():
                try:
                    trust = read_json(trust_path)
                    source = TrustedGrantStore(storage).submission_provenance(session, submission, entry.get("transport", "HTTPS"))
                    trusted = valid and row["receiptVerification"] == "VERIFIED" and verify_trust_receipt(trust,
                        session=session, receipt=receipt, manifest=manifest, transport=entry.get("transport", "HTTPS"), source=source)
                    if not trusted:
                        raise ValueError("CSA-TRUST-ATTESTATION")
                    facts = trust["provenance"]
                    row["trustAttestationIntegrity"] = "VERIFIED_SERVER_RECORD"
                    row["trustReason"] = "Server-verified authorized release and independently enrolled Lab provenance, bound to this accepted evidence/receipt. This is not remote attestation of endpoint execution."
                    for name in ("publisherKeyId", "labKeyId", "publisherManifestDigest", "policyDigest", "approvalDigest", "publisherCertificateSha256", "tlsFingerprint"):
                        row[name] = facts[name]
                    row["assurance"] = trust["assurance"]
                    if trust["assurance"] == "REAL":
                        row.update(publisherProvenance="VERIFIED_AUTHORIZED_PROVENANCE", labAuthority="VERIFIED_ENROLLED_AUTHORITY", tlsIdentity="VERIFIED_ENROLLED_PIN")
                    else:
                        row.update(publisherProvenance="TEST_ONLY", labAuthority="TEST_ONLY", tlsIdentity="TEST_ONLY")
                        row["trustReason"] = "Isolated test identities only. No real publisher/Lab/channel enrollment is established."
                except (OSError, ValueError, KeyError, TypeError):
                    row.update(publisherProvenance="NOT_VERIFIED", labAuthority="NOT_VERIFIED",
                        tlsIdentity="NOT_VERIFIED", trustAttestationIntegrity="NOT_VERIFIED",
                        trustReason="Protected trust receipt signature or submission/transport binding failed.")
            normalized_path = storage.path(assessment_id, "normalized", submission + ".json")
            if normalized_path.is_file():
                normalized = read_json(normalized_path)
                digest = sha256_value({"normalized": normalized, "packageDigest": manifest["packageDigest"]})
                row["normalizedEvidenceBinding"] = "VERIFIED" if digest == analysis.get("evidenceSetDigest") else "NOT_VERIFIED"
            trusted = session.report_configuration.get("trustedCollectorBuildDigests", [])
            if row["receiptVerification"] != "NOT_EVALUATED":
                row["collectorBuildAllowlist"] = (
                    "VERIFIED" if valid and row["receiptVerification"] == "VERIFIED"
                    and manifest.get("collectorBuildDigest") in trusted
                    and manifest.get("collectionProfileDigest") == session.collection_profile_digest else "NOT_VERIFIED")
        except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile):
            # A later receipt/derivative error must not rewrite the outcome of
            # an archive check already performed successfully.
            if row["archiveIntegrity"] == "NOT_EVALUATED":
                row["archiveIntegrity"] = "NOT_VERIFIED"
            elif row["receiptVerification"] == "NOT_EVALUATED":
                row["receiptVerification"] = "NOT_VERIFIED"
            elif row["normalizedEvidenceBinding"] == "NOT_EVALUATED":
                row["normalizedEvidenceBinding"] = "NOT_VERIFIED"
            row["reason"] = "Recorded evidence could not be verified."
    return {
        "reportIntegrity": "NOT_EVALUATED",
        "reportIntegrityReason": "Verify the generated HTML and model against the separate integrity sidecar; this report cannot independently verify itself.",
        "evidencePackageIntegrity": _aggregate(value for row in rows for value in (
            row["archiveIntegrity"], row["receiptVerification"], row["normalizedEvidenceBinding"])),
        "collectorBuildTrusted": _aggregate(row["collectorBuildAllowlist"] for row in rows),
        "collectorBuildTrustScope": "Recorded session allowlist membership only. Independent publisher/Lab provenance is checked and displayed separately.",
        "publisherAuthenticity": _trust_summary(rows, "publisherProvenance"),
        "independentLabIdentity": "TRUST_ENROLLMENT_PENDING" if _trust_summary(rows, "labAuthority") == "NOT_EVALUATED" else _trust_summary(rows, "labAuthority"),
        "tlsIdentity": "SESSION_CERTIFICATE_PIN_RECORDED" if rows and all(row["tlsIdentity"] == "SESSION_CERTIFICATE_PIN_RECORDED" for row in rows) else _trust_summary(rows, "tlsIdentity"),
        "signedReceiptIntegrity": _aggregate(row["receiptVerification"] for row in rows),
        "endpointChecks": rows,
    }
