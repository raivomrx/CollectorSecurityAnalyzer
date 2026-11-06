"""Server-produced, signed provenance bound to accepted evidence and receipt."""
import logging

from csa_console.canonical import sha256_value
from csa_console.identifiers import utc_text
from csa_console.receipts import sign_receipt, verify_receipt
from csa_console.trusted_grants import TrustedGrantStore
from csa_console.audit import ConsoleAuditLog


def record_accepted_provenance(storage, session, package, receipt, transport):
    """A provenance write error cannot turn an already signed acceptance into a rejection."""
    try:
        return record_trust_receipt(storage, session, package, receipt, transport)
    except (OSError, ValueError, TypeError, KeyError):
        submission = receipt["submissionId"]
        logging.getLogger(__name__).warning("CSA-TRUST-RECORD-WRITE submission=%s", submission)
        try:
            ConsoleAuditLog(storage.path(session.assessment_id, "audit", "audit.jsonl")).append(
                "post_acceptance_trust_record_failed", {"sessionId": session.session_id,
                    "submissionId": submission, "stage": "POST_ACCEPTANCE_TRUST_RECORD",
                    "eventClass": "ACCEPTED", "code": "CSA-TRUST-RECORD-WRITE"})
        except (OSError, ValueError):
            logging.getLogger(__name__).warning("CSA-AUDIT-WRITE-FAILED stage=POST_ACCEPTANCE_TRUST_RECORD submission=%s", submission)
        return "NOT_EVALUATED"


def record_trust_receipt(storage, session, package, receipt, transport):
    source = TrustedGrantStore(storage).submission_provenance(session, receipt["submissionId"], transport)
    if source is None:
        return "NOT_EVALUATED"
    facts = source["verification"]["facts"]
    if (source["buildDigest"] != package.manifest["collectorBuildDigest"]
            or facts["assessmentId"] != session.assessment_id or facts["sessionId"] != session.session_id
            or facts["envelopeId"] != source["envelopeId"] or facts["profileDigest"] != session.collection_profile_digest):
        raise ValueError("CSA-TRUST-ATTESTATION-SCOPE")
    record = {
        "objectType": "CSA_SUBMISSION_TRUST_RECEIPT", "schemaVersion": 1,
        "assessmentId": session.assessment_id, "sessionId": session.session_id,
        "submissionId": receipt["submissionId"], "envelopeId": source["envelopeId"],
        "evidencePackageDigest": package.package_digest, "acceptedReceiptDigest": sha256_value(receipt),
        "collectorBuildDigest": source["buildDigest"], "transport": transport,
        "assurance": source["verification"]["assurance"], "provenance": facts,
        "authorization": source["authorization"], "requestedExecutionMode": source["requestedExecutionMode"],
        "executionModeEvidence": "CLIENT_REQUEST_NOT_POLICY_ATTESTATION", "recordedAt": utc_text(),
        "verificationScope": "SERVER_VERIFIED_AUTHORIZED_PROVENANCE_NOT_REMOTE_EXECUTION_ATTESTATION",
    }
    record["serverSignature"] = sign_receipt(record, session.tls_private_key_path)
    storage.write_json(session.assessment_id, ("submissions", "accepted", receipt["submissionId"] + ".trust.json"), record)
    ConsoleAuditLog(storage.path(session.assessment_id, "audit", "audit.jsonl")).append("submission_trust_recorded", {
        "sessionId": session.session_id, "submissionId": receipt["submissionId"], "envelopeId": source["envelopeId"],
        "assurance": record["assurance"], "trustReceiptDigest": sha256_value(record), "transport": transport})
    return record["assurance"]


def verify_trust_receipt(record, *, session, receipt, manifest, transport, source):
    if (source is None or source.get("envelopeId") != record.get("envelopeId")
            or source.get("verification", {}).get("assurance") != record.get("assurance")
            or sha256_value(source.get("verification", {}).get("facts", {})) != sha256_value(record.get("provenance", {}))):
        return False
    if (record.get("objectType") != "CSA_SUBMISSION_TRUST_RECEIPT" or record.get("schemaVersion") != 1
            or not verify_receipt(record, session.tls_certificate_path)):
        return False
    expected = {"assessmentId": session.assessment_id, "sessionId": session.session_id,
        "submissionId": manifest["submissionId"], "evidencePackageDigest": manifest["packageDigest"],
        "collectorBuildDigest": manifest["collectorBuildDigest"], "acceptedReceiptDigest": sha256_value(receipt), "transport": transport}
    if any(record.get(key) != value for key, value in expected.items()):
        return False
    facts = record.get("provenance", {})
    return (record.get("assurance") in {"REAL", "TEST_ONLY"}
        and facts.get("assessmentId") == session.assessment_id and facts.get("sessionId") == session.session_id
        and facts.get("envelopeId") == record.get("envelopeId")
        and facts.get("collectorBuildDigest") == manifest["collectorBuildDigest"]
        and facts.get("profileDigest") == manifest["collectionProfileDigest"]
        and facts.get("tlsFingerprint") == session.tls_fingerprint
        and record.get("verificationScope") == "SERVER_VERIFIED_AUTHORIZED_PROVENANCE_NOT_REMOTE_EXECUTION_ATTESTATION")
