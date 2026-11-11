"""Local assessor preflight. Observations never enroll or approve an identity."""
import json
from datetime import datetime, timezone
from pathlib import Path
import re
import time

from csa_console.canonical import sha256_value
from csa_console.sessions import _parse_utc
from csa_console.trusted_grants import TrustedGrantStore
from csa_lab.trust_authority import NativeTrustAuthority, known_folder, require_protected_path


GROUPS = {
    "publisher": "Approve Publisher legal identity, signing certificate, key custody and independently checked certificate/SPKI pins.",
    "lab": "Independently approve the Lab signing key and provision its recipient policy.",
    "tls": "Check the exact Lab origin and session TLS fingerprint through the independent channel.",
    "channel": "Approve the managed delivery or assessor handoff channel and retain its evidence.",
    "authorization": "Record assessor and customer approval references, approver, UTC approval time, endpoint scope and expiry.",
    "build": "Sign final immutable EXE/PS bytes and issue a verified session bundle for this exact build/profile.",
    "liveAcceptance": "Record real HOME and LAB acceptance of this candidate; synthetic tests do not satisfy this gate.",
}


def inspect_pilot(service, assessment_id, recipient_id=""):
    state = service.load_state(assessment_id)
    session = service.sessions.load_session(assessment_id, state.session_id)
    expired = _parse_utc(session.expires_at).timestamp() <= time.time()
    result = {"state": "SESSION_EXPIRED" if expired else "SETUP_REQUIRED",
        "trustState": "TRUST_ENROLLMENT_PENDING", "publicRelease": "HOLD",
        "exe": "BLOCKED", "quickRun": "BLOCKED", "customerPilotPermitted": False,
        "oneTimeSetup": "Administrator or independently approved managed deployment must provision the immutable launcher and protected policy first. The Collector engine is temporary; collection runs as standard user.",
        "expiresAt": session.expires_at, "profile": session.collection_profile,
        "checks": [{"id": key, "status": "PENDING", "remediation": text} for key, text in GROUPS.items()],
        "approvals": {}, "verifiedInvitations": [], "diagnosticCode": "TRUST_ENROLLMENT_PENDING"}
    if recipient_id and not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", recipient_id):
        raise ValueError("Invalid recipient identifier")
    if not recipient_id:
        result["diagnosticCode"] = "PILOT_RECIPIENT_REQUIRED"
        return result
    store = TrustedGrantStore(service.storage)
    if store._path(session).is_file():
        with store._transaction(session) as connection:
            candidates = [dict(row) for row in connection.execute(
                "SELECT * FROM grants WHERE operationState='READY' AND used=0 AND recipientId=? AND expiresAt>?",
                (recipient_id, time.time()))]
        for row in candidates:
            saved = json.loads(row["provenance"] or "{}")
            if saved.get("assurance") != "ASSESSOR_VERIFIED_PILOT":
                continue
            try:
                from csa_lab.assessor_pilot import AssessorAuthority, bootstrap_directory
                proof = AssessorAuthority(bootstrap_directory()/"CSA-TrustedCollector.exe",
                    saved["facts"]["approvalDigest"]).verify(Path(row["bundlePath"]))
                if proof.record() != saved:
                    continue
                result.update(state="PRIVATE_HANDOFF_PREPARED", trustState="ASSESSOR_VERIFIED_PILOT",
                    exe="READY_AFTER_INDEPENDENT_COMPARISON", quickRun="READY_AFTER_INDEPENDENT_COMPARISON",
                    customerPilotPermitted=True, diagnosticCode="VERIFY_PRIVATE_HANDOFF_AT_ENDPOINT",
                    oneTimeSetup="No administrator or predeployment required for the approved private pilot. Independently check the EXE and approval fingerprints, unpack the private handoff, then choose EXE or Quick Run. Windows controls remain enforced. Production signing and real HOME/LAB acceptance remain separate.")
                result["verifiedInvitations"] = [{"envelopeId":row["envelopeId"],"approvalDigest":saved["facts"]["approvalDigest"]}]
                approval=json.loads((Path(row["bundlePath"])/"pilot-approval.json").read_bytes())
                result["approvals"]={key:approval[key] for key in ("approvedBy","customerApprovalReference","assessorApprovalReference","independentChannelReference")}
                for check in result["checks"]:
                    check["status"] = "ASSESSOR_APPROVED_PRIVATE_PILOT" if check["id"] != "liveAcceptance" else "LIVE_ACCEPTANCE_PENDING"
                return result
            except (OSError, ValueError, KeyError, TypeError):
                continue
    authority = NativeTrustAuthority.for_recipient(recipient_id)
    # Merely finding a local file is never proof that its contents are trusted.
    paths = [authority.policy_path, authority.approval_path,
             known_folder(0x26) / "CSA/Collector/CSA-TrustedCollector.exe",
             known_folder(0x26) / "CSA/Collector/Start-CSATrustedCollector.ps1"]
    missing = [name for path, name in zip(paths, ("RECIPIENT_POLICY", "INDEPENDENT_APPROVAL", "IMMUTABLE_EXE", "SIGNED_PS_ENTRY")) if not path.is_file()]
    if missing:
        result["diagnosticCode"] = "PILOT_PROVISIONING_MISSING"
        result["missingComponents"] = missing
        return result
    try:
        for path in paths:
            require_protected_path(path)
        approval = json.loads(authority.approval_path.read_text("utf-8"))
        validate_pilot_authorization(approval, session, recipient_id)
        result["approvals"] = {key: approval[key] for key in
            ("approvedBy", "approvedAt", "assessorApprovalReference", "customerApprovalReference")}
        result["approvalDigest"] = sha256_value(approval)
        store = TrustedGrantStore(service.storage)
        for row in store.network_records(session):
            if row["recipientId"] != recipient_id:
                continue
            proof = authority.verify(Path(row["bundlePath"]))
            if proof.assurance != "REAL" or proof.record() != json.loads(row["provenance"] or "{}"):
                continue
            envelope = json.loads((Path(row["bundlePath"]) / "session-envelope.json").read_bytes())
            proof.bind(session, envelope)
            if proof.facts["expiresAt"] <= time.time():
                continue
            result["verifiedInvitations"].append({key: proof.facts[key] for key in
                ("envelopeId", "recipientId", "publisherManifestDigest", "collectorBuildDigest", "policyDigest", "approvalDigest", "expiresAt")})
        if result["verifiedInvitations"] and not expired:
            result.update(state="PILOT_READY", trustState="REAL", exe="READY", quickRun="READY",
                          customerPilotPermitted=True, diagnosticCode="PILOT_READY")
            for check in result["checks"]:
                check["status"] = "VERIFIED_INDEPENDENT_APPROVAL"
        else:
            result["diagnosticCode"] = "PILOT_VERIFIED_INVITATION_REQUIRED"
    except (OSError, ValueError, KeyError, TypeError):
        # Do not echo untrusted policy fields, paths or parser exceptions.
        result["diagnosticCode"] = "PILOT_INDEPENDENT_VERIFICATION_FAILED"
    return result


def validate_pilot_authorization(approval, session, recipient_id):
    import ipaddress
    sources = approval.get("approvedSourceAddresses")
    if not isinstance(sources, list) or not 1 <= len(sources) <= 32 or not all(isinstance(item, str) for item in sources):
        raise ValueError("PILOT_SOURCE_SCOPE_REQUIRED")
    for item in sources:
        ipaddress.ip_address(item)
    for key in ("approvedBy", "assessorApprovalReference", "customerApprovalReference"):
        value = approval.get(key)
        if (not isinstance(value, str) or not 1 <= len(value) <= 160
                or any(ord(char) < 32 for char in value)
                or re.search("PENDING|UNKNOWN|PLACEHOLDER|TEST_ONLY", value, re.I)):
            raise ValueError("PILOT_APPROVAL_REQUIRED")
    now = time.time()
    if (type(approval.get("approvedAt")) is not int or not 0 < approval["approvedAt"] <= now
            or type(approval.get("expiresAt")) is not int or approval["expiresAt"] <= now
            or approval["approvedAt"] > approval["expiresAt"]):
        raise ValueError("PILOT_APPROVAL_EXPIRED")
    for key, expected in {"assessmentId": session.assessment_id, "sessionId": session.session_id,
                          "recipientId": recipient_id, "tlsFingerprint": session.tls_fingerprint}.items():
        if approval.get(key) != expected:
            raise ValueError("PILOT_APPROVAL_SCOPE")


def handoff_markdown(result):
    # Export contains only the explicit operator view, never raw policies/secrets.
    lines = ["# PILOT_GO_NO_GO", "", "Public release: HOLD", "",
             "| Transport | State |", "|---|---|",
             f"| EXE | {result['exe']} |", f"| Quick Run | {result['quickRun']} |", "",
             f"Customer pilot permitted: {result['customerPilotPermitted']}",
             f"Diagnostic: {result['diagnosticCode']}", f"Session expires (UTC): {result['expiresAt']}",
             "", result["oneTimeSetup"], "", "## Independent approval record", ""]
    for key, value in result["approvals"].items():
        lines.append(f"- {key}: " + json.dumps(value, ensure_ascii=False))
    for check in result["checks"]:
        lines.append(f"- {check['id']}: {check['status']}. {check['remediation']}")
    lines += ["", "Generated (UTC): " + datetime.now(timezone.utc).isoformat(),
              "", "If blocked, contact the assessor/IT owner. Do not disable endpoint protection or change persistent policy.",
              "No clean HOME/LAB execution is implied by this preflight. Preserve independent primary acceptance evidence."]
    return "\n".join(lines) + "\n"
