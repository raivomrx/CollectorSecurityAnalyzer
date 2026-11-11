"""Approved ADR 5682: private one-use assessor handoff, never a public trust root."""
import base64
from datetime import datetime, timedelta, timezone
import ipaddress
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from csa_console.canonical import sha256_bytes, sha256_file
from csa_console.file_security import restrict_directory
from csa_console.trust_evidence import VerifiedTrustEvidence
from csa_console.trusted_grants import TrustedGrantStore
from csa_console.collector_package import COLLECTOR_VERSION
from csa_lab.trusted_distribution import publisher_manifest, _create_trusted_bundle, trust_bytes


def bootstrap_directory():
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "trusted-collector"
    return Path(__file__).resolve().parents[1] / "build/trusted-collector"


def pilot_commands(folder, approval_digest, exe_digest):
    if (not isinstance(folder, str) or not re.fullmatch(r"[A-Za-z]:\\[A-Za-z0-9 _\\.\-]+", folder)
            or any(part == ".." for part in folder.split("\\"))):
        raise ValueError("Use a simple absolute Windows folder path without shell metacharacters")
    for digest in (approval_digest, exe_digest):
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
            raise ValueError("CSA-PILOT-INDEPENDENT-HASH-REQUIRED")
    folder = folder.rstrip("\\")
    exe = folder + r"\CSA-TrustedCollector.exe"
    commands = {}
    for quick in (False, True):
        script = ("$p='"+exe+"';$f=[IO.File]::Open($p,'Open','Read','Read');try{"
            "$h=[Security.Cryptography.SHA256]::Create();try{$d='sha256:'+"
            "([BitConverter]::ToString($h.ComputeHash($f))).Replace('-','').ToLowerInvariant()}"
            "finally{$h.Dispose()};if($d -cne '"+exe_digest+"'){throw 'CSA-PILOT-EXE-HASH'};"
            "& $p --assessor-pilot --bundle '"+folder+"' --approval-sha256 '"+approval_digest+"'"+
            (" --quick-run" if quick else "")+";exit $LASTEXITCODE}finally{$f.Dispose()}")
        commands["quick" if quick else "standard"] = (
            "powershell.exe -NoProfile" + (" -ExecutionPolicy Bypass" if quick else "") + ' -Command "'+script+'"')
    commands["exe"] = ('"'+exe+'" --assessor-pilot --bundle "'+folder+
        '" --approval-sha256 '+approval_digest+" --quick-run")
    return commands


class AssessorAuthority:
    def __init__(self, executable, expected_approval):
        self.executable, self.expected_approval = Path(executable), expected_approval

    def verify(self, bundle):
        result = subprocess.run([str(self.executable), "--inspect-assessor-pilot", str(bundle),
            "--approval-sha256", self.expected_approval], capture_output=True, text=True, timeout=90,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if result.returncode:
            raise ValueError("CSA-PILOT-VERIFICATION-FAILED")
        record = json.loads(result.stdout)
        if record.get("assurance") != "ASSESSOR_VERIFIED_PILOT":
            raise ValueError("CSA-PILOT-ASSURANCE")
        return VerifiedTrustEvidence(record["assurance"], record["facts"])


def _identity(role, now, expiry):
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CSA private assessor " + role)])
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(datetime.fromtimestamp(now-120, timezone.utc))
        .not_valid_after(datetime.fromtimestamp(expiry+120, timezone.utc)).sign(key, hashes.SHA256()))
    row = {"keyId": "assessor-"+role, "spkiSha256": sha256_bytes(key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)),
        "issuedAt": now-60, "expiresAt": expiry, "revoked": False}
    if role == "publisher":
        row["certificateSha256"] = sha256_bytes(certificate.public_bytes(serialization.Encoding.DER))
    def sign(content):
        return (pkcs7.PKCS7SignatureBuilder().set_data(content).add_signer(certificate, key, hashes.SHA256()).sign(
            serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary]))
    return row, sign


def issue_assessor_pilot(service, assessment_id, request):
    required = {"recipientId", "endpointBinding", "sourceAddress", "approvedBy", "customerApprovalReference",
                "assessorApprovalReference", "independentChannelReference", "riskAccepted"}
    if (set(request) != required or request.get("riskAccepted") is not True
            or any(not isinstance(request.get(key), str) for key in required-{"riskAccepted"})):
        raise ValueError("CSA-PILOT-APPROVAL-REQUIRED")
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", request["recipientId"]) or not re.fullmatch(r"sha256:[a-f0-9]{64}", request["endpointBinding"]):
        raise ValueError("CSA-PILOT-ENDPOINT")
    for key in ("approvedBy", "customerApprovalReference", "assessorApprovalReference", "independentChannelReference"):
        if not 1 <= len(request[key]) <= 160 or any(ord(char)<32 for char in request[key]):
            raise ValueError("CSA-PILOT-APPROVAL-REQUIRED")
    try:
        source = str(ipaddress.ip_address(request["sourceAddress"]))
    except ValueError:
        raise ValueError("CSA-PILOT-SOURCE-ADDRESS") from None
    state = service.load_state(assessment_id)
    session = service.sessions.load_session(assessment_id, state.session_id)
    from csa_console.sessions import _parse_utc
    from csa_console.network import source_is_allowed
    now = int(time.time())
    expiry = min(int(_parse_utc(session.expires_at).timestamp()), now+7200)
    if expiry <= now+60 or session.status.value != "OPEN" or not source_is_allowed(session, source):
        raise ValueError("CSA-PILOT-SESSION")
    source_root = bootstrap_directory()
    executable, entry = source_root/"CSA-TrustedCollector.exe", source_root/"Start-CSATrustedCollector.ps1"
    if not executable.is_file() or not entry.is_file():
        raise ValueError("CSA-PILOT-BUILD-REQUIRED")
    package_root = Path(state.collector_path).parent/"package"
    publisher, sign_publisher = _identity("publisher", now, expiry)
    lab, sign_lab = _identity("lab", now, expiry)
    config = json.loads((package_root/"session-config.json").read_bytes())
    lab_id = "LAB-" + secrets.token_hex(12)
    lab.update(labId=lab_id, origin=config["serverUrl"], tlsFingerprint=session.tls_fingerprint)
    policy = {"objectType":"CSA_TRUST_POLICY", "schemaVersion":1, "issuedAt":now-60, "expiresAt":expiry,
              "revocationFreshUntil":expiry, "minimumReleaseSequence":1, "endpointId":request["recipientId"],
              "publishers":[publisher], "labs":[lab]}
    release = publisher_manifest(package_root, executable, entry, key_id=publisher["keyId"], version=COLLECTOR_VERSION,
        commit=config.get("collectorBuildCommit") or "0"*40, release_sequence=1, issued_at=now-30, expires_at=expiry)
    envelope_id = "PILOT-" + secrets.token_urlsafe(24)
    output = service.storage.path(assessment_id, "pilot-handoffs", envelope_id)
    output.parent.mkdir(parents=True, exist_ok=True)
    store = TrustedGrantStore(service.storage)
    try:
        with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
            work = Path(temporary); restrict_directory(work)
            package = work/"package"; shutil.copytree(package_root, package)
            bundle, envelope, build = _create_trusted_bundle(work/"bundle", package, release, sign_publisher(release),
                sign_session=sign_lab, grant_store=store, session=session, network=False, key_id=lab["keyId"],
                lab_id=lab_id, recipient_id=request["recipientId"], envelope_id=envelope_id,
                nonce=secrets.token_urlsafe(32), issued_at=now-30)
            # Session may last longer than the pilot; the independent approval ends earlier.
            approval = {"objectType":"CSA_ASSESSOR_PILOT", "schemaVersion":1, "issuedAt":now-30, "expiresAt":expiry,
                "approvedAt":now, "sourceAddress":source, "assurance":"ASSESSOR_VERIFIED_PILOT", **{key:request[key] for key in ("approvedBy",
                "customerApprovalReference", "assessorApprovalReference", "independentChannelReference", "endpointBinding")},
                "policy":policy, "publisherManifestDigest":sha256_bytes(release),
                "sessionEnvelopeDigest":sha256_file(bundle/"session-envelope.json"), "packageDigest":envelope["packageDigest"],
                "publisherSignatureDigest":sha256_file(bundle/"publisher-manifest.p7s"),
                "sessionSignatureDigest":sha256_file(bundle/"session-envelope.p7s")}
            approval_bytes = trust_bytes(approval); digest = sha256_bytes(approval_bytes)
            (bundle/"pilot-approval.json").write_bytes(approval_bytes)
            shutil.copy2(executable, bundle/executable.name); shutil.copy2(entry, bundle/entry.name)
            proof = AssessorAuthority(executable, digest).verify(bundle)
            bundle.replace(output)
            store.finish_issue(session, envelope, build_digest=build, provenance=proof, bundle_path=output,
                               approved_sources=[source])
    except Exception:
        store.fail_issue(session, envelope_id, "CSA-PILOT-ISSUANCE-FAILED")
        raise
    service._audit(assessment_id).append("assessor_pilot_handoff_prepared", {
        "envelopeId":envelope_id, "assurance":"ASSESSOR_VERIFIED_PILOT", "approvalDigest":digest,
        "expiresAt":expiry, "endpointBinding":request["endpointBinding"],
        "sourceAddressDigest":sha256_bytes(source.encode()), "approvalRecordDigest":sha256_bytes(trust_bytes(request)),
        "publicRelease":"HOLD"})
    return {"state":"PRIVATE_HANDOFF_PREPARED", "assurance":"ASSESSOR_VERIFIED_PILOT", "handoffId":envelope_id,
        "approvalSha256":digest, "exeSha256":sha256_file(executable), "entrySha256":sha256_file(entry),
        "expiresAt":expiry, "publicRelease":"HOLD",
        "instruction":"Independently compare approval and EXE fingerprints, deliver privately, then run as standard user. New invitation for each run. Delete the private handoff after receipt/export."}
