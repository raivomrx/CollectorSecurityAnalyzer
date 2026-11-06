"""Author immutable publisher metadata and independently signed session bundles."""
from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
from typing import Callable
from urllib.parse import urlsplit

from csa_console.canonical import sha256_bytes, sha256_file, sha256_value, write_canonical_json
from csa_console.collector_package import verify_collector_package
from csa_console.file_security import restrict_directory
from csa_lab.collector_executable import _package_zip

SESSION_DATA = frozenset({"session-config.json", "server-cert.pem", "offline-public.xml", "OPERATOR-INSTRUCTIONS.txt"})
SIGNER = Path(__file__).parent / "powershell" / "Sign-CSATrustObject.ps1"


def trust_bytes(value) -> bytes:
    """Serialize the signed schemas using the integer-only RFC 8785 subset."""
    def encode(item):
        if item is None or type(item) in {bool, int, str}:
            if type(item) is int and abs(item) > 9007199254740991:
                raise ValueError("CSA-TRUST-NUMBER")
            return json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        if isinstance(item, dict) and all(type(key) is str for key in item):
            keys = sorted(item, key=lambda key: key.encode("utf-16-be"))
            return "{" + ",".join(encode(key) + ":" + encode(item[key]) for key in keys) + "}"
        if isinstance(item, list):
            return "[" + ",".join(encode(child) for child in item) + "]"
        raise ValueError("CSA-TRUST-NUMBER")
    return encode(value).encode("utf-8", errors="strict")


def publisher_manifest(package_root: Path, bootstrap: Path, entry_point: Path, *,
                       key_id: str, version: str, commit: str, release_sequence: int,
                       issued_at: int, expires_at: int) -> bytes:
    """Called in the controlled publisher lane after final artifact signing."""
    package = verify_collector_package(package_root)
    files = [row for row in package["files"] if row["path"] not in SESSION_DATA]
    config = json.loads((package_root / "session-config.json").read_text(encoding="utf-8"))
    return trust_bytes({
        "objectType": "CSA_PUBLISHER_RELEASE", "schemaVersion": 1, "keyId": key_id,
        "issuedAt": issued_at, "expiresAt": expires_at, "releaseSequence": release_sequence,
        "version": version, "commit": commit, "bootstrapSha256": sha256_file(bootstrap),
        "bootstrapSize": bootstrap.stat().st_size, "entryPointSize": entry_point.stat().st_size,
        "entryPointSha256": sha256_file(entry_point), "files": files,
        "profiles": [{"profileId": config["collectionProfile"], "profileDigest": config["collectionProfileDigest"],
                      "privacyPolicyDigest": sha256_file(package_root / config["privacyPolicy"])}],
    })


def session_envelope(package_root: Path, publisher: bytes, *, key_id: str, lab_id: str,
                     recipient_id: str, envelope_id: str, nonce: str, issued_at: int,
                     maximum_bytes: int = 128 * 1024 * 1024, authorization_digest: str | None = None) -> tuple[bytes, bytes]:
    """Bind the existing session, TLS pin, profile, privacy and engine archive."""
    package = verify_collector_package(package_root)
    config = json.loads((package_root / "session-config.json").read_text(encoding="utf-8"))
    origin = urlsplit(config["serverUrl"])
    if (origin.scheme != "https" or not origin.hostname or origin.username or origin.password
            or origin.path or origin.query or origin.fragment):
        raise ValueError("CSA-TRUST-ORIGIN")
    for locator in (recipient_id, envelope_id, nonce):
        if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", locator):
            raise ValueError("CSA-TRUST-NONCE")
    expires = int(datetime.fromisoformat(config["expiresAt"].replace("Z", "+00:00")).timestamp())
    if not issued_at < expires <= issued_at + 86400:
        raise ValueError("CSA-TRUST-EXPIRED")
    if type(maximum_bytes) is not int or not 0 < maximum_bytes <= 128 * 1024 * 1024:
        raise ValueError("CSA-TRUST-SCOPE")
    archive = _package_zip(package_root)
    envelope = trust_bytes({
        "objectType": "CSA_LAB_SESSION", "schemaVersion": 2 if authorization_digest else 1, "keyId": key_id,
        "issuedAt": issued_at, "expiresAt": expires, "envelopeId": envelope_id, "nonce": nonce,
        "labId": lab_id, "recipientId": recipient_id, "assessmentId": config["assessmentId"],
        "sessionId": config["sessionId"], "origin": config["serverUrl"],
        "tlsFingerprint": config["serverCertificateFingerprint"], "mode": config["collectorMode"],
        "profileId": config["collectionProfile"], "profileDigest": config["collectionProfileDigest"],
        "privacyPolicyDigest": sha256_file(package_root / config["privacyPolicy"]),
        "publisherManifestDigest": sha256_bytes(publisher), "packageDigest": sha256_bytes(archive),
        "sessionManifestDigest": sha256_file(package_root / "trusted-manifest.json"),
        "submissionPolicy": {"transport": "HTTPS_OR_ENCRYPTED_OFFLINE", "maximumBytes": maximum_bytes,
                             "receiptRequired": True, **({"authorizationDigest": authorization_digest} if authorization_digest else {})},
    })
    return envelope, archive


def create_trusted_bundle(output: Path, package_root: Path, publisher: bytes, publisher_signature: bytes, *,
                          sign_session: Callable[[bytes], bytes], grant_store, session, network=False, authority=None, **scope) -> Path:
    """Publish a complete private handoff without mutating the original package."""
    output = output.resolve()
    if output.exists():
        raise ValueError("CSA-TRUST-OUTPUT")
    if not publisher_signature:
        raise ValueError("CSA-TRUST-SIGNATURE")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="trusted-bundle-", dir=output.parent) as directory:
        work = Path(directory)
        restrict_directory(work)
        package = work / "package"
        shutil.copytree(package_root, package)
        staged, envelope, build_digest = _create_trusted_bundle(work / "bundle", package, publisher, publisher_signature,
            sign_session=sign_session, grant_store=grant_store, session=session, network=network, **scope)
        try:
            if network and authority is None:
                raise ValueError("TRUST_ENROLLMENT_PENDING")
            provenance = authority.verify(staged) if authority is not None else None
            staged.replace(output)
            grant_store.finish_issue(session, envelope, build_digest=build_digest, provenance=provenance,
                bundle_path=output, network=network)
        except Exception:
            grant_store.fail_issue(session, scope["envelope_id"], "CSA-TRUST-ISSUANCE-PUBLISH")
            raise
    return output


def _create_trusted_bundle(output: Path, package_root: Path, publisher: bytes, publisher_signature: bytes, *,
                           sign_session: Callable[[bytes], bytes], grant_store, session, network=False, **scope):
    """Write a separate data-only handoff. Publisher code is never modified."""
    if output.exists():
        raise ValueError("CSA-TRUST-OUTPUT")
    configuration_path = package_root / "session-config.json"
    config = json.loads(configuration_path.read_text(encoding="utf-8"))
    if config.get("assessmentId") != session.assessment_id or config.get("sessionId") != session.session_id:
        raise ValueError("CSA-TRUST-SESSION")
    private_proof = secrets.token_urlsafe(32) if network else scope["nonce"]
    authorization_secret = secrets.token_urlsafe(32) if network else None
    config.update(trustedEnvelopeId=scope["envelope_id"], trustedEnvelopeNonce=private_proof)
    write_canonical_json(configuration_path, config)
    manifest_path = package_root / "trusted-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for row in manifest["files"]:
        if row["path"] == "session-config.json":
            row.update(sha256=sha256_file(configuration_path), size=configuration_path.stat().st_size)
    manifest["collectorBuildDigest"] = sha256_value(manifest["files"])
    write_canonical_json(manifest_path, manifest)
    envelope, archive = session_envelope(package_root, publisher,
        maximum_bytes=session.maximum_package_size,
        authorization_digest=sha256_bytes(private_proof.encode("ascii")) if network else None, **scope)
    value = json.loads(envelope)
    grant_store.begin_issue(session, value, private_proof=private_proof, authorization_secret=authorization_secret)
    try:
        signature = sign_session(envelope)
        if not signature:
            raise ValueError("CSA-TRUST-SIGNATURE")
        output.mkdir(parents=True)
        restrict_directory(output)
        files = {"publisher-manifest.json": publisher, "publisher-manifest.p7s": publisher_signature,
                 "session-envelope.json": envelope, "session-envelope.p7s": signature, "collector.zip": archive}
        if network:
            # Private out-of-band handoff, never served by the network endpoints.
            files["assessor-authorization.txt"] = authorization_secret.encode("ascii")
        for name, content in files.items():
            (output / name).write_bytes(content)
        return output, value, manifest["collectorBuildDigest"]
    except Exception:
        grant_store.fail_issue(session, scope["envelope_id"], "CSA-TRUST-ISSUANCE-SIGNING")
        raise


def sign_with_windows_store(content: bytes, thumbprint: str, work_root: Path, *,
                            publisher_certificate_sha256: str | None = None,
                            publisher_artifacts: tuple[Path, ...] = ()) -> bytes:
    """Use an already provisioned signing identity without exporting its key."""
    if not re.fullmatch(r"[A-Fa-f0-9]{40}", thumbprint):
        raise ValueError("CSA-TRUST-SIGNER")
    import os
    with tempfile.TemporaryDirectory(prefix="trust-sign-", dir=work_root) as directory:
        root = Path(directory)
        restrict_directory(root)
        source, target = root / "object.json", root / "object.p7s"
        source.write_bytes(content)
        command = [
            str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"),
            "-NoProfile", "-NonInteractive", "-File", str(SIGNER), "-InputPath", str(source),
            "-OutputPath", str(target), "-Thumbprint", thumbprint,
        ]
        if publisher_certificate_sha256 is not None:
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", publisher_certificate_sha256) or len(publisher_artifacts) != 2:
                raise ValueError("CSA-TRUST-PUBLISHER")
            verification = root / "publisher-verification.json"
            verification.write_bytes(trust_bytes({"certificateSha256": publisher_certificate_sha256,
                "artifacts": [str(path.resolve()) for path in publisher_artifacts]}))
            command.extend(["-PublisherVerificationPath", str(verification)])
        completed = subprocess.run(command, capture_output=True, timeout=60, check=False)
        if completed.returncode:
            raise ValueError("CSA-TRUST-SIGNING")
        return target.read_bytes()
