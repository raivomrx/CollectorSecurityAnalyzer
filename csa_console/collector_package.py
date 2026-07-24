"""Generate and verify session-bound Windows Collector packages."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from csa_console.canonical import (
    read_json,
    sha256_file,
    sha256_value,
    write_canonical_json,
)
from csa_console.capabilities import (
    DEFAULT_PROFILE_PATH,
    CollectionProfile,
)
from csa_console.identifiers import utc_text
from csa_console.models import AssessmentSession

ROOT = Path(__file__).resolve().parents[1]
COLLECTOR_SOURCE = ROOT / "collector" / "windows"


class CollectorPackageError(ValueError):
    """Report an invalid or unsafe Collector package."""


def create_collector_package(
    session: AssessmentSession,
    enrollment_token: str,
    output_directory: str | Path,
    server_url: str | None = None,
) -> Path:
    """Create a minimal trusted-script package for one session."""

    if not session.tls_certificate_path or not session.tls_fingerprint:
        raise CollectorPackageError("Session TLS identity is incomplete")
    if not session.offline_public_key_path:
        raise CollectorPackageError("Session offline public key is unavailable")
    destination = Path(output_directory).resolve()
    if destination.exists() and any(destination.iterdir()):
        raise CollectorPackageError("Collector package output is not empty")
    destination.mkdir(parents=True, exist_ok=True)
    collector_destination = destination / "collector"
    collector_destination.mkdir()
    shutil.copy2(
        COLLECTOR_SOURCE / "Collect-CSAWindowsEvidence.ps1",
        collector_destination / "Collect-CSAWindowsEvidence.ps1",
    )
    shutil.copy2(
        COLLECTOR_SOURCE / "evidence-manifest.json",
        collector_destination / "evidence-manifest.json",
    )
    shutil.copy2(
        COLLECTOR_SOURCE / "collection-capabilities.json",
        collector_destination / "collection-capabilities.json",
    )
    shutil.copytree(
        COLLECTOR_SOURCE / "modules", collector_destination / "modules"
    )
    shutil.copytree(
        COLLECTOR_SOURCE / "profiles", collector_destination / "profiles"
    )
    shutil.copy2(
        COLLECTOR_SOURCE / "Invoke-CSACollector.ps1",
        destination / "Invoke-CSACollector.ps1",
    )
    shutil.copy2(
        session.tls_certificate_path, destination / "server-cert.pem"
    )
    shutil.copy2(
        session.offline_public_key_path, destination / "offline-public.xml"
    )
    profile = CollectionProfile.load(DEFAULT_PROFILE_PATH)
    target_url = server_url or (
        f"https://{session.listen_address}:{session.listen_port}"
    )
    if not target_url.casefold().startswith("https://"):
        raise CollectorPackageError("Collector server URL must use HTTPS")
    configuration = {
        "schemaVersion": "5.0",
        "assessmentId": session.assessment_id,
        "sessionId": session.session_id,
        "assessmentName": session.assessment_name,
        "customerReference": session.customer_reference,
        "collectorMode": session.collector_mode.value,
        "collectionProfile": session.collection_profile,
        "collectionProfileDigest": session.collection_profile_digest,
        "serverUrl": target_url.rstrip("/"),
        "serverCertificateFingerprint": session.tls_fingerprint,
        "enrollmentToken": enrollment_token,
        "expiresAt": session.expires_at,
        "activeValidation": False,
        "privacyPolicy": "collector/profiles/privacy-default.json",
        "offlinePublicKey": "offline-public.xml",
    }
    write_canonical_json(destination / "session-config.json", configuration)
    instructions = (
        "CSA Windows Endpoint Collector\n"
        f"Assessment: {session.assessment_name}\n"
        f"Organization reference: {session.customer_reference}\n"
        "Collector mode: STANDARD USER\n"
        "Administrator rights required: NO\n"
        "Active security testing: NO\n\n"
        "Run from a non-elevated PowerShell process:\n"
        "powershell.exe -NoProfile -ExecutionPolicy Bypass "
        "-File .\\Invoke-CSACollector.ps1\n"
    )
    (destination / "OPERATOR-INSTRUCTIONS.txt").write_text(
        instructions, encoding="utf-8"
    )
    trusted_files = [
        path
        for path in destination.rglob("*")
        if path.is_file() and path.name != "trusted-manifest.json"
    ]
    file_entries = [
        {
            "path": path.relative_to(destination).as_posix(),
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
        }
        for path in sorted(
            trusted_files, key=lambda value: value.relative_to(destination).as_posix()
        )
    ]
    collector_build_digest = sha256_value(file_entries)
    manifest: dict[str, Any] = {
        "schemaVersion": "5.0",
        "assessmentId": session.assessment_id,
        "sessionId": session.session_id,
        "collectionProfile": profile.profile_id,
        "collectionProfileDigest": profile.digest,
        "collectorBuildDigest": collector_build_digest,
        "serverCertificateFingerprint": session.tls_fingerprint,
        "expiration": session.expires_at,
        "createdAt": utc_text(),
        "files": file_entries,
    }
    write_canonical_json(destination / "trusted-manifest.json", manifest)
    return destination


def verify_collector_package(package_root: str | Path) -> dict[str, Any]:
    """Verify every allowlisted Collector package file digest."""

    root = Path(package_root).resolve()
    manifest = read_json(root / "trusted-manifest.json")
    files = manifest.get("files")
    if not isinstance(files, list):
        raise CollectorPackageError("Trusted manifest files must be a list")
    declared: set[str] = set()
    for item in files:
        if not isinstance(item, dict):
            raise CollectorPackageError("Trusted manifest file entry is invalid")
        relative = str(item.get("path", ""))
        if not relative or relative in declared:
            raise CollectorPackageError("Trusted manifest path is missing or duplicate")
        declared.add(relative)
        candidate = (root / Path(relative)).resolve()
        if root not in candidate.parents or not candidate.is_file():
            raise CollectorPackageError(f"Trusted file is missing: {relative}")
        if sha256_file(candidate) != item.get("sha256"):
            raise CollectorPackageError(f"Trusted file digest mismatch: {relative}")
        if candidate.stat().st_size != item.get("size"):
            raise CollectorPackageError(f"Trusted file size mismatch: {relative}")
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "trusted-manifest.json"
    }
    if actual != declared:
        raise CollectorPackageError("Collector package contains undeclared files")
    if sha256_value(files) != manifest.get("collectorBuildDigest"):
        raise CollectorPackageError("Collector build digest is invalid")
    return manifest
