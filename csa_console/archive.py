"""Encrypted, verifiable assessment archive export."""

from __future__ import annotations

import base64
import io
import json
import os
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from csa_console.audit import ConsoleAuditLog
from csa_console.canonical import (
    canonical_bytes,
    canonical_json,
    sha256_bytes,
)
from csa_console.identifiers import utc_text
from csa_console.storage import AssessmentStorage

ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


class AssessmentArchiveError(ValueError):
    """Report invalid, tampered or undecryptable assessment archives."""


def export_assessment_archive(
    storage: AssessmentStorage,
    assessment_id: str,
    output_path: str | Path,
    passphrase: str,
) -> Path:
    """Export an assessment as a password-encrypted deterministic archive."""

    if len(passphrase) < 12:
        raise AssessmentArchiveError("Archive passphrase must be at least 12 characters")
    root = storage.assessment_path(assessment_id)
    audit = ConsoleAuditLog(storage.path(assessment_id, "audit", "audit.jsonl"))
    audit.append("assessment_export_started", {"assessmentId": assessment_id})
    files = [
        path
        for path in root.rglob("*")
        if path.is_file() and "exports" not in path.relative_to(root).parts
    ]
    entries = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": sha256_bytes(path.read_bytes()),
            "size": path.stat().st_size,
        }
        for path in sorted(files, key=lambda item: item.relative_to(root).as_posix())
    ]
    audit_summary = audit.verify()
    manifest = {
        "schemaVersion": "5.0",
        "assessmentId": assessment_id,
        "createdAt": utc_text(),
        "files": entries,
        "finalAuditEntryHash": audit_summary["finalAuditEntryHash"],
        "evidenceSetDigest": sha256_bytes(canonical_bytes(entries)),
    }
    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(
        archive_buffer, "w", zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for entry in entries:
            info = zipfile.ZipInfo(entry["path"], ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, root.joinpath(entry["path"]).read_bytes())
        info = zipfile.ZipInfo("archive-manifest.json", ZIP_TIMESTAMP)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o600 << 16
        archive.writestr(info, canonical_bytes(manifest))
    plaintext = archive_buffer.getvalue()
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(passphrase, salt)
    associated = canonical_bytes(
        {"schemaVersion": "5.0", "assessmentId": assessment_id}
    )
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated)
    envelope = {
        "schemaVersion": "5.0",
        "algorithm": "SCRYPT+A256GCM",
        "assessmentId": assessment_id,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "plaintextDigest": sha256_bytes(plaintext),
    }
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise AssessmentArchiveError("Assessment archive output already exists")
    output.write_bytes(canonical_bytes(envelope))
    output.chmod(0o600)
    audit.append(
        "assessment_exported",
        {
            "assessmentId": assessment_id,
            "archiveDigest": sha256_bytes(output.read_bytes()),
        },
    )
    return output


def verify_assessment_archive(
    path: str | Path,
    passphrase: str,
) -> dict[str, Any]:
    """Decrypt and verify every assessment archive entry in memory."""

    raw = Path(path).read_bytes()
    try:
        text = raw.decode("utf-8")
        envelope = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssessmentArchiveError("Assessment archive envelope is invalid") from error
    if canonical_json(envelope) != text:
        raise AssessmentArchiveError("Assessment archive envelope is not canonical")
    if envelope.get("algorithm") != "SCRYPT+A256GCM":
        raise AssessmentArchiveError("Assessment archive algorithm is unsupported")
    try:
        salt = base64.b64decode(envelope["salt"], validate=True)
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
    except (KeyError, ValueError) as error:
        raise AssessmentArchiveError("Assessment archive encoding is invalid") from error
    associated = canonical_bytes(
        {
            "schemaVersion": "5.0",
            "assessmentId": envelope.get("assessmentId"),
        }
    )
    try:
        plaintext = AESGCM(_derive_key(passphrase, salt)).decrypt(
            nonce, ciphertext, associated
        )
    except Exception as error:
        raise AssessmentArchiveError(
            "Assessment archive authentication failed"
        ) from error
    if sha256_bytes(plaintext) != envelope.get("plaintextDigest"):
        raise AssessmentArchiveError("Assessment archive plaintext digest mismatch")
    try:
        archive = zipfile.ZipFile(io.BytesIO(plaintext))
    except zipfile.BadZipFile as error:
        raise AssessmentArchiveError("Assessment archive payload is invalid") from error
    with archive:
        infos = archive.infolist()
        names = [item.filename for item in infos]
        if len(names) != len(set(names)) or "archive-manifest.json" not in names:
            raise AssessmentArchiveError("Assessment archive file set is invalid")
        if len(names) > 10000:
            raise AssessmentArchiveError("Assessment archive contains too many files")
        total_size = 0
        for info in infos:
            path_value = PurePosixPath(info.filename)
            mode = info.external_attr >> 16
            if (
                path_value.is_absolute()
                or ".." in path_value.parts
                or "\\" in info.filename
                or stat.S_ISLNK(mode)
                or info.is_dir()
            ):
                raise AssessmentArchiveError("Assessment archive contains an unsafe path")
            total_size += info.file_size
            if total_size > 2 * 1024 * 1024 * 1024:
                raise AssessmentArchiveError(
                    "Assessment archive exceeds the extraction limit"
                )
        manifest_bytes = archive.read("archive-manifest.json")
        manifest = json.loads(manifest_bytes)
        if canonical_bytes(manifest) != manifest_bytes:
            raise AssessmentArchiveError("Assessment archive manifest is not canonical")
        declared = manifest.get("files")
        if not isinstance(declared, list):
            raise AssessmentArchiveError("Assessment archive file manifest is invalid")
        if {item["path"] for item in declared} != set(names) - {
            "archive-manifest.json"
        }:
            raise AssessmentArchiveError("Assessment archive file manifest is incomplete")
        for item in declared:
            value = archive.read(item["path"])
            if (
                len(value) != item["size"]
                or sha256_bytes(value) != item["sha256"]
            ):
                raise AssessmentArchiveError(
                    f"Assessment archive entry is invalid: {item['path']}"
                )
        _verify_archived_audit(
            archive.read("audit/audit.jsonl"),
            str(manifest["finalAuditEntryHash"]),
        )
    return {
        "assessmentId": manifest["assessmentId"],
        "archiveVerificationStatus": "VERIFIED",
        "fileCount": len(declared),
        "finalAuditEntryHash": manifest["finalAuditEntryHash"],
        "archiveDigest": sha256_bytes(raw),
    }


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive an archive key with a memory-hard KDF."""

    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(
        passphrase.encode("utf-8")
    )


def _verify_archived_audit(value: bytes, expected_hash: str) -> None:
    """Verify an archived JSONL hash chain without extraction."""

    previous: str | None = None
    lines = value.decode("utf-8").splitlines()
    if not lines:
        raise AssessmentArchiveError("Archived audit log is empty")
    from csa_console.canonical import sha256_value

    for line in lines:
        entry = json.loads(line)
        stored = entry.pop("entryHash", None)
        if entry.get("previousEntryHash") != previous or sha256_value(entry) != stored:
            raise AssessmentArchiveError("Archived audit chain is invalid")
        previous = stored
    if previous != expected_hash:
        raise AssessmentArchiveError("Archived audit final hash is invalid")
