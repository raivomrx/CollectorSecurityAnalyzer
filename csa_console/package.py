"""Canonical endpoint evidence package creation and validation."""

from __future__ import annotations

import base64
import hmac
import io
import json
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from csa_console.canonical import (
    canonical_bytes,
    canonical_json,
    sha256_bytes,
    sha256_value,
)
from csa_console.enums import CapabilityStatus
from csa_console.privacy import SensitiveDataScanner

PAYLOAD_FILES = (
    "evidence.json",
    "capability-results.json",
    "collection-log.json",
)
REQUIRED_FILES = (
    "manifest.json",
    *PAYLOAD_FILES,
    "integrity.json",
    "signatures/submission.sig",
)
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


class PackageValidationError(ValueError):
    """Report an invalid or unsafe endpoint evidence package."""

    def __init__(self, state: str, safe_message: str) -> None:
        """Create a structured package validation error."""

        super().__init__(safe_message)
        self.state = state
        self.safe_message = safe_message


@dataclass(slots=True)
class ValidatedPackage:
    """Contain verified package metadata and evidence."""

    manifest: dict[str, Any]
    evidence: dict[str, Any]
    capability_results: list[dict[str, Any]]
    collection_log: dict[str, Any]
    package_digest: str


def build_evidence_package(
    output_path: str | Path,
    *,
    manifest_fields: dict[str, Any],
    evidence: dict[str, Any],
    capability_results: list[dict[str, Any]],
    collection_log: dict[str, Any],
    enrollment_token: str,
    nonce: str,
) -> Path:
    """Build a deterministic session-bound evidence package."""

    SensitiveDataScanner().require_clean(evidence)
    SensitiveDataScanner().require_clean(capability_results)
    SensitiveDataScanner().require_clean(collection_log)
    payload_values: dict[str, Any] = {
        "evidence.json": evidence,
        "capability-results.json": capability_results,
        "collection-log.json": collection_log,
    }
    payload_bytes = {
        name: canonical_bytes(value) for name, value in payload_values.items()
    }
    files = [
        {
            "path": name,
            "sha256": sha256_bytes(payload_bytes[name]),
            "size": len(payload_bytes[name]),
        }
        for name in PAYLOAD_FILES
    ]
    binding = {
        "assessmentId": manifest_fields["assessmentId"],
        "sessionId": manifest_fields["sessionId"],
        "submissionId": manifest_fields["submissionId"],
        "nonce": nonce,
        "files": files,
    }
    package_digest = sha256_value(binding)
    integrity = {
        "schemaVersion": "5.0",
        "binding": binding,
        "packageDigest": package_digest,
    }
    signed = {
        "sessionId": manifest_fields["sessionId"],
        "submissionId": manifest_fields["submissionId"],
        "nonce": nonce,
        "packageDigest": package_digest,
    }
    signature = base64.b64encode(
        hmac.digest(
            enrollment_token.encode("utf-8"),
            canonical_bytes(signed),
            "sha256",
        )
    ).decode("ascii")
    signature_document = {
        "algorithm": "HMAC-SHA256",
        "keyId": enrollment_token.partition(".")[0],
        "signed": signed,
        "signature": signature,
    }
    integrity_bytes = canonical_bytes(integrity)
    signature_bytes = canonical_bytes(signature_document)
    manifest = dict(manifest_fields)
    manifest.update(
        {
            "schemaVersion": "5.0",
            "files": files,
            "packageDigest": package_digest,
            "integrityDigest": sha256_bytes(integrity_bytes),
            "signatureDigest": sha256_bytes(signature_bytes),
        }
    )
    archive_files = {
        "manifest.json": canonical_bytes(manifest),
        **payload_bytes,
        "integrity.json": integrity_bytes,
        "signatures/submission.sig": signature_bytes,
    }
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    with zipfile.ZipFile(
        temporary,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for name in sorted(archive_files):
            info = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, archive_files[name])
    temporary.chmod(0o600)
    temporary.replace(output)
    return output


class EvidencePackageValidator:
    """Validate archive safety, integrity, binding, schema and privacy."""

    def __init__(
        self,
        maximum_package_size: int = 25 * 1024 * 1024,
        maximum_uncompressed_size: int = 100 * 1024 * 1024,
        maximum_files: int = 8,
    ) -> None:
        """Create a bounded package validator."""

        self.maximum_package_size = maximum_package_size
        self.maximum_uncompressed_size = maximum_uncompressed_size
        self.maximum_files = maximum_files

    def peek_manifest(self, archive_bytes: bytes) -> dict[str, Any]:
        """Safely read only the canonical manifest from an archive."""

        members = self._safe_members(archive_bytes)
        manifest_bytes = members["manifest.json"]
        return self._parse_canonical_object(manifest_bytes, "manifest.json")

    def validate(
        self,
        archive_bytes: bytes,
        *,
        enrollment_token: str,
        expected_assessment_id: str,
        expected_session_id: str,
        expected_submission_id: str,
        expected_nonce: str,
        expected_profile_digest: str,
    ) -> ValidatedPackage:
        """Validate a package against an open session contract."""

        members = self._safe_members(archive_bytes)
        manifest = self._parse_canonical_object(
            members["manifest.json"], "manifest.json"
        )
        evidence = self._parse_canonical_object(
            members["evidence.json"], "evidence.json"
        )
        capability_raw = self._parse_canonical_value(
            members["capability-results.json"], "capability-results.json"
        )
        if not isinstance(capability_raw, list):
            raise PackageValidationError(
                "REJECTED_SCHEMA", "Capability results must be a list"
            )
        capability_results = [
            item for item in capability_raw if isinstance(item, dict)
        ]
        if len(capability_results) != len(capability_raw):
            raise PackageValidationError(
                "REJECTED_SCHEMA", "Capability results contain a non-object"
            )
        collection_log = self._parse_canonical_object(
            members["collection-log.json"], "collection-log.json"
        )
        integrity = self._parse_canonical_object(
            members["integrity.json"], "integrity.json"
        )
        signature = self._parse_canonical_object(
            members["signatures/submission.sig"],
            "signatures/submission.sig",
        )
        self._validate_manifest(
            manifest,
            expected_assessment_id,
            expected_session_id,
            expected_submission_id,
            expected_profile_digest,
        )
        try:
            from collector_schema.validation import validate_v2_document

            validate_v2_document(evidence)
        except (ValueError, TypeError, KeyError) as error:
            raise PackageValidationError(
                "REJECTED_SCHEMA", "Collector evidence schema validation failed"
            ) from error
        declared_files = manifest.get("files")
        if not isinstance(declared_files, list):
            raise PackageValidationError(
                "REJECTED_SCHEMA", "Manifest files must be a list"
            )
        expected_entries = {item["path"]: item for item in declared_files}
        if set(expected_entries) != set(PAYLOAD_FILES):
            raise PackageValidationError(
                "REJECTED_SCHEMA", "Manifest payload file set is invalid"
            )
        for name in PAYLOAD_FILES:
            declaration = expected_entries[name]
            if declaration.get("sha256") != sha256_bytes(members[name]):
                raise PackageValidationError(
                    "REJECTED_DIGEST", f"Payload digest mismatch: {name}"
                )
            if declaration.get("size") != len(members[name]):
                raise PackageValidationError(
                    "REJECTED_DIGEST", f"Payload size mismatch: {name}"
                )
        if manifest.get("integrityDigest") != sha256_bytes(
            members["integrity.json"]
        ):
            raise PackageValidationError(
                "REJECTED_DIGEST", "Integrity document digest mismatch"
            )
        if manifest.get("signatureDigest") != sha256_bytes(
            members["signatures/submission.sig"]
        ):
            raise PackageValidationError(
                "REJECTED_DIGEST", "Signature document digest mismatch"
            )
        binding = integrity.get("binding")
        if not isinstance(binding, dict):
            raise PackageValidationError(
                "REJECTED_SCHEMA", "Integrity binding is missing"
            )
        if binding.get("nonce") != expected_nonce:
            raise PackageValidationError(
                "REJECTED_REPLAY", "Submission nonce binding is invalid"
            )
        if binding.get("files") != declared_files:
            raise PackageValidationError(
                "REJECTED_DIGEST", "Integrity file binding is invalid"
            )
        package_digest = sha256_value(binding)
        if (
            integrity.get("packageDigest") != package_digest
            or manifest.get("packageDigest") != package_digest
        ):
            raise PackageValidationError(
                "REJECTED_DIGEST", "Package digest is invalid"
            )
        signed = signature.get("signed")
        expected_signed = {
            "sessionId": expected_session_id,
            "submissionId": manifest["submissionId"],
            "nonce": expected_nonce,
            "packageDigest": package_digest,
        }
        if signed != expected_signed:
            raise PackageValidationError(
                "REJECTED_DIGEST", "Submission signature binding is invalid"
            )
        expected_signature = base64.b64encode(
            hmac.digest(
                enrollment_token.encode("utf-8"),
                canonical_bytes(expected_signed),
                "sha256",
            )
        ).decode("ascii")
        if not hmac.compare_digest(
            str(signature.get("signature", "")), expected_signature
        ):
            raise PackageValidationError(
                "REJECTED_TOKEN", "Submission signature is invalid"
            )
        self._validate_capability_results(capability_results)
        scanner = SensitiveDataScanner()
        for value in (evidence, capability_results, collection_log):
            if scanner.scan(value):
                raise PackageValidationError(
                    "REJECTED_SENSITIVE_DATA",
                    "Package contains prohibited sensitive material",
                )
        return ValidatedPackage(
            manifest=manifest,
            evidence=evidence,
            capability_results=capability_results,
            collection_log=collection_log,
            package_digest=package_digest,
        )

    def _safe_members(self, archive_bytes: bytes) -> dict[str, bytes]:
        """Read a small allowlisted archive without filesystem extraction."""

        if len(archive_bytes) > self.maximum_package_size:
            raise PackageValidationError(
                "REJECTED_PACKAGE_LIMIT", "Package exceeds the compressed size limit"
            )
        try:
            archive = zipfile.ZipFile(io.BytesIO(archive_bytes), "r")
        except (zipfile.BadZipFile, OSError) as error:
            raise PackageValidationError(
                "REJECTED_ARCHIVE_SAFETY", "Package is not a valid ZIP archive"
            ) from error
        with archive:
            infos = archive.infolist()
            if len(infos) > self.maximum_files:
                raise PackageValidationError(
                    "REJECTED_PACKAGE_LIMIT", "Package contains too many files"
                )
            names = [item.filename for item in infos]
            if len(names) != len(set(names)):
                raise PackageValidationError(
                    "REJECTED_ARCHIVE_SAFETY", "Package contains duplicate paths"
                )
            if set(names) != set(REQUIRED_FILES):
                raise PackageValidationError(
                    "REJECTED_ARCHIVE_SAFETY", "Package file set is invalid"
                )
            total = 0
            members: dict[str, bytes] = {}
            for info in infos:
                path = PurePosixPath(info.filename)
                unix_mode = info.external_attr >> 16
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or "\\" in info.filename
                    or stat.S_ISLNK(unix_mode)
                    or info.is_dir()
                ):
                    raise PackageValidationError(
                        "REJECTED_ARCHIVE_SAFETY", "Package contains an unsafe path"
                    )
                total += info.file_size
                if total > self.maximum_uncompressed_size:
                    raise PackageValidationError(
                        "REJECTED_PACKAGE_LIMIT",
                        "Package exceeds the uncompressed size limit",
                    )
                if info.compress_size == 0 and info.file_size > 0:
                    ratio = float("inf")
                else:
                    ratio = info.file_size / max(1, info.compress_size)
                if ratio > 100:
                    raise PackageValidationError(
                        "REJECTED_ARCHIVE_SAFETY",
                        "Package compression ratio is unsafe",
                    )
                members[info.filename] = archive.read(info)
            return members

    def _parse_canonical_object(
        self, value: bytes, label: str
    ) -> dict[str, Any]:
        """Parse and require a canonical JSON object."""

        parsed = self._parse_canonical_value(value, label)
        if not isinstance(parsed, dict):
            raise PackageValidationError(
                "REJECTED_SCHEMA", f"{label} must contain a JSON object"
            )
        return parsed

    def _parse_canonical_value(self, value: bytes, label: str) -> Any:
        """Parse deterministic compact JSON from Python or Windows PowerShell."""

        try:
            text = value.decode("utf-8")
            parsed = json.loads(text, object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PackageValidationError(
                "REJECTED_SCHEMA", f"{label} contains invalid JSON"
            ) from error
        except ValueError as error:
            raise PackageValidationError(
                "REJECTED_SCHEMA", f"{label} contains duplicate JSON keys"
            ) from error
        if canonical_json(parsed) != text and not _is_compact_json(text):
            raise PackageValidationError(
                "REJECTED_SCHEMA", f"{label} is not canonical JSON"
            )
        return parsed

    def _validate_manifest(
        self,
        manifest: dict[str, Any],
        assessment_id: str,
        session_id: str,
        submission_id: str,
        profile_digest: str,
    ) -> None:
        """Validate required manifest identity and build fields."""

        required = {
            "schemaVersion",
            "assessmentId",
            "sessionId",
            "submissionId",
            "collectorVersion",
            "collectorBuildDigest",
            "collectionProfile",
            "collectionProfileDigest",
            "deviceId",
            "startedAt",
            "completedAt",
            "privilegeContext",
            "files",
            "packageDigest",
        }
        if required - set(manifest):
            raise PackageValidationError(
                "REJECTED_SCHEMA", "Manifest is missing required fields"
            )
        if manifest.get("schemaVersion") != "5.0":
            raise PackageValidationError(
                "REJECTED_SCHEMA", "Unsupported package schema version"
            )
        if (
            manifest.get("assessmentId") != assessment_id
            or manifest.get("sessionId") != session_id
            or manifest.get("submissionId") != submission_id
        ):
            raise PackageValidationError(
                "REJECTED_TOKEN", "Package is bound to a different session"
            )
        if manifest.get("collectionProfileDigest") != profile_digest:
            raise PackageValidationError(
                "REJECTED_UNTRUSTED_COLLECTOR",
                "Collection profile digest is not trusted",
            )
        if manifest.get("privilegeContext") not in {
            "STANDARD_USER",
            "ADMIN_MEMBER_NOT_ELEVATED",
        }:
            raise PackageValidationError(
                "REJECTED_SCHEMA",
                "Standard-user session received incompatible privilege context",
            )

    def _validate_capability_results(
        self, results: list[dict[str, Any]]
    ) -> None:
        """Validate capability terminal states and unique IDs."""

        seen: set[str] = set()
        allowed = {item.value for item in CapabilityStatus}
        for item in results:
            capability_id = str(item.get("capabilityId", ""))
            if not capability_id or capability_id in seen:
                raise PackageValidationError(
                    "REJECTED_SCHEMA",
                    "Capability results contain a missing or duplicate ID",
                )
            seen.add(capability_id)
            if item.get("status") not in allowed:
                raise PackageValidationError(
                    "REJECTED_SCHEMA",
                    f"Capability result has an invalid state: {capability_id}",
                )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON object keys."""

    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"Duplicate JSON key: {key}")
        value[key] = item
    return value


def _is_compact_json(value: str) -> bool:
    """Return whether JSON has no insignificant whitespace."""

    in_string = False
    escaped = False
    for character in value:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character.isspace():
            return False
    return not in_string and not escaped
