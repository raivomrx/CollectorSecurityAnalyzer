"""Safe JSON loading for framework content packs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from frameworks.digest import pack_content_digest
from frameworks.enums import (
    AssessmentMode,
    AutomationCapability,
    FrameworkControlLevel,
    MappingStatus,
    MappingStrength,
    PackStatus,
    ReviewMethod,
    ReviewPendingReason,
)
from frameworks.exceptions import FrameworkPackError
from frameworks.models import FrameworkControl, FrameworkPack, FrameworkSource, RuleMapping

MAX_PACK_BYTES = 5 * 1024 * 1024
MAX_CONTROLS = 5000
MAX_STRING_LENGTH = 4096
MAX_JSON_DEPTH = 24


def load_json_document(path: str | Path, max_bytes: int = MAX_PACK_BYTES) -> dict[str, Any]:
    """Load a bounded JSON object while rejecting duplicate keys."""

    source = Path(path)
    if source.stat().st_size > max_bytes:
        raise FrameworkPackError(f"Framework JSON exceeds {max_bytes} bytes: {source}")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise FrameworkPackError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(source.read_text(encoding="utf-8-sig"), object_pairs_hook=reject_duplicates)
    except (OSError, json.JSONDecodeError) as error:
        raise FrameworkPackError(f"Cannot load framework JSON {source}: {error}") from error
    if not isinstance(value, dict):
        raise FrameworkPackError(f"Framework JSON root must be an object: {source}")
    _enforce_limits(value)
    return value


def load_pack(path: str | Path, verify_digest: bool = True) -> FrameworkPack:
    """Load one framework pack and verify its content digest."""

    document = load_json_document(path)
    expected = str(document.get("contentHashSha256", ""))
    actual = pack_content_digest(document)
    if verify_digest and expected != actual:
        raise FrameworkPackError(
            f"Framework pack digest mismatch: expected {expected or '<missing>'}, got {actual}"
        )
    try:
        source = document["source"]
        return FrameworkPack(
            schema_version=str(document["schemaVersion"]),
            framework_id=str(document["frameworkId"]),
            name=str(document["name"]),
            version=str(document["version"]),
            status=PackStatus(document["status"]),
            source=FrameworkSource(
                publisher=str(source["publisher"]),
                release=_optional_string(source.get("release")),
                published_at=_optional_string(source.get("publishedAt")),
                retrieved_at=str(source["retrievedAt"]),
                reference=str(source["reference"]),
                digest_sha256=_optional_string(
                    source.get("sourceDigestSha256", source.get("digestSha256"))
                ),
                source_file_name=_optional_string(source.get("sourceFileName")),
                source_format=_optional_string(source.get("sourceFormat")),
                imported_at=_optional_string(source.get("importedAt")),
                record_count=_optional_int(source.get("recordCount")),
            ),
            scope=tuple(str(item) for item in document["scope"]),
            license_notice=str(document["license"]),
            created_at=str(document["createdAt"]),
            updated_at=str(document["updatedAt"]),
            maintainer=str(document["maintainer"]),
            minimum_csa_version=str(document["minimumCsaVersion"]),
            deprecated=bool(document["deprecated"]),
            supersedes=_optional_string(document.get("supersedes")),
            superseded_by=_optional_string(document.get("supersededBy")),
            controls=tuple(_parse_control(item) for item in document["controls"]),
            content_hash_sha256=expected,
            assessment_mode=AssessmentMode(
                document.get("assessmentMode", AssessmentMode.FORMAL_ASSESSMENT.value)
            ),
            disclaimer_en=_optional_string(
                (document.get("disclaimers") or {}).get("en")
            ),
            disclaimer_et=_optional_string(
                (document.get("disclaimers") or {}).get("et")
            ),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise FrameworkPackError(f"Invalid framework pack {path}: {error}") from error


def _parse_control(value: dict[str, Any]) -> FrameworkControl:
    """Parse one control object."""

    return FrameworkControl(
        control_id=str(value["controlId"]),
        title=str(value["title"]),
        section=str(value["section"]),
        profile=tuple(str(item) for item in value.get("profile", [])),
        level=FrameworkControlLevel(value["level"]),
        automation=AutomationCapability(value["automation"]),
        mappings=tuple(_parse_mapping(item) for item in value.get("mappings", [])),
        tags=tuple(str(item) for item in value.get("tags", [])),
        notes=_optional_string(value.get("notes")),
    )


def _parse_mapping(value: dict[str, Any]) -> RuleMapping:
    """Parse one rule mapping object."""

    return RuleMapping(
        rule_id=str(value["ruleId"]),
        strength=MappingStrength(value["mappingStrength"]),
        status=MappingStatus(value["mappingStatus"]),
        rationale=str(value["rationale"]),
        evidence_limitations=tuple(str(item) for item in value.get("evidenceLimitations", [])),
        reviewer=_optional_string(value.get("reviewer")),
        reviewed_at=_optional_string(value.get("reviewedAt")),
        source_reference=_optional_string(value.get("sourceReference")),
        source_release=_optional_string(value.get("sourceRelease")),
        review_method=(
            ReviewMethod(value["reviewMethod"])
            if value.get("reviewMethod") is not None
            else None
        ),
        review_pending_reason=(
            ReviewPendingReason(value["reviewPendingReason"])
            if value.get("reviewPendingReason") is not None
            else None
        ),
    )


def _optional_string(value: Any) -> str | None:
    """Normalize nullable strings."""

    return None if value is None else str(value)


def _optional_int(value: Any) -> int | None:
    """Normalize nullable integer metadata."""

    return None if value is None else int(value)


def _enforce_limits(value: Any, depth: int = 0) -> None:
    """Reject pathologically large or deeply nested JSON values."""

    if depth > MAX_JSON_DEPTH:
        raise FrameworkPackError("Framework JSON exceeds maximum nesting depth")
    if isinstance(value, str) and len(value) > MAX_STRING_LENGTH:
        raise FrameworkPackError("Framework JSON string exceeds maximum length")
    if isinstance(value, dict):
        controls = value.get("controls")
        if isinstance(controls, list) and len(controls) > MAX_CONTROLS:
            raise FrameworkPackError("Framework pack exceeds maximum control count")
        for key, item in value.items():
            _enforce_limits(key, depth + 1)
            _enforce_limits(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _enforce_limits(item, depth + 1)
