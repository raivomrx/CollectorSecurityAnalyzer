"""Collector Schema v2 validation."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from collector_schema.enums import CollectionStatus, ConfigurationSource


class CollectorSchemaError(ValueError):
    """Raised when collector schema validation fails."""


def validate_schema_version(data: dict[str, Any]) -> list[str]:
    """Validate collector schema version and return non-fatal warnings."""

    version = str(data.get("schemaVersion") or data.get("schema_version") or "1.0")
    warnings: list[str] = []
    major, _minor = _version_parts(version)
    if major not in {1, 2}:
        raise CollectorSchemaError(f"UNSUPPORTED_SCHEMA_VERSION: {version}")
    if major == 2 and version != "2.0":
        warnings.append(f"Forward-compatible collector schema version: {version}")
    return warnings


def validate_v2_document(data: dict[str, Any]) -> list[str]:
    """Validate a Schema v2 JSON object."""

    warnings = validate_schema_version(data)
    required = {
        "schemaVersion",
        "collectorVersion",
        "collectionId",
        "collectionStartedAt",
        "collectionCompletedAt",
        "device",
        "operatingSystem",
        "security",
        "collectionSummary",
    }
    missing = [field for field in sorted(required) if field not in data]
    if missing:
        raise CollectorSchemaError(f"Missing required root field: {missing[0]}")

    started = _parse_datetime(data["collectionStartedAt"], "collectionStartedAt")
    completed = _parse_datetime(data["collectionCompletedAt"], "collectionCompletedAt")
    if completed < started:
        raise CollectorSchemaError("collectionCompletedAt is before collectionStartedAt")

    seen_settings: set[str] = set()
    for setting in _iter_setting_dicts(data):
        setting_id = str(setting.get("settingId", ""))
        if not setting_id:
            raise CollectorSchemaError("Security setting missing settingId")
        if setting_id in seen_settings:
            raise CollectorSchemaError(f"Duplicate setting ID: {setting_id}")
        seen_settings.add(setting_id)
        _validate_setting(setting)
    return warnings


def _validate_setting(setting: dict[str, Any]) -> None:
    """Validate one security setting dictionary."""

    try:
        CollectionStatus(setting.get("collectionStatus", ""))
    except ValueError as error:
        raise CollectorSchemaError(f"Invalid collectionStatus: {setting.get('collectionStatus')}") from error
    try:
        ConfigurationSource(setting.get("source", "UNKNOWN"))
    except ValueError as error:
        raise CollectorSchemaError(f"Invalid configuration source: {setting.get('source')}") from error
    confidence = setting.get("confidence")
    if not isinstance(confidence, int) or not 0 <= confidence <= 100:
        raise CollectorSchemaError(f"Invalid confidence: {setting.get('settingId')}")
    _parse_datetime(setting.get("collectedAt"), f"{setting.get('settingId')}.collectedAt")


def _iter_setting_dicts(data: dict[str, Any]):
    """Yield setting dictionaries from supported v2 locations."""

    security = data.get("security", {})
    updates = data.get("updates", {})
    for section in (security, updates):
        if isinstance(section, dict):
            for setting in section.get("settings", []):
                if not isinstance(setting, dict):
                    raise CollectorSchemaError("Security setting must be an object")
                yield setting


def _parse_datetime(value: Any, field_name: str) -> datetime:
    """Parse a collector timestamp."""

    if not isinstance(value, str):
        raise CollectorSchemaError(f"Invalid timestamp: {field_name}")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise CollectorSchemaError(f"Invalid timestamp: {field_name}") from error


def _version_parts(version: str) -> tuple[int, int]:
    """Return major/minor version parts."""

    parts = version.split(".")
    try:
        return int(parts[0]), int(parts[1] if len(parts) > 1 else 0)
    except ValueError as error:
        raise CollectorSchemaError(f"Invalid schema version: {version}") from error
