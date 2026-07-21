"""Collector schema loader."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from collector_schema.compatibility import CollectorV1ToV2Adapter
from collector_schema.enums import CollectionStatus, ConfigurationSource
from collector_schema.models import (
    CollectionError,
    CollectionSummary,
    CollectorDocument,
    DeviceIdentity,
    OperatingSystemEvidence,
    ServiceInventoryEvidence,
    SoftwareInventoryEvidence,
    UpdateEvidence,
    WindowsSecurityEvidence,
)
from collector_schema.validation import validate_schema_version, validate_v2_document
from evidence.windows_models import SecuritySettingEvidence


def load_collector_document(data: dict[str, Any], validate: bool = False) -> CollectorDocument:
    """Load collector JSON data as a CollectorDocument."""

    validate_schema_version(data)
    version = str(data.get("schemaVersion") or data.get("schema_version") or "1.0")
    if version.startswith("1.") or "schemaVersion" not in data:
        return CollectorV1ToV2Adapter().convert(data)
    if validate:
        validate_v2_document(data)
    return _parse_v2_document(data)


def _parse_v2_document(data: dict[str, Any]) -> CollectorDocument:
    """Parse a v2 collector document."""

    security_settings = [_parse_setting(item) for item in data.get("security", {}).get("settings", [])]
    update_settings = [_parse_setting(item) for item in data.get("updates", {}).get("settings", [])]
    started = _parse_datetime(data.get("collectionStartedAt"))
    completed = _parse_datetime(data.get("collectionCompletedAt"))
    device = data.get("device", {}) if isinstance(data.get("device", {}), dict) else {}
    os_data = data.get("operatingSystem", {}) if isinstance(data.get("operatingSystem", {}), dict) else {}
    summary = data.get("collectionSummary", {}) if isinstance(data.get("collectionSummary", {}), dict) else {}
    return CollectorDocument(
        schema_version=str(data.get("schemaVersion", "2.0")),
        collector_version=str(data.get("collectorVersion", "")),
        collection_id=str(data.get("collectionId", "")),
        collection_started_at=started,
        collection_completed_at=completed,
        device=DeviceIdentity(
            hostname=device.get("hostname"),
            domain=device.get("domain"),
            workgroup=device.get("workgroup"),
            tenant_id=device.get("tenantId"),
            current_user=device.get("currentUser"),
            elevated=bool(device.get("elevated", False)),
        ),
        operating_system=OperatingSystemEvidence(
            name=os_data.get("name"),
            version=os_data.get("version"),
            build=os_data.get("build"),
            architecture=os_data.get("architecture"),
            edition=os_data.get("edition"),
        ),
        security=WindowsSecurityEvidence(settings=security_settings),
        software=SoftwareInventoryEvidence(items=data.get("software", {}).get("items", []) if isinstance(data.get("software"), dict) else []),
        updates=UpdateEvidence(settings=update_settings),
        services=ServiceInventoryEvidence(
            services=data.get("services", {}).get("services", []) if isinstance(data.get("services"), dict) else [],
            scheduled_tasks=data.get("services", {}).get("scheduledTasks", []) if isinstance(data.get("services"), dict) else [],
        ),
        collection_summary=_parse_summary(summary),
        errors=[
            CollectionError(
                module=str(item.get("module", "")),
                status=CollectionStatus(item.get("status", "FAILED")),
                error_code=str(item.get("errorCode", "")),
                message=str(item.get("message", "")),
            )
            for item in data.get("errors", [])
            if isinstance(item, dict)
        ],
        metadata=data.get("metadata", {}) if isinstance(data.get("metadata", {}), dict) else {},
    )


def _parse_setting(item: dict[str, Any]) -> SecuritySettingEvidence:
    """Parse one v2 security setting."""

    return SecuritySettingEvidence(
        setting_id=str(item["settingId"]),
        category=str(item.get("category", "")),
        configured_value=item.get("configuredValue"),
        effective_value=item.get("effectiveValue"),
        source=ConfigurationSource(item.get("source", "UNKNOWN")),
        collection_status=CollectionStatus(item.get("collectionStatus", "NOT_AVAILABLE")),
        confidence=int(item.get("confidence", 0)),
        collected_at=_parse_datetime(item.get("collectedAt")),
        provider=str(item.get("provider", "")),
        source_path=item.get("sourcePath") or item.get("source_path"),
        error_code=item.get("errorCode"),
        error_message=item.get("errorMessage"),
        metadata=item.get("metadata", {}) if isinstance(item.get("metadata", {}), dict) else {},
    )


def _parse_summary(data: dict[str, Any]) -> CollectionSummary:
    """Parse collection summary."""

    return CollectionSummary(
        total_collectors=int(data.get("totalCollectors", 0)),
        successful_collectors=int(data.get("successfulCollectors", 0)),
        partial_collectors=int(data.get("partialCollectors", 0)),
        failed_collectors=int(data.get("failedCollectors", 0)),
        unsupported_collectors=int(data.get("unsupportedCollectors", 0)),
        access_denied_collectors=int(data.get("accessDeniedCollectors", 0)),
        evidence_items=int(data.get("evidenceItems", 0)),
        collection_coverage_percent=float(data.get("collectionCoveragePercent", 0.0)),
        mandatory_collection_coverage_percent=float(data.get("mandatoryCollectionCoveragePercent", 0.0)),
        elevated=bool(data.get("elevated", False)),
        reboot_pending=data.get("rebootPending"),
        warnings=[str(item) for item in data.get("warnings", [])],
        module_execution_coverage_percent=float(
            data.get("moduleExecutionCoveragePercent", data.get("collectionCoveragePercent", 0.0))
        ),
        evidence_collection_coverage_percent=float(
            data.get("evidenceCollectionCoveragePercent", data.get("collectionCoveragePercent", 0.0))
        ),
        mandatory_evidence_applicable=int(data.get("mandatoryEvidenceApplicable", 0)),
        mandatory_evidence_collected=int(data.get("mandatoryEvidenceCollected", 0)),
    )


def _parse_datetime(value: Any) -> datetime:
    """Parse an optional ISO timestamp."""

    if isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    return datetime.now(timezone.utc)
