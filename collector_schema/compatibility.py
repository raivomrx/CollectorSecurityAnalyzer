"""Schema v1 to Schema v2 compatibility adapter."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

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
from evidence.windows_models import SecuritySettingEvidence
from utils import safe_get


class CollectorV1ToV2Adapter:
    """Convert legacy collector JSON into conservative Schema v2 models."""

    def convert(self, source: dict[str, Any]) -> CollectorDocument:
        """Convert a legacy collector dictionary to a v2 collector document."""

        collected_at = _now()
        settings = _legacy_security_settings(source, collected_at)
        update_settings = _legacy_update_settings(source, collected_at)
        errors: list[CollectionError] = []
        summary = CollectionSummary(
            total_collectors=7,
            successful_collectors=7,
            partial_collectors=0,
            failed_collectors=0,
            unsupported_collectors=0,
            access_denied_collectors=0,
            evidence_items=len(settings) + len(update_settings),
            collection_coverage_percent=100.0,
            mandatory_collection_coverage_percent=100.0,
            elevated=bool(source.get("Elevated", False)),
            reboot_pending=None,
            warnings=["Schema v1 input converted through compatibility adapter."],
            module_invocation_coverage_percent=100.0,
            successful_module_percent=100.0,
            evidence_unit_coverage_percent=100.0,
            mandatory_evidence_coverage_percent=100.0,
        )
        return CollectorDocument(
            schema_version="2.0",
            collector_version=str(source.get("CollectorVersion", "legacy-v1-adapter")),
            collection_id=str(source.get("CollectionId", "legacy-v1")),
            collection_started_at=collected_at,
            collection_completed_at=collected_at,
            device=DeviceIdentity(
                hostname=source.get("ComputerName"),
                domain=source.get("Domain"),
                workgroup=source.get("Workgroup"),
                tenant_id=source.get("TenantID") or source.get("TenantId"),
                current_user=source.get("Current_user") or source.get("CurrentUser"),
                elevated=bool(source.get("Elevated", False)),
            ),
            operating_system=OperatingSystemEvidence(
                name=source.get("OS") or source.get("OperatingSystem"),
                version=source.get("OSVersion"),
                build=source.get("OSBuild"),
                architecture=source.get("Architecture"),
                edition=source.get("OSEdition"),
            ),
            security=WindowsSecurityEvidence(settings=settings),
            software=SoftwareInventoryEvidence(items=source.get("Software", []) if isinstance(source.get("Software"), list) else []),
            updates=UpdateEvidence(settings=update_settings),
            services=ServiceInventoryEvidence(
                services=source.get("Non_standard_win_services", [])
                if isinstance(source.get("Non_standard_win_services"), list)
                else []
            ),
            collection_summary=summary,
            errors=errors,
            metadata={"source_schema": "1.x"},
        )


def _legacy_security_settings(source: dict[str, Any], collected_at: datetime) -> list[SecuritySettingEvidence]:
    """Convert known v1 security fields without inventing missing values."""

    settings: list[SecuritySettingEvidence] = []
    if "Bitlocker-C" in source:
        settings.append(_setting("BITLOCKER_OS_PROTECTION", "Encryption", bool(source.get("Bitlocker-C")), collected_at, "Bitlocker-C", confidence=70))
    defender_state = safe_get(source, "Windows Defender.ProductState")
    if defender_state not in (None, ""):
        settings.append(_setting("DEFENDER_ENABLED", "Defender", str(defender_state).casefold() == "on", collected_at, "Windows Defender.ProductState", confidence=70))
    firewall = source.get("Firewall")
    if isinstance(firewall, dict):
        for profile in ("Domain", "Private", "Public"):
            value = safe_get(source, f"Firewall.{profile}.Enabled")
            if value is not None:
                settings.append(_setting(f"WINDOWS_FIREWALL_{profile.upper()}_ENABLED", "Firewall", bool(value), collected_at, f"Firewall.{profile}.Enabled", confidence=70))
    admins = source.get("All_local_admins")
    if admins is not None:
        count = len(admins) if isinstance(admins, list) else int(admins) if str(admins).isdigit() else None
        settings.append(_setting("LOCAL_ADMINISTRATOR_COUNT", "Accounts", count, collected_at, "All_local_admins", confidence=70))
    return settings


def _legacy_update_settings(source: dict[str, Any], collected_at: datetime) -> list[SecuritySettingEvidence]:
    """Convert known v1 update fields."""

    settings: list[SecuritySettingEvidence] = []
    value = source.get("Updates_lastInstallationSuccessDate")
    if value:
        settings.append(_setting("WINDOWS_UPDATE_LAST_INSTALL_SUCCESS", "Updates", value, collected_at, "Updates_lastInstallationSuccessDate", confidence=70))
    return settings


def _setting(
    setting_id: str,
    category: str,
    value: Any,
    collected_at: datetime,
    source_path: str,
    confidence: int,
) -> SecuritySettingEvidence:
    """Create adapter evidence."""

    return SecuritySettingEvidence(
        setting_id=setting_id,
        category=category,
        configured_value=value,
        effective_value=value,
        source=ConfigurationSource.UNKNOWN,
        collection_status=CollectionStatus.SUCCESS,
        confidence=confidence,
        collected_at=collected_at,
        provider="CollectorV1ToV2Adapter",
        source_path=source_path,
        error_code=None,
        error_message=None,
        metadata={"adapter": "v1_to_v2"},
    )


def _now() -> datetime:
    """Return current UTC time."""

    return datetime.now(timezone.utc)
