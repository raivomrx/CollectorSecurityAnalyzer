"""Normalize accepted Collector evidence into the Console endpoint model."""

from __future__ import annotations

from typing import Any

from csa_console.coverage import calculate_coverage
from csa_console.models import EndpointEvidenceRecord
from csa_console.package import ValidatedPackage


def normalize_endpoint_package(
    package: ValidatedPackage,
) -> EndpointEvidenceRecord:
    """Build canonical endpoint evidence from a validated package."""

    evidence = package.evidence
    manifest = package.manifest
    security = _object(evidence.get("security"))
    updates = _object(evidence.get("updates"))
    services = _object(evidence.get("services"))
    settings = [
        item
        for item in security.get("settings", [])
        if isinstance(item, dict)
    ]
    update_settings = [
        item for item in updates.get("settings", []) if isinstance(item, dict)
    ]
    endpoint_protection = _settings(
        settings, ("DEFENDER_", "WINDOWS_FIREWALL_", "ACTIVE_FIREWALL_")
    )
    disk_encryption = _settings(settings, ("BITLOCKER_",))
    network = _settings(
        settings,
        (
            "NETWORK_",
            "NETBIOS_",
            "LLMNR_",
            "WPAD_",
            "SMB",
            "NTLM_",
            "LAN_MANAGER_",
            "RDP_",
            "WINRM_",
        ),
    )
    used_ids = {
        str(item.get("settingId"))
        for group in (endpoint_protection, disk_encryption, network)
        for item in group.get("settings", [])
    }
    policies = {
        "settings": [
            item
            for item in settings
            if str(item.get("settingId")) not in used_ids
        ]
    }
    limitations = [
        {
            "capabilityId": item.capability_id,
            "domain": item.domain.value,
            "reason": item.reason,
        }
        for item in calculate_coverage(package.capability_results).limitations
    ]
    operating_system = _object(evidence.get("operatingSystem"))
    device = _object(evidence.get("device"))
    hardware = _object(evidence.get("hardware"))
    return EndpointEvidenceRecord(
        schema_version="5.0",
        assessment_id=str(manifest["assessmentId"]),
        session_id=str(manifest["sessionId"]),
        submission_id=str(manifest["submissionId"]),
        device_id=str(manifest["deviceId"]),
        identity=device,
        operating_system=operating_system,
        hardware=hardware,
        privilege_context=_object(evidence.get("privilegeContext")),
        collection_coverage=calculate_coverage(package.capability_results),
        software=[
            item
            for item in _object(evidence.get("software")).get("items", [])
            if isinstance(item, dict)
        ],
        updates={"settings": update_settings},
        endpoint_protection=endpoint_protection,
        disk_encryption=disk_encryption,
        network_configuration=network,
        security_policies=policies,
        services=[
            item
            for item in services.get("services", [])
            if isinstance(item, dict)
        ],
        scheduled_tasks=[
            item
            for item in services.get("scheduledTasks", [])
            if isinstance(item, dict)
        ],
        startup=[
            item
            for item in services.get("startup", [])
            if isinstance(item, dict)
        ],
        certificates=[
            item
            for item in _object(evidence.get("certificates")).get("items", [])
            if isinstance(item, dict)
        ],
        collection_limitations=limitations,
        source_digests={
            "package": package.package_digest,
            "collectorBuild": str(manifest["collectorBuildDigest"]),
            "collectionProfile": str(manifest["collectionProfileDigest"]),
        },
    )


def _object(value: Any) -> dict[str, Any]:
    """Return only dictionary values."""

    return value if isinstance(value, dict) else {}


def _settings(
    values: list[dict[str, Any]],
    prefixes: tuple[str, ...],
) -> dict[str, Any]:
    """Select settings by canonical identifier prefix."""

    return {
        "settings": [
            item
            for item in values
            if str(item.get("settingId", "")).startswith(prefixes)
        ]
    }
