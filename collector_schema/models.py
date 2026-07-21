"""Collector Schema v2 data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from collector_schema.enums import CollectionStatus
from evidence.windows_models import SecuritySettingEvidence


@dataclass(slots=True)
class DeviceIdentity:
    """Identify the collected endpoint."""

    hostname: str | None = None
    domain: str | None = None
    workgroup: str | None = None
    tenant_id: str | None = None
    current_user: str | None = None
    elevated: bool = False


@dataclass(slots=True)
class OperatingSystemEvidence:
    """Represent operating system identity evidence."""

    name: str | None = None
    version: str | None = None
    build: str | None = None
    architecture: str | None = None
    edition: str | None = None


@dataclass(slots=True)
class WindowsSecurityEvidence:
    """Group Windows security setting evidence."""

    settings: list[SecuritySettingEvidence] = field(default_factory=list)


@dataclass(slots=True)
class SoftwareInventoryEvidence:
    """Represent software inventory evidence."""

    items: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class UpdateEvidence:
    """Represent update inventory evidence."""

    settings: list[SecuritySettingEvidence] = field(default_factory=list)


@dataclass(slots=True)
class ServiceInventoryEvidence:
    """Represent services and scheduled task evidence."""

    services: list[dict[str, Any]] = field(default_factory=list)
    scheduled_tasks: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class CollectionSummary:
    """Summarize collector module execution quality."""

    total_collectors: int
    successful_collectors: int
    partial_collectors: int
    failed_collectors: int
    unsupported_collectors: int
    access_denied_collectors: int
    evidence_items: int
    collection_coverage_percent: float
    mandatory_collection_coverage_percent: float
    elevated: bool
    reboot_pending: bool | None
    warnings: list[str] = field(default_factory=list)
    module_invocation_coverage_percent: float = 0.0
    successful_module_percent: float = 0.0
    evidence_unit_coverage_percent: float = 0.0
    mandatory_evidence_coverage_percent: float = 0.0
    module_execution_coverage_percent: float = 0.0
    evidence_collection_coverage_percent: float = 0.0
    mandatory_evidence_applicable: int = 0
    mandatory_evidence_collected: int = 0


@dataclass(slots=True)
class CollectionError:
    """Represent one collector module error."""

    module: str
    status: CollectionStatus
    error_code: str
    message: str


@dataclass(slots=True)
class CollectorDocument:
    """Represent a Collector Schema v2 document."""

    schema_version: str
    collector_version: str
    collection_id: str
    collection_started_at: datetime
    collection_completed_at: datetime
    device: DeviceIdentity
    operating_system: OperatingSystemEvidence
    security: WindowsSecurityEvidence
    software: SoftwareInventoryEvidence
    updates: UpdateEvidence
    services: ServiceInventoryEvidence
    collection_summary: CollectionSummary
    errors: list[CollectionError]
    metadata: dict[str, Any] = field(default_factory=dict)
