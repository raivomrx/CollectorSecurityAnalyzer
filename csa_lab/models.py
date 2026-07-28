"""Typed models used by the CSA Lab application layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class LabAssessmentStatus(str, Enum):
    """User-facing CSA Lab assessment states."""

    DRAFT = "DRAFT"
    COLLECTING = "COLLECTING"
    PAUSED = "PAUSED"
    READY_FOR_REPORT = "READY_FOR_REPORT"
    COMPLETED = "COMPLETED"
    CLOSED = "CLOSED"
    ERROR = "ERROR"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"


class EndpointUiStatus(str, Enum):
    """User-facing endpoint processing states."""

    DOWNLOADED = "DOWNLOADED"
    COLLECTING = "COLLECTING"
    RECEIVED = "RECEIVED"
    VALIDATING = "VALIDATING"
    NORMALIZING = "NORMALIZING"
    ANALYZING = "ANALYZING"
    COMPLETE = "COMPLETE"
    REJECTED = "REJECTED"
    QUARANTINED = "QUARANTINED"
    ERROR = "ERROR"


@dataclass(slots=True)
class AssessmentWizardRequest:
    """Represent validated input from the New Assessment wizard."""

    name: str
    expected_endpoints: int = 1
    organization: str = ""
    reference_number: str = ""
    assessor_notes: str = ""
    description: str = ""
    collection_profile: str = "windows-standard-v1"
    session_expiry_hours: int = 2
    allowed_submissions: int | None = None
    source_subnet: str = ""
    network_profile: str = "Private"
    interface_id: str = ""
    listener_address: str = "127.0.0.1"
    listener_port: int = 8443
    offline_collection: bool = True
    active_validation: bool = False

    def validate(self) -> None:
        """Validate safe wizard boundaries before creating any state."""

        self.name = self.name.strip()
        self.organization = self.organization.strip()
        self.reference_number = self.reference_number.strip()
        if not self.name or len(self.name) > 120:
            raise ValueError("Assessment name must contain 1 to 120 characters")
        if not 1 <= self.expected_endpoints <= 10000:
            raise ValueError("Expected endpoint count must be between 1 and 10000")
        if not 1 <= self.session_expiry_hours <= 72:
            raise ValueError("Session expiry must be between 1 and 72 hours")
        if not 1 <= self.listener_port <= 65535:
            raise ValueError("Listener port must be between 1 and 65535")
        if self.active_validation:
            raise ValueError(
                "Active Validation is isolated from standard-user collection"
            )
        if self.allowed_submissions is None:
            self.allowed_submissions = self.expected_endpoints + max(
                2, min(10, self.expected_endpoints // 2 + 1)
            )
        if self.allowed_submissions < self.expected_endpoints:
            raise ValueError(
                "Allowed submissions cannot be lower than expected endpoints"
            )


@dataclass(slots=True)
class NetworkInterface:
    """Describe one candidate collection network."""

    interface_id: str
    name: str
    address: str
    subnet: str
    profile: str
    adapter_type: str
    connected: bool
    is_virtual: bool
    is_vpn: bool
    recommended: bool = False
    warning: str = ""


@dataclass(slots=True)
class FirewallRuleSpec:
    """Describe a least-privilege temporary Windows Firewall rule."""

    rule_name: str
    program_path: str
    local_address: str
    local_port: int
    remote_subnet: str
    profile: str
    protocol: str = "TCP"


@dataclass(slots=True)
class PortalState:
    """Persist non-secret download portal state."""

    join_code_hash: str
    collector_path: str
    expires_at: str
    maximum_downloads: int
    download_count: int = 0
    active: bool = False


@dataclass(slots=True)
class LabAssessmentState:
    """Persist the GUI-facing state for one assessment."""

    assessment_id: str
    session_id: str
    name: str
    organization: str
    reference_number: str
    assessor_notes: str
    description: str
    created_at: str
    expected_endpoints: int
    listener_address: str
    listener_port: int
    source_subnet: str
    network_profile: str
    interface_id: str
    status: LabAssessmentStatus
    expires_at: str
    offline_collection: bool
    firewall_rule_name: str
    collector_path: str
    report_path: str = ""
    report_generated_at: str = ""
    download_count: int = 0
    recovery_details: list[str] = field(default_factory=list)
    settings: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class EndpointDashboardItem:
    """Describe one latest endpoint submission for the live dashboard."""

    device_id: str
    submission_id: str
    status: EndpointUiStatus
    transport: str
    coverage_percent: float | None
    finding_count: int | None
    received_at: str
    collector_version: str
    execution_mode: str
    integrity_level: str
    is_elevated: bool
    local_administrator_member: bool | None
    receipt_status: str
    evidence_digest: str
    severity_counts: dict[str, int] = field(default_factory=dict)
    capability_gaps: list[dict[str, Any]] = field(default_factory=list)
