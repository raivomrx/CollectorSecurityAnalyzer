"""Typed data models for the CSA Assessment Console."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from csa_console.enums import (
    AssessmentStatus,
    CapabilityStatus,
    CollectorMode,
    CoverageDomain,
    MinimumPrivilege,
    PrivilegeKind,
    SessionStatus,
    SubmissionState,
)


@dataclass(slots=True)
class CollectionPrivilegeContext:
    """Describe the endpoint process privilege context."""

    execution_mode: PrivilegeKind
    is_elevated: bool
    is_local_administrator_member: bool
    integrity_level: str
    uac_virtualization: bool | None
    effective_user_hash: str
    collection_scope: str


@dataclass(slots=True)
class CollectorCapabilityDefinition:
    """Describe one self-contained endpoint collection capability."""

    capability_id: str
    name: str
    description: str
    supported_operating_systems: list[str]
    minimum_privilege: MinimumPrivilege
    collection_method: str
    evidence_types: list[str]
    sensitivity: str
    timeout_seconds: int
    failure_semantics: str
    framework_mappings: dict[str, list[str]]
    coverage_domain: CoverageDomain
    module: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CollectorCapabilityDefinition":
        """Build a definition from its JSON representation."""

        return cls(
            capability_id=str(data["capabilityId"]),
            name=str(data["name"]),
            description=str(data.get("description", "")),
            supported_operating_systems=[
                str(item) for item in data.get("supportedOperatingSystems", [])
            ],
            minimum_privilege=MinimumPrivilege(data["minimumPrivilege"]),
            collection_method=str(data["collectionMethod"]),
            evidence_types=[str(item) for item in data.get("evidenceTypes", [])],
            sensitivity=str(data.get("sensitivity", "LOW")),
            timeout_seconds=int(data.get("timeoutSeconds", 30)),
            failure_semantics=str(
                data.get("failureSemantics", "PARTIAL_OR_UNKNOWN")
            ),
            framework_mappings={
                str(key): [str(item) for item in values]
                for key, values in data.get("frameworkMappings", {}).items()
            },
            coverage_domain=CoverageDomain(data["coverageDomain"]),
            module=str(data["module"]),
        )


@dataclass(slots=True)
class CapabilityResult:
    """Record the terminal result of one collection capability."""

    capability_id: str
    status: CapabilityStatus
    started_at: str
    completed_at: str
    evidence_count: int
    expected_evidence_count: int
    limitation_code: str | None = None
    safe_message: str | None = None


@dataclass(slots=True)
class CollectionPrivacyPolicy:
    """Control privacy-sensitive endpoint evidence collection."""

    include_hostname: bool = False
    hash_username: bool = True
    hash_tenant_id: bool = True
    include_ip_addresses: bool = False
    include_mac_addresses: bool = False
    include_software_inventory: bool = True
    include_browser_extensions: bool = False
    include_certificate_subjects: bool = False
    include_local_admin_names: bool = False
    include_file_paths: str = "REDACT_USER_PROFILE"
    include_raw_registry_values: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CollectionPrivacyPolicy":
        """Build a privacy policy from camel-case JSON."""

        return cls(
            include_hostname=bool(data.get("includeHostname", False)),
            hash_username=bool(data.get("hashUsername", True)),
            hash_tenant_id=bool(data.get("hashTenantId", True)),
            include_ip_addresses=bool(data.get("includeIpAddresses", False)),
            include_mac_addresses=bool(data.get("includeMacAddresses", False)),
            include_software_inventory=bool(
                data.get("includeSoftwareInventory", True)
            ),
            include_browser_extensions=bool(
                data.get("includeBrowserExtensions", False)
            ),
            include_certificate_subjects=bool(
                data.get("includeCertificateSubjects", False)
            ),
            include_local_admin_names=bool(
                data.get("includeLocalAdminNames", False)
            ),
            include_file_paths=str(
                data.get("includeFilePaths", "REDACT_USER_PROFILE")
            ),
            include_raw_registry_values=bool(
                data.get("includeRawRegistryValues", False)
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return the policy using the collector JSON contract."""

        return {
            "includeHostname": self.include_hostname,
            "hashUsername": self.hash_username,
            "hashTenantId": self.hash_tenant_id,
            "includeIpAddresses": self.include_ip_addresses,
            "includeMacAddresses": self.include_mac_addresses,
            "includeSoftwareInventory": self.include_software_inventory,
            "includeBrowserExtensions": self.include_browser_extensions,
            "includeCertificateSubjects": self.include_certificate_subjects,
            "includeLocalAdminNames": self.include_local_admin_names,
            "includeFilePaths": self.include_file_paths,
            "includeRawRegistryValues": self.include_raw_registry_values,
        }


@dataclass(slots=True)
class Assessment:
    """Represent a customer endpoint assessment."""

    assessment_id: str
    name: str
    customer_reference: str
    created_at: str
    created_by: str
    status: AssessmentStatus = AssessmentStatus.OPEN


@dataclass(slots=True)
class AssessmentSession:
    """Represent one bounded endpoint collection session."""

    assessment_id: str
    session_id: str
    customer_reference: str
    assessment_name: str
    created_at: str
    expires_at: str
    collector_mode: CollectorMode
    expected_device_count: int
    allowed_submission_count: int
    allowed_source_networks: list[str]
    allowed_source_addresses: list[str]
    framework_packs: list[str]
    collection_profile: str
    collection_profile_digest: str
    created_by: str
    status: SessionStatus
    token_id: str
    token_hash: str
    token_expires_at: str
    token_max_uses: int
    token_uses: int
    listen_address: str
    listen_port: int
    maximum_package_size: int
    request_timeout: int
    tls_certificate_path: str | None = None
    tls_private_key_path: str | None = None
    tls_fingerprint: str | None = None
    offline_public_key_path: str | None = None
    offline_private_key_path: str | None = None
    report_configuration: dict[str, Any] = field(default_factory=dict)
    audit_chain_start: str | None = None


@dataclass(slots=True)
class SubmissionNonce:
    """Represent a short-lived one-use submission nonce."""

    session_id: str
    submission_id: str
    nonce: str
    issued_at: str
    expires_at: str
    source_address: str
    used: bool = False


@dataclass(slots=True)
class SubmissionReceipt:
    """Represent a signed Console submission receipt."""

    assessment_id: str
    session_id: str
    submission_id: str
    received_at: str
    package_digest: str
    validation_status: str
    server_receipt_id: str
    server_signature: str
    cleanup_confirmed: bool | None = None


@dataclass(slots=True)
class CoverageLimitation:
    """Describe one capability-level coverage limitation."""

    capability_id: str
    domain: CoverageDomain
    reason: str


@dataclass(slots=True)
class AssessmentCoverage:
    """Represent endpoint collection coverage by security domain."""

    overall_coverage_percent: float
    coverage_by_domain: dict[str, float]
    limitations: list[CoverageLimitation] = field(default_factory=list)


@dataclass(slots=True)
class EndpointEvidenceRecord:
    """Canonical endpoint evidence independent of the collector transport."""

    schema_version: str
    assessment_id: str
    session_id: str
    submission_id: str
    device_id: str
    identity: dict[str, Any]
    operating_system: dict[str, Any]
    hardware: dict[str, Any]
    privilege_context: dict[str, Any]
    collection_coverage: AssessmentCoverage
    software: list[dict[str, Any]]
    updates: dict[str, Any]
    endpoint_protection: dict[str, Any]
    disk_encryption: dict[str, Any]
    network_configuration: dict[str, Any]
    security_policies: dict[str, Any]
    services: list[dict[str, Any]]
    scheduled_tasks: list[dict[str, Any]]
    startup: list[dict[str, Any]]
    certificates: list[dict[str, Any]]
    collection_limitations: list[dict[str, Any]]
    source_digests: dict[str, str]


@dataclass(slots=True)
class EndpointAnalysis:
    """Summarize one accepted endpoint analysis."""

    assessment_id: str
    session_id: str
    submission_id: str
    device_id: str
    score: int
    coverage: AssessmentCoverage
    findings: list[dict[str, Any]]
    report_path: str | None
    evidence_set_digest: str
    analysis_engine_version: str = "CSA-5.0"


@dataclass(slots=True)
class FleetFinding:
    """Represent one deduplicated finding across assessed endpoints."""

    fleet_finding_id: str
    rule_id: str
    title: str
    severity: str
    affected_endpoint_count: int
    assessed_endpoint_count: int
    affected_percent: float
    endpoint_references: list[str]
    systemic: bool
    framework_mappings: dict[str, list[str]]
    recommendation: str
    confidence: float
    risk_score: float


@dataclass(slots=True)
class FleetAnalysis:
    """Represent deterministic fleet-level assessment results."""

    assessment_id: str
    endpoint_count: int
    submission_count: int
    duplicate_endpoint_submission_count: int
    rejected_submission_count: int
    analysis_pending_count: int
    average_coverage_percent: float
    fleet_risk_score: float
    risk_rating: str
    endpoint_analyses: list[EndpointAnalysis]
    fleet_findings: list[FleetFinding]
    coverage_by_domain: dict[str, float]
    evidence_set_digest: str


def dataclass_dict(value: Any) -> dict[str, Any]:
    """Return a dataclass as a plain dictionary."""

    result = asdict(value)
    if not isinstance(result, dict):
        raise TypeError("Expected a dataclass object")
    return result
