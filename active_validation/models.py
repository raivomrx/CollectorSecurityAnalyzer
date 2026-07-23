"""Data models for active validation planning and execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from active_validation.enums import (
    ActiveValidationStatus,
    CorrelatedRuleStatus,
    ResponderExposureStatus,
    ResponderRiskLevel,
    RiskLevel,
    ValidatorStatus,
    TestIdentityMode,
)


@dataclass(slots=True, frozen=True)
class ValidatorDefinition:
    """Describe a versioned active validator and its safety requirements."""

    validator_id: str
    version: str
    title: str
    description: str
    supported_rule_ids: tuple[str, ...]
    supported_platforms: tuple[str, ...]
    required_privileges: tuple[str, ...]
    risk_level: RiskLevel
    network_impact: str
    system_change_impact: str
    requires_rollback: bool
    default_timeout_seconds: int
    maximum_timeout_seconds: int
    required_capabilities: tuple[str, ...]
    evidence_produced: tuple[str, ...]
    safety_constraints: tuple[str, ...]
    domain: str = "GENERAL"
    depends_on_validator_ids: tuple[str, ...] = ()
    optional_dependency_ids: tuple[str, ...] = ()
    required_evidence_types: tuple[str, ...] = ()
    produced_evidence_types: tuple[str, ...] = ()
    execution_order: int = 100


@dataclass(slots=True, frozen=True)
class RegistryEntry:
    """Bind a validator implementation to reviewed registry metadata."""

    validator_id: str
    version: str
    module: str
    class_name: str
    status: ValidatorStatus
    supported_rule_ids: tuple[str, ...]


@dataclass(slots=True)
class ValidationContext:
    """Expose only the minimum data needed by an isolated validator."""

    schema_version: str
    run_id: str
    validator_id: str
    timeout_seconds: int
    temporary_directory: str
    host_identifier_hash: str
    authorization_digest: str
    policy_digest: str
    platform: str
    observed_privileges: tuple[str, ...]
    passive_data: dict[str, Any]
    passive_results: dict[str, str]
    prior_results: list[dict[str, Any]]
    policy: dict[str, Any]
    authorization_scope: dict[str, Any] = field(default_factory=dict)
    authorization_permissions: dict[str, bool] = field(default_factory=dict)
    test_identity: dict[str, Any] | None = None
    profile: str | None = None
    transport_observation: dict[str, Any] | None = None
    plan_digest: str = ""
    live_transport_config: dict[str, Any] | None = None


@dataclass(slots=True, frozen=True)
class ApplicabilityResult:
    """Describe whether a validator can run in the supplied context."""

    applicable: bool
    status: ActiveValidationStatus
    reason: str = ""


@dataclass(slots=True, frozen=True)
class ValidationPlan:
    """Describe one authorized validator execution."""

    run_id: str
    validator_id: str
    validator_version: str
    timeout_seconds: int
    risk_level: RiskLevel
    requires_rollback: bool
    temporary_object_prefix: str
    sequence: int
    profile: str | None = None


@dataclass(slots=True)
class RollbackResult:
    """Describe rollback completion without exposing raw object data."""

    required: bool
    completed: bool
    manual_cleanup_required: bool = False
    remaining_objects: list[dict[str, str]] = field(default_factory=list)
    error_code: str | None = None


@dataclass(slots=True)
class ActiveValidationResult:
    """Represent a minimized, serializable active validation result."""

    schema_version: str
    run_id: str
    validator_id: str
    validator_version: str
    status: ActiveValidationStatus
    started_at: str
    completed_at: str
    duration_ms: int
    host_identifier_hash: str
    authorization_digest: str
    policy_digest: str
    rule_ids: list[str] = field(default_factory=list)
    risk_level: RiskLevel | None = None
    required_privileges: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    cleanup: RollbackResult = field(
        default_factory=lambda: RollbackResult(required=False, completed=True)
    )
    error_code: str | None = None
    error_summary: str | None = None


@dataclass(slots=True, frozen=True)
class CorrelatedRuleResult:
    """Keep passive, active, and correlated rule outcomes separate."""

    rule_id: str
    passive_status: str | None
    validator_id: str | None
    active_status: ActiveValidationStatus
    correlated_status: CorrelatedRuleStatus


@dataclass(slots=True)
class ResponderExposureAssessment:
    """Summarize Responder-style exposure without credential material."""

    validator_id: str = "VAL-RESPONDER-EXPOSURE-001"
    status: ResponderExposureStatus = ResponderExposureStatus.NOT_TESTED
    risk_level: ResponderRiskLevel = ResponderRiskLevel.UNKNOWN
    confidence: int = 0
    attack_prerequisites: list[str] = field(default_factory=list)
    observed_attack_paths: list[dict[str, str]] = field(default_factory=list)
    mitigating_controls: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ActiveValidationSummary:
    """Count active validation outcomes without changing their semantics."""

    planned: int = 0
    executed: int = 0
    passed: int = 0
    failed: int = 0
    inconclusive: int = 0
    skipped: int = 0
    errors: int = 0
    timeouts: int = 0
    rollback_failures: int = 0


@dataclass(slots=True)
class ActiveValidationRun:
    """Describe one complete active validation request and its audit output."""

    schema_version: str = "1.0"
    run_id: str = ""
    enabled: bool = False
    state: str = "DISABLED"
    assessment_id: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    policy_digest: str | None = None
    authorization_digest: str | None = None
    formal_authorization_verified: bool = False
    requested_validator_ids: list[str] = field(default_factory=list)
    planned_validator_ids: list[str] = field(default_factory=list)
    summary: ActiveValidationSummary = field(default_factory=ActiveValidationSummary)
    results: list[ActiveValidationResult] = field(default_factory=list)
    correlations: list[CorrelatedRuleResult] = field(default_factory=list)
    responder_exposure: ResponderExposureAssessment | None = None
    warnings: list[str] = field(default_factory=list)
    audit_log_path: str | None = None
    plan_digest: str | None = None
    assessment_depth: str = "SAFE_OBSERVATION"
    final_audit_entry_hash: str | None = None
    audit_entry_count: int = 0
    audit_verification_status: str = "NOT_VERIFIED"


@dataclass(slots=True, frozen=True)
class SafetyPolicy:
    """Represent validated active-validation safety policy."""

    schema_version: str
    enabled: bool
    allowed_risk_levels: tuple[RiskLevel, ...]
    allow_temporary_system_changes: bool
    allow_network_listeners: bool
    allow_outbound_network_tests: bool
    allow_loopback_network_tests: bool
    allowed_target_cidrs: tuple[str, ...]
    maximum_validators_per_run: int
    maximum_total_duration_seconds: int
    default_validator_timeout_seconds: int
    require_explicit_authorization: bool
    redact_sensitive_paths: bool
    retain_raw_event_data: bool
    digest: str
    allow_deep_responder_validation: bool = False
    allow_name_resolution_responses: bool = False
    allow_authentication_challenges: bool = False
    allow_temporary_network_listeners: bool = False
    allow_temporary_firewall_changes: bool = False
    allow_synthetic_credential_flow: bool = False
    allow_real_credential_observation: bool = False
    allow_credential_material_retention: bool = False
    allow_credential_relay: bool = False
    allow_hash_cracking: bool = False
    allow_external_targets: bool = False


@dataclass(slots=True, frozen=True)
class AuthorizationScope:
    """Describe explicitly authorized devices and validators."""

    device_identifiers: tuple[str, ...]
    validator_ids: tuple[str, ...]
    network_interfaces: tuple[str, ...] = ()
    allowed_source_addresses: tuple[str, ...] = ()
    allowed_target_addresses: tuple[str, ...] = ()
    allowed_protocols: tuple[str, ...] = ()


@dataclass(slots=True, frozen=True)
class AuthorizationPermissions:
    """Describe separately granted deep-validation operations."""

    name_resolution_spoofing: bool = False
    authentication_challenge: bool = False
    temporary_listener: bool = False
    temporary_firewall_change: bool = False
    credential_material_retention: bool = False
    credential_relay: bool = False
    hash_cracking: bool = False
    explicit_current_user_test: bool = False
    machine_account_observation: bool = False


@dataclass(slots=True, frozen=True)
class TestIdentity:
    """Describe a test identity without carrying credential material."""

    mode: TestIdentityMode
    identifier: str
    credential_reference: str
    authorized_for_authentication_test: bool


@dataclass(slots=True, frozen=True)
class ValidationAuthorization:
    """Represent a validated, time-limited active-validation grant."""

    schema_version: str
    authorized: bool
    assessment_id: str
    scope: AuthorizationScope
    authorized_by: str
    authorized_at: str
    expires_at: str
    purpose: str
    digest: str
    permissions: AuthorizationPermissions = field(
        default_factory=AuthorizationPermissions
    )
    test_identity: TestIdentity | None = None


@dataclass(slots=True, frozen=True)
class CredentialFlowObservation:
    """Store only minimized facts derived from an authentication flow."""

    flow_observed: bool
    protocol: str | None
    authentication_family: str | None
    test_identity_matched: bool
    identity_hash: str | None
    message_types_observed: tuple[str, ...]
    credential_material_retained: bool = False
    credential_material_written_to_disk: bool = False
    credential_material_included_in_report: bool = False
    relay_attempted: bool = False
    cracking_attempted: bool = False
