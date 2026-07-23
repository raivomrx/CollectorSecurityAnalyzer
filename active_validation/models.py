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


@dataclass(slots=True, frozen=True)
class AuthorizationScope:
    """Describe explicitly authorized devices and validators."""

    device_identifiers: tuple[str, ...]
    validator_ids: tuple[str, ...]


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
