"""Explicit non-runnable validators retained for reviewed roadmap coverage."""

from active_validation.enums import ActiveValidationStatus, RiskLevel
from active_validation.models import (
    ActiveValidationResult,
    ValidationContext,
    ValidationPlan,
    ValidatorDefinition,
)
from active_validation.validators.base import BaseActiveValidator, utc_start


class _ReviewRequiredValidator(BaseActiveValidator):
    """Return a transparent non-supported result when invoked directly."""

    def execute(
        self,
        context: ValidationContext,
        plan: ValidationPlan,
    ) -> ActiveValidationResult:
        """Refuse execution until the validator has completed review."""

        started_at, started_clock = utc_start()
        return self.result(
            context,
            ActiveValidationStatus.NOT_SUPPORTED,
            started_at,
            started_clock,
            limitations=["Validator remains REVIEW_REQUIRED and cannot be planned."],
        )


class FirewallLoopbackValidator(_ReviewRequiredValidator):
    """Reserve a controlled firewall enforcement-path self-test."""

    definition = ValidatorDefinition(
        validator_id="VAL-WIN-FIREWALL-LOOPBACK-001",
        version="1.0.0",
        title="Windows Firewall enforcement-path self-test",
        description="Reserved loopback-only temporary-rule validation.",
        supported_rule_ids=("FW-005",),
        supported_platforms=("windows",),
        required_privileges=("LOCAL_ADMIN",),
        risk_level=RiskLevel.CONTROLLED_TEMPORARY_CHANGE,
        network_impact="LOOPBACK_LISTENER",
        system_change_impact="TEMPORARY_FIREWALL_RULE",
        requires_rollback=True,
        default_timeout_seconds=30,
        maximum_timeout_seconds=60,
        required_capabilities=("FIREWALL_ADMIN", "LOOPBACK"),
        evidence_produced=("BOOLEAN_OBSERVATION", "REDACTED_OBJECT_NAME"),
        safety_constraints=("LOOPBACK_ONLY", "CSA_NAMESPACE_ONLY"),
    )


class SmbSigningLocalValidator(_ReviewRequiredValidator):
    """Reserve safe local SMB signing negotiation validation."""

    definition = ValidatorDefinition(
        validator_id="VAL-SMB-SIGNING-LOCAL-001",
        version="1.0.0",
        title="Local SMB signing negotiation capability",
        description="Reserved until credential-free negotiation is stable.",
        supported_rule_ids=("PROTO-002",),
        supported_platforms=("windows",),
        required_privileges=("STANDARD_USER",),
        risk_level=RiskLevel.SAFE_READ_ONLY,
        network_impact="LOOPBACK_ONLY",
        system_change_impact="NONE",
        requires_rollback=False,
        default_timeout_seconds=15,
        maximum_timeout_seconds=30,
        required_capabilities=("SMB_SESSION_METADATA",),
        evidence_produced=("SIGNING_STATE",),
        safety_constraints=("NO_AUTHENTICATION_CHALLENGE", "NO_CREDENTIAL_MATERIAL"),
    )


def observation_definition(
    validator_id: str,
    title: str,
    rule_ids: tuple[str, ...],
) -> ValidatorDefinition:
    """Build metadata for a passive, no-response protocol observer."""

    return ValidatorDefinition(
        validator_id=validator_id,
        version="1.0.0",
        title=title,
        description="Reserved no-response local protocol observation.",
        supported_rule_ids=rule_ids,
        supported_platforms=("windows",),
        required_privileges=("LOCAL_ADMIN",),
        risk_level=RiskLevel.LOW_IMPACT,
        network_impact="LOCAL_OBSERVATION",
        system_change_impact="TRANSIENT_QUERY",
        requires_rollback=False,
        default_timeout_seconds=20,
        maximum_timeout_seconds=45,
        required_capabilities=("LOCAL_PACKET_OBSERVATION",),
        evidence_produced=("BOOLEAN_OBSERVATION", "NUMERIC_COUNT"),
        safety_constraints=(
            "NO_RESPONSE",
            "NO_PACKET_CAPTURE_RETENTION",
            "NO_AUTHENTICATION_TRIGGER",
        ),
        domain="RESPONDER_EXPOSURE",
    )


class LlmnrObserveValidator(_ReviewRequiredValidator):
    """Reserve LLMNR no-response runtime observation."""

    definition = observation_definition(
        "VAL-LLMNR-OBSERVE-001", "LLMNR no-response observation", ("PROTO-003",)
    )


class NbtnsObserveValidator(_ReviewRequiredValidator):
    """Reserve NBT-NS no-response runtime observation."""

    definition = observation_definition(
        "VAL-NBTNS-OBSERVE-001", "NBT-NS no-response observation", ("PROTO-004",)
    )


class MdnsObserveValidator(_ReviewRequiredValidator):
    """Reserve mDNS no-response runtime observation."""

    definition = observation_definition(
        "VAL-MDNS-WINDOWS-OBSERVE-001",
        "mDNS no-response observation",
        ("PROTO-003",),
    )


class OutboundSmbPathValidator(_ReviewRequiredValidator):
    """Reserve a pre-authentication outbound SMB path check."""

    definition = ValidatorDefinition(
        validator_id="VAL-OUTBOUND-SMB-PATH-001",
        version="1.0.0",
        title="Outbound SMB path availability",
        description="Reserved connection test that closes before negotiation.",
        supported_rule_ids=("PROTO-002",),
        supported_platforms=("windows",),
        required_privileges=("STANDARD_USER",),
        risk_level=RiskLevel.LOW_IMPACT,
        network_impact="OUTBOUND",
        system_change_impact="NONE",
        requires_rollback=False,
        default_timeout_seconds=10,
        maximum_timeout_seconds=20,
        required_capabilities=("PRE_AUTH_CONNECTION",),
        evidence_produced=("BOOLEAN_OBSERVATION",),
        safety_constraints=("NO_NEGOTIATION", "NO_AUTHENTICATION_CHALLENGE"),
        domain="RESPONDER_EXPOSURE",
    )


class HttpNtlmPolicyValidator(_ReviewRequiredValidator):
    """Reserve effective HTTP integrated-authentication policy validation."""

    definition = ValidatorDefinition(
        validator_id="VAL-HTTP-NTLM-POLICY-001",
        version="1.0.0",
        title="HTTP integrated authentication policy",
        description="Reserved read-only effective policy validation.",
        supported_rule_ids=("PROTO-006",),
        supported_platforms=("windows",),
        required_privileges=("STANDARD_USER",),
        risk_level=RiskLevel.SAFE_READ_ONLY,
        network_impact="NONE",
        system_change_impact="NONE",
        requires_rollback=False,
        default_timeout_seconds=10,
        maximum_timeout_seconds=20,
        required_capabilities=("EFFECTIVE_POLICY_READ",),
        evidence_produced=("POLICY_STATE", "PROVENANCE"),
        safety_constraints=("NO_HTTP_SERVER", "NO_AUTHENTICATION_CHALLENGE"),
        domain="RESPONDER_EXPOSURE",
    )


class NameResolutionFallbackValidator(_ReviewRequiredValidator):
    """Reserve effective fallback order validation."""

    definition = ValidatorDefinition(
        validator_id="VAL-NAME-RESOLUTION-FALLBACK-001",
        version="1.0.0",
        title="Name resolution fallback order",
        description="Reserved read-only effective fallback policy validation.",
        supported_rule_ids=("PROTO-003", "PROTO-004"),
        supported_platforms=("windows",),
        required_privileges=("STANDARD_USER",),
        risk_level=RiskLevel.SAFE_READ_ONLY,
        network_impact="NONE",
        system_change_impact="NONE",
        requires_rollback=False,
        default_timeout_seconds=10,
        maximum_timeout_seconds=20,
        required_capabilities=("EFFECTIVE_POLICY_READ",),
        evidence_produced=("POLICY_STATE",),
        safety_constraints=("NO_NAME_QUERY",),
        domain="RESPONDER_EXPOSURE",
    )
