"""Active validation safety policy loading and validation."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

from active_validation.digest import sha256_digest
from active_validation.enums import RiskLevel
from active_validation.json_io import load_strict_json
from active_validation.models import SafetyPolicy, ValidatorDefinition

DEFAULT_POLICY: dict[str, Any] = {
    "schemaVersion": "1.0",
    "enabled": False,
    "allowedRiskLevels": ["SAFE_READ_ONLY"],
    "allowTemporarySystemChanges": False,
    "allowNetworkListeners": False,
    "allowOutboundNetworkTests": False,
    "allowLoopbackNetworkTests": True,
    "allowedTargetCidrs": [],
    "maximumValidatorsPerRun": 10,
    "maximumTotalDurationSeconds": 300,
    "defaultValidatorTimeoutSeconds": 20,
    "requireExplicitAuthorization": True,
    "redactSensitivePaths": True,
    "retainRawEventData": False,
    "allowDeepResponderValidation": False,
    "allowNameResolutionResponses": False,
    "allowAuthenticationChallenges": False,
    "allowTemporaryNetworkListeners": False,
    "allowTemporaryFirewallChanges": False,
    "allowSyntheticCredentialFlow": False,
    "allowRealCredentialObservation": False,
    "allowCredentialMaterialRetention": False,
    "allowCredentialRelay": False,
    "allowHashCracking": False,
    "allowExternalTargets": False,
}

DEEP_POLICY_REQUIREMENTS = {
    "allowDeepResponderValidation": True,
    "allowNameResolutionResponses": True,
    "allowAuthenticationChallenges": True,
    "allowTemporaryNetworkListeners": True,
    "allowTemporaryFirewallChanges": True,
    "allowSyntheticCredentialFlow": True,
    "allowRealCredentialObservation": False,
    "allowCredentialMaterialRetention": False,
    "allowCredentialRelay": False,
    "allowHashCracking": False,
    "allowExternalTargets": False,
}


class SafetyPolicyError(ValueError):
    """Report an invalid or unsafe active validation policy."""


def default_policy() -> SafetyPolicy:
    """Return the built-in disabled policy."""

    return _parse_policy(DEFAULT_POLICY)


def load_policy(path: str | Path) -> SafetyPolicy:
    """Load and validate an active validation policy."""

    return _parse_policy(load_strict_json(path))


def validate_validator_safety(
    definition: ValidatorDefinition,
    policy: SafetyPolicy,
) -> tuple[bool, str]:
    """Check whether policy permits a validator definition."""

    if not policy.enabled:
        return False, "Active validation policy is disabled"
    if definition.risk_level in {RiskLevel.RESTRICTED, RiskLevel.PROHIBITED}:
        return False, f"Risk level {definition.risk_level.value} cannot run"
    if definition.risk_level not in policy.allowed_risk_levels:
        return False, "Validator risk level is not allowed"
    if (
        definition.risk_level == RiskLevel.CONTROLLED_TEMPORARY_CHANGE
        and not policy.allow_temporary_system_changes
    ):
        return False, "Temporary system changes are not allowed"
    if definition.network_impact in {"LOOPBACK_LISTENER", "SCOPED_LISTENER"} and (
        not policy.allow_network_listeners
    ):
        return False, "Network listener is not allowed"
    if definition.network_impact == "LOOPBACK_LISTENER" and (
        not policy.allow_loopback_network_tests
    ):
        return False, "Loopback listener is not allowed"
    if (
        definition.network_impact == "OUTBOUND"
        and not policy.allow_outbound_network_tests
    ):
        return False, "Outbound network tests are not allowed"
    return True, ""


def validate_deep_responder_policy(policy: SafetyPolicy) -> tuple[bool, str]:
    """Require every deep-validation permit and every mandatory prohibition."""

    values = {
        "allowDeepResponderValidation": policy.allow_deep_responder_validation,
        "allowNameResolutionResponses": policy.allow_name_resolution_responses,
        "allowAuthenticationChallenges": policy.allow_authentication_challenges,
        "allowTemporaryNetworkListeners":
            policy.allow_temporary_network_listeners,
        "allowTemporaryFirewallChanges":
            policy.allow_temporary_firewall_changes,
        "allowSyntheticCredentialFlow": policy.allow_synthetic_credential_flow,
        "allowRealCredentialObservation":
            policy.allow_real_credential_observation,
        "allowCredentialMaterialRetention":
            policy.allow_credential_material_retention,
        "allowCredentialRelay": policy.allow_credential_relay,
        "allowHashCracking": policy.allow_hash_cracking,
        "allowExternalTargets": policy.allow_external_targets,
    }
    missing = [
        key for key, expected in DEEP_POLICY_REQUIREMENTS.items()
        if values[key] is not expected
    ]
    if not policy.enabled:
        missing.insert(0, "enabled")
    if missing:
        return False, "Deep responder policy gate failed: " + ", ".join(missing)
    return True, ""


def _parse_policy(data: dict[str, Any]) -> SafetyPolicy:
    """Validate policy fields and return a typed policy."""

    required = set(DEFAULT_POLICY)
    missing = sorted(required - set(data))
    unknown = sorted(set(data) - required)
    if missing or unknown:
        raise SafetyPolicyError(
            f"Policy keys invalid; missing={missing}, unknown={unknown}"
        )
    if data["schemaVersion"] != "1.0":
        raise SafetyPolicyError("Unsupported policy schemaVersion")
    for key in (
        "enabled",
        "allowTemporarySystemChanges",
        "allowNetworkListeners",
        "allowOutboundNetworkTests",
        "allowLoopbackNetworkTests",
        "requireExplicitAuthorization",
        "redactSensitivePaths",
        "retainRawEventData",
        "allowDeepResponderValidation",
        "allowNameResolutionResponses",
        "allowAuthenticationChallenges",
        "allowTemporaryNetworkListeners",
        "allowTemporaryFirewallChanges",
        "allowSyntheticCredentialFlow",
        "allowRealCredentialObservation",
        "allowCredentialMaterialRetention",
        "allowCredentialRelay",
        "allowHashCracking",
        "allowExternalTargets",
    ):
        if not isinstance(data[key], bool):
            raise SafetyPolicyError(f"Policy field {key} must be boolean")
    if data["requireExplicitAuthorization"] is not True:
        raise SafetyPolicyError("Explicit authorization cannot be disabled")
    if data["retainRawEventData"] is True:
        raise SafetyPolicyError("Raw event retention is not supported")
    for prohibited in (
        "allowRealCredentialObservation",
        "allowCredentialMaterialRetention",
        "allowCredentialRelay",
        "allowHashCracking",
        "allowExternalTargets",
    ):
        if data[prohibited] is True:
            raise SafetyPolicyError(f"{prohibited} cannot be enabled")
    try:
        risks = tuple(RiskLevel(value) for value in data["allowedRiskLevels"])
    except (TypeError, ValueError) as error:
        raise SafetyPolicyError("Invalid allowedRiskLevels") from error
    if len(risks) != len(set(risks)):
        raise SafetyPolicyError("allowedRiskLevels contains duplicates")
    if RiskLevel.RESTRICTED in risks or RiskLevel.PROHIBITED in risks:
        raise SafetyPolicyError(
            "Restricted or prohibited risk levels cannot be enabled"
        )
    cidrs = data["allowedTargetCidrs"]
    if not isinstance(cidrs, list):
        raise SafetyPolicyError("allowedTargetCidrs must be an array")
    try:
        for cidr in cidrs:
            ipaddress.ip_network(cidr, strict=False)
    except (TypeError, ValueError) as error:
        raise SafetyPolicyError("Invalid target CIDR") from error
    if data["allowOutboundNetworkTests"] and not cidrs:
        raise SafetyPolicyError("Outbound tests require an explicit target CIDR")
    numeric = {
        "maximumValidatorsPerRun": (1, 100),
        "maximumTotalDurationSeconds": (1, 3600),
        "defaultValidatorTimeoutSeconds": (1, 300),
    }
    for key, bounds in numeric.items():
        value = data[key]
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not bounds[0] <= value <= bounds[1]
        ):
            raise SafetyPolicyError(f"Policy field {key} is outside allowed bounds")
    return SafetyPolicy(
        schema_version=data["schemaVersion"],
        enabled=data["enabled"],
        allowed_risk_levels=risks,
        allow_temporary_system_changes=data["allowTemporarySystemChanges"],
        allow_network_listeners=data["allowNetworkListeners"],
        allow_outbound_network_tests=data["allowOutboundNetworkTests"],
        allow_loopback_network_tests=data["allowLoopbackNetworkTests"],
        allowed_target_cidrs=tuple(cidrs),
        maximum_validators_per_run=data["maximumValidatorsPerRun"],
        maximum_total_duration_seconds=data["maximumTotalDurationSeconds"],
        default_validator_timeout_seconds=data["defaultValidatorTimeoutSeconds"],
        require_explicit_authorization=data["requireExplicitAuthorization"],
        redact_sensitive_paths=data["redactSensitivePaths"],
        retain_raw_event_data=data["retainRawEventData"],
        digest=sha256_digest(data),
        allow_deep_responder_validation=data["allowDeepResponderValidation"],
        allow_name_resolution_responses=data["allowNameResolutionResponses"],
        allow_authentication_challenges=data["allowAuthenticationChallenges"],
        allow_temporary_network_listeners=data[
            "allowTemporaryNetworkListeners"
        ],
        allow_temporary_firewall_changes=data[
            "allowTemporaryFirewallChanges"
        ],
        allow_synthetic_credential_flow=data["allowSyntheticCredentialFlow"],
        allow_real_credential_observation=data[
            "allowRealCredentialObservation"
        ],
        allow_credential_material_retention=data[
            "allowCredentialMaterialRetention"
        ],
        allow_credential_relay=data["allowCredentialRelay"],
        allow_hash_cracking=data["allowHashCracking"],
        allow_external_targets=data["allowExternalTargets"],
    )
