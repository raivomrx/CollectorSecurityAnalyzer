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
    if definition.network_impact == "LOOPBACK_LISTENER" and (
        not policy.allow_network_listeners
        or not policy.allow_loopback_network_tests
    ):
        return False, "Loopback listener is not allowed"
    if (
        definition.network_impact == "OUTBOUND"
        and not policy.allow_outbound_network_tests
    ):
        return False, "Outbound network tests are not allowed"
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
    ):
        if not isinstance(data[key], bool):
            raise SafetyPolicyError(f"Policy field {key} must be boolean")
    if data["requireExplicitAuthorization"] is not True:
        raise SafetyPolicyError("Explicit authorization cannot be disabled")
    if data["retainRawEventData"] is True:
        raise SafetyPolicyError("Raw event retention is not supported")
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
    )
