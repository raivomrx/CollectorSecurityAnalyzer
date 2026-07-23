"""Deterministic active validation planning."""

from __future__ import annotations

from active_validation.authorization import require_scope
from active_validation.enums import RiskLevel, ValidatorStatus
from active_validation.models import (
    SafetyPolicy,
    ValidationAuthorization,
    ValidationPlan,
)
from active_validation.policy import validate_validator_safety
from active_validation.registry import ValidatorRegistry

PROFILE_RISKS = {
    "safe-read-only": {RiskLevel.SAFE_READ_ONLY},
    "safe-local": {RiskLevel.SAFE_READ_ONLY, RiskLevel.LOW_IMPACT},
    "controlled-temporary": {
        RiskLevel.SAFE_READ_ONLY,
        RiskLevel.LOW_IMPACT,
        RiskLevel.CONTROLLED_TEMPORARY_CHANGE,
    },
}


class PlanningError(ValueError):
    """Report an invalid, unsafe, or unauthorized validation selection."""


class ValidationPlanner:
    """Select only explicit, reviewed, authorized validators."""

    def __init__(self, registry: ValidatorRegistry) -> None:
        """Create a planner for a reviewed registry."""

        self.registry = registry

    def plan(
        self,
        run_id: str,
        requested_validator_ids: list[str],
        policy: SafetyPolicy,
        authorization: ValidationAuthorization,
        device_identifier: str,
        assessment_id: str | None = None,
        profile: str | None = None,
        platform: str | None = None,
        observed_privileges: tuple[str, ...] = ("STANDARD_USER",),
        available_rule_ids: set[str] | None = None,
    ) -> list[ValidationPlan]:
        """Return deterministic plans after all safety gates pass."""

        selected = self._resolve_selection(requested_validator_ids, profile)
        if not selected:
            raise PlanningError("At least one validator or profile must be selected")
        if len(selected) > policy.maximum_validators_per_run:
            raise PlanningError("Selection exceeds maximumValidatorsPerRun")
        require_scope(authorization, device_identifier, selected, assessment_id)
        plans: list[ValidationPlan] = []
        total_timeout = 0
        for sequence, validator_id in enumerate(selected, start=1):
            entry = self.registry.get(validator_id)
            if entry is None:
                raise PlanningError(f"Unknown validator: {validator_id}")
            if entry.status != ValidatorStatus.ACTIVE:
                raise PlanningError(
                    f"Validator is not ACTIVE: {validator_id} ({entry.status.value})"
                )
            definition = self.registry.definition(entry)
            if platform is not None and platform.casefold() not in {
                item.casefold() for item in definition.supported_platforms
            }:
                raise PlanningError(f"{validator_id}: platform is not supported")
            missing_privileges = set(definition.required_privileges) - set(
                observed_privileges
            )
            if missing_privileges:
                raise PlanningError(
                    f"{validator_id}: required privilege is unavailable"
                )
            if (
                available_rule_ids is not None
                and definition.supported_rule_ids
                and not set(definition.supported_rule_ids) & available_rule_ids
            ):
                raise PlanningError(
                    f"{validator_id}: no related passive rule is available"
                )
            allowed, reason = validate_validator_safety(definition, policy)
            if not allowed:
                raise PlanningError(f"{validator_id}: {reason}")
            timeout = min(
                definition.default_timeout_seconds,
                definition.maximum_timeout_seconds,
                policy.default_validator_timeout_seconds,
            )
            total_timeout += timeout
            plans.append(
                ValidationPlan(
                    run_id=run_id,
                    validator_id=validator_id,
                    validator_version=definition.version,
                    timeout_seconds=timeout,
                    risk_level=definition.risk_level,
                    requires_rollback=definition.requires_rollback,
                    temporary_object_prefix=f"CSA-VALIDATION-{run_id}",
                    sequence=sequence,
                )
            )
        if total_timeout > policy.maximum_total_duration_seconds:
            raise PlanningError("Planned duration exceeds policy limit")
        return sorted(
            plans,
            key=lambda item: (
                item.validator_id == "VAL-RESPONDER-EXPOSURE-001",
                item.sequence,
                item.validator_id,
            ),
        )

    def _resolve_selection(
        self,
        requested_validator_ids: list[str],
        profile: str | None,
    ) -> list[str]:
        """Resolve explicit IDs or one explicit risk profile."""

        if requested_validator_ids and profile:
            raise PlanningError("Use validator IDs or a profile, not both")
        if profile:
            risks = PROFILE_RISKS.get(profile)
            if risks is None:
                raise PlanningError(f"Unknown validation profile: {profile}")
            selected = [
                entry.validator_id
                for entry in self.registry.get_active()
                if self.registry.definition(entry).risk_level in risks
            ]
        else:
            selected = requested_validator_ids
        if len(selected) != len(set(selected)):
            raise PlanningError("Duplicate validator selection")
        return sorted(selected)
