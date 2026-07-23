"""Deterministic active validation planning."""

from __future__ import annotations

from active_validation.authorization import AuthorizationError, require_scope
from active_validation.digest import sha256_digest
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
    "deep-responder-validation": {
        RiskLevel.SAFE_READ_ONLY,
        RiskLevel.LOW_IMPACT,
        RiskLevel.CONTROLLED_TEMPORARY_CHANGE,
    },
}
DEEP_VALIDATOR_ID = "VAL-RESPONDER-DEEP-001"
RESPONDER_AGGREGATE_ID = "VAL-RESPONDER-EXPOSURE-001"


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
        explicitly_selected = set(selected)
        if not selected:
            raise PlanningError("At least one validator or profile must be selected")
        selected = self._resolve_dependencies(selected, profile)
        if len(selected) > policy.maximum_validators_per_run:
            raise PlanningError("Selection exceeds maximumValidatorsPerRun")
        try:
            require_scope(
                authorization,
                device_identifier,
                selected,
                assessment_id,
            )
        except AuthorizationError as error:
            raise PlanningError(str(error)) from error
        ordered = self._topological_order(selected)
        plans: list[ValidationPlan] = []
        total_timeout = 0
        for sequence, validator_id in enumerate(ordered, start=1):
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
                and validator_id in explicitly_selected
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
                    profile=profile,
                )
            )
        if total_timeout > policy.maximum_total_duration_seconds:
            raise PlanningError("Planned duration exceeds policy limit")
        return plans

    def _resolve_selection(
        self,
        requested_validator_ids: list[str],
        profile: str | None,
    ) -> list[str]:
        """Resolve explicit IDs or one explicit risk profile."""

        if profile:
            risks = PROFILE_RISKS.get(profile)
            if risks is None:
                raise PlanningError(f"Unknown validation profile: {profile}")
            if requested_validator_ids:
                selected = list(requested_validator_ids)
            elif profile == "deep-responder-validation":
                selected = [DEEP_VALIDATOR_ID, RESPONDER_AGGREGATE_ID]
            else:
                selected = [
                    entry.validator_id
                    for entry in self.registry.get_active()
                    if self.registry.definition(entry).risk_level in risks
                    and entry.validator_id != DEEP_VALIDATOR_ID
                ]
            for validator_id in selected:
                entry = self.registry.get(validator_id)
                if entry is None:
                    continue
                risk = self.registry.definition(entry).risk_level
                if risk not in risks:
                    raise PlanningError(
                        f"{validator_id}: risk exceeds profile {profile}"
                    )
                if (
                    validator_id == DEEP_VALIDATOR_ID
                    and profile != "deep-responder-validation"
                ):
                    raise PlanningError(
                        "Responder Deep requires deep-responder-validation profile"
                    )
        else:
            selected = requested_validator_ids
            if DEEP_VALIDATOR_ID in selected:
                raise PlanningError(
                    "Responder Deep requires deep-responder-validation profile"
                )
        if len(selected) != len(set(selected)):
            raise PlanningError("Duplicate validator selection")
        return sorted(selected)

    def _resolve_dependencies(
        self,
        selected: list[str],
        profile: str | None,
    ) -> list[str]:
        """Expand required dependencies and the deep aggregate."""

        resolved = set(selected)
        if DEEP_VALIDATOR_ID in resolved:
            resolved.add(RESPONDER_AGGREGATE_ID)
        queue = list(resolved)
        while queue:
            validator_id = queue.pop()
            entry = self.registry.get(validator_id)
            if entry is None:
                continue
            definition = self.registry.definition(entry)
            for optional_id in definition.optional_dependency_ids:
                if self.registry.get(optional_id) is None:
                    raise PlanningError(
                        f"{validator_id}: unknown optional dependency {optional_id}"
                    )
            for dependency_id in definition.depends_on_validator_ids:
                dependency = self.registry.get(dependency_id)
                if dependency is None:
                    raise PlanningError(
                        f"{validator_id}: unknown dependency {dependency_id}"
                    )
                if dependency.status != ValidatorStatus.ACTIVE:
                    raise PlanningError(
                        f"{validator_id}: dependency is not ACTIVE: {dependency_id}"
                    )
                dependency_risk = self.registry.definition(dependency).risk_level
                if profile and dependency_risk not in PROFILE_RISKS[profile]:
                    raise PlanningError(
                        f"{validator_id}: dependency risk escalation: {dependency_id}"
                    )
                if dependency_id not in resolved:
                    resolved.add(dependency_id)
                    queue.append(dependency_id)
        return sorted(resolved)

    def _topological_order(self, selected: list[str]) -> list[str]:
        """Return stable dependency order and reject cycles."""

        selected_set = set(selected)
        temporary: set[str] = set()
        permanent: set[str] = set()
        result: list[str] = []

        def visit(validator_id: str) -> None:
            if validator_id in permanent:
                return
            if validator_id in temporary:
                raise PlanningError("Validator dependency cycle detected")
            temporary.add(validator_id)
            entry = self.registry.get(validator_id)
            if entry is None:
                raise PlanningError(f"Unknown validator: {validator_id}")
            definition = self.registry.definition(entry)
            dependencies = [
                item for item in definition.depends_on_validator_ids
                if item in selected_set
            ]
            for dependency_id in sorted(
                dependencies,
                key=self._execution_key,
            ):
                visit(dependency_id)
            temporary.remove(validator_id)
            permanent.add(validator_id)
            result.append(validator_id)

        for validator_id in sorted(selected, key=self._execution_key):
            visit(validator_id)
        return result

    def _execution_key(self, validator_id: str) -> tuple[int, str]:
        """Return stable metadata-driven ordering."""

        entry = self.registry.get(validator_id)
        if entry is None:
            return (10_000, validator_id)
        return (self.registry.definition(entry).execution_order, validator_id)


def plan_digest(
    plans: list[ValidationPlan],
    transport_config: dict[str, object] | None = None,
) -> str:
    """Return a run-independent digest for exact plan confirmation."""

    return sha256_digest({
        "validators": [
            {
                "validatorId": item.validator_id,
                "validatorVersion": item.validator_version,
                "timeoutSeconds": item.timeout_seconds,
                "riskLevel": item.risk_level.value,
                "requiresRollback": item.requires_rollback,
                "sequence": item.sequence,
                "profile": item.profile,
            }
            for item in plans
        ],
        "liveTransport": transport_config,
    })
