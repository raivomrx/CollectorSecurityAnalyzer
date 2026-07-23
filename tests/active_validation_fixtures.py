"""Unsafe registry fixture used to prove prohibited validator rejection."""

from active_validation.enums import ActiveValidationStatus, RiskLevel
from active_validation.models import ActiveValidationResult, ValidationContext, ValidationPlan, ValidatorDefinition
from active_validation.validators.base import BaseActiveValidator, utc_start


class ProhibitedValidator(BaseActiveValidator):
    """Represent a validator that policy and registry must never activate."""

    definition = ValidatorDefinition(
        validator_id="VAL-PROHIBITED-001",
        version="1.0.0",
        title="Prohibited test fixture",
        description="Never runnable.",
        supported_rule_ids=("PS-002",),
        supported_platforms=("windows",),
        required_privileges=(),
        risk_level=RiskLevel.PROHIBITED,
        network_impact="NONE",
        system_change_impact="NONE",
        requires_rollback=False,
        default_timeout_seconds=1,
        maximum_timeout_seconds=1,
        required_capabilities=(),
        evidence_produced=(),
        safety_constraints=("NEVER_RUN",),
    )

    def execute(
        self,
        context: ValidationContext,
        plan: ValidationPlan,
    ) -> ActiveValidationResult:
        """Return a result only to satisfy the fixture interface."""

        started_at, started_clock = utc_start()
        return self.result(
            context,
            ActiveValidationStatus.ERROR,
            started_at,
            started_clock,
        )
