"""Shared helpers for safe active validators."""

from __future__ import annotations

from datetime import datetime, timezone
from time import monotonic
from typing import Any

from active_validation.enums import ActiveValidationStatus
from active_validation.models import (
    ActiveValidationResult,
    ApplicabilityResult,
    RollbackResult,
    ValidationContext,
    ValidationPlan,
    ValidatorDefinition,
)


class BaseActiveValidator:
    """Provide safe defaults for validator applicability and rollback."""

    definition: ValidatorDefinition

    def describe(self) -> ValidatorDefinition:
        """Return immutable validator metadata."""

        return self.definition

    def check_applicability(self, context: ValidationContext) -> ApplicabilityResult:
        """Check platform and declared privileges."""

        if context.platform.casefold() not in {
            item.casefold() for item in self.definition.supported_platforms
        }:
            return ApplicabilityResult(
                applicable=False,
                status=ActiveValidationStatus.NOT_SUPPORTED,
                reason="Platform is not supported",
            )
        missing = set(self.definition.required_privileges) - set(
            context.observed_privileges
        )
        if missing:
            return ApplicabilityResult(
                applicable=False,
                status=ActiveValidationStatus.ACCESS_DENIED,
                reason="Required privilege is unavailable",
            )
        return ApplicabilityResult(
            applicable=True,
            status=ActiveValidationStatus.PLANNED,
        )

    def plan(self, context: ValidationContext) -> ValidationPlan:
        """Build a deterministic plan from the isolated context."""

        return ValidationPlan(
            run_id=context.run_id,
            validator_id=self.definition.validator_id,
            validator_version=self.definition.version,
            timeout_seconds=min(
                context.timeout_seconds,
                self.definition.maximum_timeout_seconds,
            ),
            risk_level=self.definition.risk_level,
            requires_rollback=self.definition.requires_rollback,
            temporary_object_prefix=f"CSA-VALIDATION-{context.run_id}",
            sequence=0,
        )

    def rollback(
        self,
        context: ValidationContext,
        plan: ValidationPlan,
    ) -> RollbackResult:
        """Report complete cleanup for validators with no temporary state."""

        return RollbackResult(
            required=plan.requires_rollback,
            completed=not plan.requires_rollback,
        )

    def result(
        self,
        context: ValidationContext,
        status: ActiveValidationStatus,
        started_at: str,
        started_clock: float,
        evidence: list[dict[str, Any]] | None = None,
        limitations: list[str] | None = None,
        cleanup: RollbackResult | None = None,
        error_code: str | None = None,
        error_summary: str | None = None,
    ) -> ActiveValidationResult:
        """Build a minimized result with consistent timestamps."""

        completed = datetime.now(timezone.utc).isoformat()
        return ActiveValidationResult(
            schema_version="1.0",
            run_id=context.run_id,
            validator_id=self.definition.validator_id,
            validator_version=self.definition.version,
            status=status,
            started_at=started_at,
            completed_at=completed,
            duration_ms=max(0, round((monotonic() - started_clock) * 1000)),
            host_identifier_hash=context.host_identifier_hash,
            authorization_digest=context.authorization_digest,
            policy_digest=context.policy_digest,
            evidence=evidence or [],
            limitations=limitations or [],
            cleanup=cleanup or RollbackResult(required=False, completed=True),
            error_code=error_code,
            error_summary=error_summary,
        )


def utc_start() -> tuple[str, float]:
    """Return wall-clock and monotonic start values."""

    return datetime.now(timezone.utc).isoformat(), monotonic()
