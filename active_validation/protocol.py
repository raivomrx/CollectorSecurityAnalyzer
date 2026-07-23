"""Validator plug-in protocol."""

from __future__ import annotations

from typing import Protocol

from active_validation.models import (
    ActiveValidationResult,
    ApplicabilityResult,
    RollbackResult,
    ValidationContext,
    ValidationPlan,
    ValidatorDefinition,
)


class ActiveValidator(Protocol):
    """Define the isolated validator plug-in contract."""

    def describe(self) -> ValidatorDefinition:
        """Return immutable validator metadata."""

    def check_applicability(self, context: ValidationContext) -> ApplicabilityResult:
        """Check runtime applicability without changing the host."""

    def plan(self, context: ValidationContext) -> ValidationPlan:
        """Return a deterministic execution plan."""

    def execute(
        self,
        context: ValidationContext,
        plan: ValidationPlan,
    ) -> ActiveValidationResult:
        """Execute the validation and return minimized evidence."""

    def rollback(
        self,
        context: ValidationContext,
        plan: ValidationPlan,
    ) -> RollbackResult:
        """Remove only temporary objects created by this run."""
