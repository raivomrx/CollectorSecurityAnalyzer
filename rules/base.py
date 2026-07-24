"""Base abstractions for analyzer rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from analysis_context import AnalysisContext
from risk import Finding, Severity, Status
from rules.metadata import RuleMetadata


class BaseRule(ABC):
    """Abstract base class for all security rules."""

    metadata: RuleMetadata

    @property
    def id(self) -> str:
        """Return the rule identifier."""

        return self.metadata.id

    def run(
        self,
        data: dict[str, Any],
        context: AnalysisContext | None = None,
    ) -> list[Finding]:
        """Run the rule and return technical findings."""

        return self.check(data, context)

    def not_evaluated(
        self,
        required_setting_ids: list[str],
        reason: str = "EVIDENCE_MISSING",
    ) -> list[Finding]:
        """Return a technical non-result when required evidence is unavailable."""

        return [
            Finding(
                rule_id=self.id,
                severity=Severity.INFO,
                status=Status.NOT_EVALUATED,
                evidence={
                    "required_setting_ids": required_setting_ids,
                    "collection_status": reason,
                },
                score=0,
            )
        ]

    @abstractmethod
    def check(
        self,
        data: dict[str, Any],
        context: AnalysisContext | None = None,
    ) -> list[Finding]:
        """Run the rule against collector data and return findings."""
