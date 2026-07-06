"""Risk and audit finding models for Collector Security Analyzer."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from knowledge.models import Knowledge


@dataclass(slots=True)
class Finding:
    """Represent a technical finding produced by an analyzer rule."""

    rule_id: str
    severity: str
    status: str = "FAIL"
    score: float | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    affected_asset: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return the finding as a JSON-serializable dictionary."""

        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Create a finding from a dictionary."""

        return cls(**data)


@dataclass(slots=True)
class AuditFinding:
    """Combine a technical finding with knowledge-base context."""

    finding: Finding
    knowledge: Knowledge

    def to_dict(self) -> dict[str, Any]:
        """Return the audit finding as a JSON-serializable dictionary."""

        return {
            "finding": self.finding.to_dict(),
            "knowledge": asdict(self.knowledge),
        }
