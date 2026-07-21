"""Risk and audit finding models for Collector Security Analyzer."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from knowledge.models import Knowledge


class Severity(str, Enum):
    """Supported finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Status(str, Enum):
    """Supported technical finding statuses."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    INFO = "INFO"
    NOT_EVALUATED = "NOT_EVALUATED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"


@dataclass(slots=True)
class Finding:
    """Represent a technical finding produced by an analyzer rule."""

    rule_id: str
    severity: Severity
    status: Status = Status.FAIL
    score: float | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    affected_asset: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return the finding as a JSON-serializable dictionary."""

        data = asdict(self)
        data["severity"] = self.severity.value
        data["status"] = self.status.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Create a finding from a dictionary."""

        values = dict(data)
        values["severity"] = Severity(values["severity"])
        values["status"] = Status(values.get("status", Status.FAIL))
        return cls(**values)


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
