"""Risk model primitives for Collector Security Analyzer."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class Finding:
    """Represent one security finding produced by an analyzer rule."""

    rule_id: str
    title: str
    severity: str
    description: str
    recommendation: str
    category: str = "general"
    affected_asset: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    score: float | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Return the finding as a JSON-serializable dictionary."""

        data = asdict(self)
        data["created_at"] = self.created_at.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Create a finding from a dictionary."""

        values = dict(data)
        created_at = values.get("created_at")
        if isinstance(created_at, str):
            values["created_at"] = datetime.fromisoformat(created_at)
        return cls(**values)
