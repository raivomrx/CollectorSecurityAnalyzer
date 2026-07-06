"""Knowledge-base data models."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class Knowledge:
    """Describe audit context for one rule identifier."""

    id: str
    title: str
    description: str
    risk: str
    recommendation: str
    frameworks: dict[str, list[str]] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
