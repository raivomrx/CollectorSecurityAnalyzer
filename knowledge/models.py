"""Knowledge-base data models."""

from __future__ import annotations

from dataclasses import dataclass, field

UNKNOWN_TEXT = "Unknown"
DEFAULT_KNOWLEDGE_VERSION = "CSA-KB-2026.1"


@dataclass(slots=True)
class Reference:
    """Describe one external knowledge reference."""

    title: str
    url: str
    vendor: str
    type: str


@dataclass(slots=True)
class KnowledgeBase:
    """Represent a loaded knowledge base."""

    version: str
    entries: dict[str, "Knowledge"] = field(default_factory=dict)


@dataclass(slots=True)
class Knowledge:
    """Describe audit context for one rule identifier."""

    id: str
    title: str
    description: str
    risk: str
    recommendation: str
    frameworks: dict[str, list[str]] = field(default_factory=dict)
    references: list[Reference] = field(default_factory=list)
    knowledge_version: str = DEFAULT_KNOWLEDGE_VERSION

    @classmethod
    def unknown(
        cls,
        rule_id: str,
        knowledge_version: str = DEFAULT_KNOWLEDGE_VERSION,
    ) -> "Knowledge":
        """Return a safe placeholder for a missing knowledge entry."""

        return cls(
            id=rule_id,
            title=UNKNOWN_TEXT,
            description=UNKNOWN_TEXT,
            risk=UNKNOWN_TEXT,
            recommendation=UNKNOWN_TEXT,
            frameworks={},
            references=[],
            knowledge_version=knowledge_version,
        )
