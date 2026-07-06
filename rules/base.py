"""Base abstractions for analyzer rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from risk import Finding
from rules.metadata import RuleMetadata


class BaseRule(ABC):
    """Abstract base class for all security rules."""

    metadata: RuleMetadata

    @property
    def id(self) -> str:
        """Return the rule identifier."""

        return self.metadata.id

    def run(self, data: dict[str, Any]) -> list[Finding]:
        """Run the rule and return technical findings."""

        return self.check(data)

    @abstractmethod
    def check(self, data: dict[str, Any]) -> list[Finding]:
        """Run the rule against collector data and return findings."""
