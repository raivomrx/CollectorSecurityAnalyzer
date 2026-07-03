"""Base abstractions for analyzer rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from risk import Finding


class BaseRule(ABC):
    """Abstract base class for all security rules."""

    id: str
    title: str
    description: str

    @abstractmethod
    def check(self, data: dict[str, Any]) -> list[Finding]:
        """Run the rule against collector data and return findings."""
