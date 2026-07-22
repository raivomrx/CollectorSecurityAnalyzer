"""Rule metadata model."""

from __future__ import annotations

from dataclasses import dataclass

from risk import Severity
from rules.categories import RuleCategory


@dataclass(slots=True)
class RuleMetadata:
    """Describe one analyzer rule for registry and reporting."""

    id: str
    title: str
    version: str
    author: str
    category: RuleCategory
    severity: Severity
    enabled: bool
    description: str
    deprecated: bool = False
    superseded_by: str | None = None
    introduced_in: str | None = None
    removed_in: str | None = None
