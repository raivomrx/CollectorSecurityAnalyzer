"""Shared analysis context for one analyzer run."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from software.models import SoftwareInventory


@dataclass(slots=True)
class AnalysisContext:
    """Share expensive analysis objects across rules, services, and reports."""

    raw_data: dict[str, Any]
    software_inventory: SoftwareInventory
    cve_results: list[Any] = field(default_factory=list)
