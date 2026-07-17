"""Shared analysis context for one analyzer run."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from software.models import SoftwareInventory

if TYPE_CHECKING:
    from compliance.models import ComplianceSummary
    from cve.enrichment_models import EnrichedCveScanSummary
    from cve.models import CveScanSummary


@dataclass(slots=True)
class AnalysisContext:
    """Share expensive analysis objects across rules, services, and reports."""

    raw_data: dict[str, Any]
    software_inventory: SoftwareInventory
    cve_summary: "CveScanSummary | None" = None
    cve_enrichment: "EnrichedCveScanSummary | None" = None
    compliance_summary: "ComplianceSummary | None" = None
