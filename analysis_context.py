"""Shared analysis context for one analyzer run."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from collector_schema.enums import PrivacyMode
from evidence.registry import WindowsEvidenceRegistry
from policies.loader import WindowsEndpointPolicy
from software.models import SoftwareInventory

if TYPE_CHECKING:
    from compliance.models import ComplianceSummary
    from collector_schema.models import CollectorDocument
    from cve.enrichment_models import EnrichedCveScanSummary
    from cve.models import CveScanSummary
    from frameworks.models import FrameworkEvaluation


@dataclass(slots=True)
class AnalysisContext:
    """Share expensive analysis objects across rules, services, and reports."""

    raw_data: dict[str, Any]
    software_inventory: SoftwareInventory
    collector_document: "CollectorDocument | None" = None
    evidence_registry: WindowsEvidenceRegistry | None = None
    policy_profile: WindowsEndpointPolicy | None = None
    privacy_mode: PrivacyMode = PrivacyMode.STANDARD
    skipped_categories: list[str] | None = None
    cve_summary: "CveScanSummary | None" = None
    cve_enrichment: "EnrichedCveScanSummary | None" = None
    compliance_summary: "ComplianceSummary | None" = None
    framework_evaluations: "list[FrameworkEvaluation] | None" = None
