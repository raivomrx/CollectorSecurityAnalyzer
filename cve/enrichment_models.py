"""Data models for multi-source CVE enrichment."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

from cve.models import ApplicabilityStatus, CveAssessment, CveDataQuality, CveScanSummary

if TYPE_CHECKING:
    from cve.prioritization import VulnerabilityPriority
    from cve.provenance import DataConflict, ProvenanceRecord


class SourceType(str, Enum):
    """Supported vulnerability intelligence source types."""

    NVD = "NVD"
    CISA_KEV = "CISA_KEV"
    CVE_PROGRAM = "CVE_PROGRAM"
    CNA = "CNA"
    CVE_PROGRAM_CONTAINER = "CVE_PROGRAM_CONTAINER"
    CISA_ADP = "CISA_ADP"
    OTHER_ADP = "OTHER_ADP"


class ExploitationStatus(str, Enum):
    """Known exploitation state from the currently available intelligence."""

    KNOWN_EXPLOITED = "KNOWN_EXPLOITED"
    NO_KEV_EVIDENCE = "NO_KEV_EVIDENCE"
    UNKNOWN = "UNKNOWN"


class RansomwareUse(str, Enum):
    """Ransomware campaign use as reported by authoritative feeds."""

    KNOWN = "KNOWN"
    UNKNOWN = "UNKNOWN"
    NOT_LISTED = "NOT_LISTED"


class SsvcExploitation(str, Enum):
    """Normalized SSVC exploitation values."""

    ACTIVE = "ACTIVE"
    POC = "POC"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


@dataclass(slots=True, frozen=True)
class ReferenceRecord:
    """Represent a source reference with provenance."""

    url: str
    title: str | None
    tags: tuple[str, ...]
    source: SourceType


@dataclass(slots=True)
class AffectedVersionRange:
    """Represent one affected-version entry from a CVE Record container."""

    vendor: str | None
    product: str | None
    package_name: str | None
    package_url: str | None
    version: str | None
    status: str | None
    version_type: str | None
    less_than: str | None
    less_than_or_equal: str | None
    changes: list[dict[str, str]] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    modules: list[str] = field(default_factory=list)
    source: SourceType = SourceType.CNA


@dataclass(slots=True)
class KevRecord:
    """Represent one CISA KEV catalog entry."""

    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: date | None
    short_description: str
    required_action: str
    due_date: date | None
    known_ransomware_campaign_use: RansomwareUse
    notes: str | None
    cwes: list[str]


@dataclass(slots=True)
class SsvcDecision:
    """Represent an SSVC decision extracted from ADP data."""

    decision: str | None
    exploitation: SsvcExploitation
    exploitation_raw: str | None
    automatable: str | None
    technical_impact: str | None
    timestamp: datetime | None
    source: SourceType


@dataclass(slots=True)
class SourceEnrichment:
    """Represent source-specific enrichment for one CVE."""

    cve_id: str
    source: SourceType
    title: str | None = None
    descriptions: list[str] = field(default_factory=list)
    affected: list[AffectedVersionRange] = field(default_factory=list)
    metrics: list[dict[str, Any]] = field(default_factory=list)
    weaknesses: list[str] = field(default_factory=list)
    references: list[ReferenceRecord] = field(default_factory=list)
    kev: KevRecord | None = None
    ssvc: SsvcDecision | None = None
    provider_name: str | None = None
    provider_short_name: str | None = None
    record_version: str | None = None
    date_updated: datetime | None = None
    raw_available: bool = False
    data_quality: CveDataQuality = CveDataQuality.UNKNOWN
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class EnrichedCveAssessment:
    """Represent one CVE assessment after multi-source enrichment."""

    base_assessment: CveAssessment
    exploitation_status: ExploitationStatus
    kev: KevRecord | None
    ssvc: SsvcDecision | None
    cna_affected: list[AffectedVersionRange]
    cna_applicability: ApplicabilityStatus
    cna_applicability_reason: str
    merged_references: list[ReferenceRecord]
    source_enrichments: list[SourceEnrichment]
    priority: "VulnerabilityPriority"
    conflicts: list["DataConflict"]
    provenance: list["ProvenanceRecord"]
    enrichment_complete: bool


@dataclass(slots=True)
class ProviderStatus:
    """Represent provider availability for one analyzer run."""

    provider: str
    enabled: bool
    succeeded: bool
    used_stale_cache: bool
    records_loaded: int
    error_message: str | None
    partial: bool = False
    attempts: int = 0


@dataclass(slots=True)
class ProviderExecutionState:
    """Track provider execution truthfully at orchestration level."""

    provider: str
    attempts: int = 0
    succeeded: bool = True
    partial: bool = False
    used_stale_cache: bool = False
    records_loaded: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass(slots=True)
class EnrichedCveScanSummary:
    """Represent enriched vulnerability scan output."""

    base_summary: CveScanSummary
    assessments: list[EnrichedCveAssessment]
    unique_enriched_cves: int
    enriched_assessment_count: int
    unique_known_exploited_cves: int
    known_exploited_assessment_count: int
    unique_ransomware_cves: int
    ransomware_assessment_count: int
    known_exploited_count: int
    ransomware_known_count: int
    cna_confirmed_count: int
    conflict_count: int
    manual_review_count: int
    provider_statuses: list[ProviderStatus]
    enrichment_complete: bool
    enrichment_coverage_percent: float
