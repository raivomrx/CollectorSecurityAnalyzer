"""CVE Intelligence Engine data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from software.models import SoftwareProduct


class CpeMatchStatus(str, Enum):
    """Status of a CPE match candidate."""

    EXACT = "EXACT"
    ALIAS = "ALIAS"
    FUZZY = "FUZZY"
    AMBIGUOUS = "AMBIGUOUS"
    NOT_FOUND = "NOT_FOUND"


class ApplicabilityStatus(str, Enum):
    """Version-aware applicability assessment status."""

    AFFECTED = "AFFECTED"
    NOT_AFFECTED = "NOT_AFFECTED"
    POSSIBLY_AFFECTED = "POSSIBLY_AFFECTED"
    NOT_EVALUATED = "NOT_EVALUATED"


class CveDataQuality(str, Enum):
    """NVD CVE data quality level."""

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNENRICHED = "UNENRICHED"
    UNKNOWN = "UNKNOWN"


@dataclass(slots=True)
class CpeCandidate:
    """Represent a resolved CPE candidate for software."""

    cpe_name: str
    title: str
    vendor: str
    product: str
    version: str | None
    deprecated: bool
    confidence: int
    match_status: CpeMatchStatus
    source: str


@dataclass(slots=True)
class CveRecord:
    """Represent a normalized NVD CVE record."""

    cve_id: str
    description: str
    published: datetime | None
    last_modified: datetime | None
    cvss_version: str | None
    cvss_score: float | None
    severity: str
    vector: str | None
    cwes: list[str]
    references: list[str]
    configurations: list[dict[str, Any]]
    source_identifier: str | None
    vuln_status: str | None
    data_quality: CveDataQuality


@dataclass(slots=True)
class CveAssessment:
    """Represent one CVE applicability assessment for software."""

    software: SoftwareProduct
    cpe: CpeCandidate | None
    cve: CveRecord
    applicability: ApplicabilityStatus
    reason: str
    confidence: int
    matched_criteria: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CveScanError:
    """Represent a non-fatal CVE scan error."""

    product_key: str | None
    stage: str
    message: str
    retryable: bool


@dataclass(slots=True)
class CveScanSummary:
    """Represent a CVE inventory scan summary."""

    scanned_products: int
    unique_products: int
    eligible_products: int
    evaluated_products: int
    coverage_percent: float
    coverage_complete: bool
    products_with_cpe: int
    products_without_cpe: int
    ambiguous_cpe_matches: int
    confirmed_vulnerabilities: int
    possible_vulnerabilities: int
    not_evaluated: int
    api_errors: int
    assessments: list[CveAssessment]
    errors: list[CveScanError]
    scan_complete: bool
