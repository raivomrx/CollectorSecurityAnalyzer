"""Provenance and conflict records for CVE enrichment."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from cve.enrichment_models import SourceType


@dataclass(slots=True, frozen=True)
class ProvenanceRecord:
    """Record the source of an enriched vulnerability value."""

    field_name: str
    value_summary: str
    source: SourceType
    provider: str | None
    retrieved_at: datetime


class ConflictType(str, Enum):
    """Types of source disagreement detected during enrichment."""

    AFFECTED_VERSION_DISAGREEMENT = "AFFECTED_VERSION_DISAGREEMENT"
    CVSS_DISAGREEMENT = "CVSS_DISAGREEMENT"
    CWE_DISAGREEMENT = "CWE_DISAGREEMENT"
    PRODUCT_DISAGREEMENT = "PRODUCT_DISAGREEMENT"
    OTHER = "OTHER"


@dataclass(slots=True)
class DataConflict:
    """Represent a source conflict that should remain visible."""

    conflict_type: ConflictType
    description: str
    sources: list[SourceType]
    requires_manual_review: bool


def retrieved_now() -> datetime:
    """Return a timezone-aware provenance timestamp."""

    return datetime.now(timezone.utc)
