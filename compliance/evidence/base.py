"""Base evidence extractor contract and helpers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone

from analysis_context import AnalysisContext
from compliance.enums import EvidenceResult
from compliance.models import EvidenceRecord, EvidenceRequirement
from risk import AuditFinding


class EvidenceExtractor(ABC):
    """Base class for compliance evidence extractors."""

    name: str

    @abstractmethod
    def extract(
        self,
        requirement: EvidenceRequirement,
        context: AnalysisContext,
        findings: list[AuditFinding],
    ) -> EvidenceRecord:
        """Extract and evaluate one evidence requirement."""


def evidence_record(
    requirement: EvidenceRequirement,
    result: EvidenceResult,
    actual_value,
    confidence: int,
    provenance: str,
) -> EvidenceRecord:
    """Create an evidence record."""

    return EvidenceRecord(
        evidence_id=requirement.evidence_id,
        source_type=requirement.source_type,
        source_reference=requirement.source_reference,
        result=result,
        actual_value=actual_value,
        expected_value=requirement.expected_result,
        description=requirement.description,
        confidence=confidence,
        collected_at=None,
        evaluated_at=datetime.now(timezone.utc),
        provenance=provenance,
        weight=requirement.weight,
        mandatory=requirement.mandatory,
    )
