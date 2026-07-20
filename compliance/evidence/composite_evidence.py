"""Composite evidence extraction."""

from __future__ import annotations

from analysis_context import AnalysisContext
from dataclasses import replace

from compliance.enums import CompositeMode, EvidenceResult, EvidenceSourceType
from compliance.evidence.base import EvidenceExtractor, evidence_record
from compliance.evidence.field_evidence import FieldEvidenceExtractor
from compliance.evidence.finding_evidence import FindingEvidenceExtractor
from compliance.models import EvidenceRequirement
from risk import AuditFinding


class CompositeEvidenceExtractor(EvidenceExtractor):
    """Evaluate AND/OR composite evidence requirements."""

    name = "composite"

    def __init__(self) -> None:
        """Create a composite extractor."""

        self.extractors = {
            "FINDING": FindingEvidenceExtractor(),
            "RAW_FIELD": FieldEvidenceExtractor(),
        }

    def extract(
        self,
        requirement: EvidenceRequirement,
        context: AnalysisContext,
        findings: list[AuditFinding],
    ):
        """Evaluate composite child requirements."""

        try:
            mode = CompositeMode(str(requirement.parameters.get("mode", "AND")).upper())
        except ValueError:
            return evidence_record(requirement, EvidenceResult.INCONCLUSIVE, None, 0, "Unknown composite mode")
        children = requirement.parameters.get("requirements", [])
        records = []
        for item in children if isinstance(children, list) else []:
            if not isinstance(item, dict):
                return evidence_record(requirement, EvidenceResult.INCONCLUSIVE, None, 0, "Invalid composite child")
            if item.get("extractor") == "composite":
                return evidence_record(requirement, EvidenceResult.INCONCLUSIVE, None, 0, "Nested composite evidence unsupported")
            child = EvidenceRequirement(
                evidence_id=str(item.get("id", requirement.evidence_id)),
                description=str(item.get("description", "")),
                source_type=EvidenceSourceType(item["sourceType"]),
                source_reference=str(item.get("sourceReference", "")),
                expected_result=item.get("expectedResult"),
                operator=str(item.get("operator", "EXISTS")),
                weight=float(item.get("weight", 1.0)),
                mandatory=bool(item.get("mandatory", True)),
                extractor=item.get("extractor"),
                parameters=item.get("parameters", {}) if isinstance(item.get("parameters", {}), dict) else {},
            )
            extractor = self.extractors.get(child.source_type.value)
            if extractor is None:
                return evidence_record(requirement, EvidenceResult.INCONCLUSIVE, None, 0, "Unknown composite child source")
            records.append(extractor.extract(child, context, findings))

        if not records:
            return evidence_record(requirement, EvidenceResult.MISSING, None, 0, "Composite evidence missing")
        if mode == CompositeMode.OR:
            if any(record.result == EvidenceResult.SUPPORTS for record in records):
                result = EvidenceResult.SUPPORTS
            elif all(record.result == EvidenceResult.NOT_APPLICABLE for record in records):
                result = EvidenceResult.NOT_APPLICABLE
            elif any(record.result in {EvidenceResult.INCONCLUSIVE, EvidenceResult.MISSING} for record in records):
                result = EvidenceResult.INCONCLUSIVE
            else:
                result = EvidenceResult.CONTRADICTS
        else:
            if all(record.result == EvidenceResult.SUPPORTS for record in records):
                result = EvidenceResult.SUPPORTS
            elif any(record.result == EvidenceResult.NOT_APPLICABLE for record in records):
                result = EvidenceResult.NOT_APPLICABLE
            elif any(record.result == EvidenceResult.CONTRADICTS for record in records):
                result = EvidenceResult.CONTRADICTS
            else:
                result = EvidenceResult.INCONCLUSIVE
        record = evidence_record(
            requirement,
            result,
            [record.actual_value for record in records],
            _weighted_confidence(records),
            f"Composite {mode.value} evidence",
        )
        return replace(
            record,
            child_provenance=[child.provenance for child in records],
        )


def _weighted_confidence(records) -> int:
    """Return child-weighted confidence."""

    total = sum(record.weight for record in records)
    if total <= 0:
        return 0
    return round(sum(record.weight * record.confidence for record in records) / total)
