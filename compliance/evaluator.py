"""Compliance control evaluator."""

from __future__ import annotations

from datetime import datetime, timezone

from analysis_context import AnalysisContext
from dataclasses import replace

from compliance.enums import (
    AssessmentScope,
    ComplianceStatus,
    EvidenceResult,
    EvidenceSourceType,
    MappingRelationship,
)
from compliance.evidence.composite_evidence import CompositeEvidenceExtractor
from compliance.evidence.field_evidence import FieldEvidenceExtractor
from compliance.evidence.finding_evidence import FindingEvidenceExtractor
from compliance.models import (
    ComplianceProfile,
    ControlAssessment,
    ControlDefinition,
    EvidenceRecord,
    RuleControlMapping,
)
from compliance.repository import ControlMappingRepository
from risk import AuditFinding


class ComplianceEvaluator:
    """Evaluate controls against available endpoint evidence."""

    def __init__(
        self,
        minimum_confidence: int = 60,
        mapping_repository: ControlMappingRepository | None = None,
    ) -> None:
        """Create an evaluator."""

        self.minimum_confidence = minimum_confidence
        self.mapping_repository = mapping_repository
        self.extractors = {
            EvidenceSourceType.FINDING: FindingEvidenceExtractor(),
            EvidenceSourceType.RAW_FIELD: FieldEvidenceExtractor(),
            EvidenceSourceType.RULE_METADATA: FindingEvidenceExtractor(),
        }
        self.composite_extractor = CompositeEvidenceExtractor()

    def evaluate_control(
        self,
        control: ControlDefinition,
        profile: ComplianceProfile,
        context: AnalysisContext,
        findings: list[AuditFinding],
    ) -> ControlAssessment:
        """Evaluate one control."""

        if not _is_applicable(control, profile):
            return _assessment(
                control,
                ComplianceStatus.NOT_APPLICABLE,
                None,
                0,
                [],
                "Control is outside profile scope.",
                None,
                False,
                False,
                assessed_scopes=[],
                unassessed_scopes=[],
            )
        if control.scope == [AssessmentScope.ORGANISATION]:
            return _assessment(
                control,
                ComplianceStatus.NOT_ASSESSED,
                None,
                0,
                [],
                "Organisation-level control cannot be assessed from endpoint evidence.",
                None,
                True,
                False,
                assessed_scopes=[],
                unassessed_scopes=control.scope,
            )
        if control.metadata.get("alternative_measure_allowed") and not control.evidence_requirements:
            return _assessment(
                control,
                ComplianceStatus.MANUAL_REVIEW,
                None,
                0,
                [],
                "Alternative equivalent measures require manual review.",
                None,
                True,
                True,
                assessed_scopes=[],
                unassessed_scopes=control.scope,
            )

        evidence = [self._extract(requirement, control, context, findings) for requirement in control.evidence_requirements]
        mandatory = [record for record in evidence if _mandatory(control, record.evidence_id)]
        related_findings = sorted({record.source_reference for record in evidence if record.source_type == EvidenceSourceType.FINDING})
        confidence = _decision_confidence(evidence)
        score = _evidence_score(evidence)
        has_unassessed_scope = AssessmentScope.ORGANISATION in control.scope and len(control.scope) > 1
        assessed_scopes = [scope for scope in control.scope if scope != AssessmentScope.ORGANISATION]
        unassessed_scopes = [scope for scope in control.scope if scope == AssessmentScope.ORGANISATION]
        has_partial_mapping = any(record.mapping_relationship == MappingRelationship.PARTIAL for record in evidence)
        has_context_only = any(record.mapping_relationship == MappingRelationship.CONTEXT_ONLY for record in evidence)
        has_unvalidated_mapping = any(record.mapping_validated is False for record in evidence)

        if any(record.result == EvidenceResult.CONTRADICTS and record.confidence >= self.minimum_confidence for record in mandatory):
            return _assessment(control, ComplianceStatus.NON_COMPLIANT, score, confidence, evidence, "Mandatory evidence contradicts the control.", "Review and remediate the related finding.", True, False, related_findings, assessed_scopes, unassessed_scopes)
        if any(record.result == EvidenceResult.CONTRADICTS for record in evidence) and any(record.result == EvidenceResult.SUPPORTS for record in evidence):
            return _assessment(control, ComplianceStatus.MANUAL_REVIEW, score, confidence, evidence, "Evidence is conflicting and requires manual review.", None, True, True, related_findings, assessed_scopes, unassessed_scopes)
        if has_unvalidated_mapping and mandatory:
            return _assessment(control, ComplianceStatus.MANUAL_REVIEW, score, confidence, evidence, "Mapping validation is incomplete; manual review required.", None, True, True, related_findings, assessed_scopes, unassessed_scopes)
        if mandatory and all(record.result == EvidenceResult.SUPPORTS and record.confidence >= self.minimum_confidence for record in mandatory):
            if has_unassessed_scope or has_partial_mapping or has_context_only:
                return _assessment(control, ComplianceStatus.PARTIALLY_COMPLIANT, score, confidence, evidence, "Endpoint evidence supports the control, but mapping or scope is partial.", None, True, has_context_only, related_findings, assessed_scopes, unassessed_scopes)
            if any(record.result in {EvidenceResult.MISSING, EvidenceResult.INCONCLUSIVE} for record in evidence if record not in mandatory):
                return _assessment(control, ComplianceStatus.PARTIALLY_COMPLIANT, score, confidence, evidence, "Mandatory evidence supports the control, but optional evidence is incomplete.", None, True, False, related_findings, assessed_scopes, unassessed_scopes)
            return _assessment(control, ComplianceStatus.COMPLIANT, score, confidence, evidence, "Available endpoint evidence supports the control.", None, True, False, related_findings, assessed_scopes, unassessed_scopes)
        if any(record.result == EvidenceResult.SUPPORTS for record in evidence):
            return _assessment(control, ComplianceStatus.PARTIALLY_COMPLIANT, score, confidence, evidence, "Some endpoint evidence supports the control, but required evidence is incomplete.", None, True, False, related_findings, assessed_scopes, unassessed_scopes)
        if any(record.result == EvidenceResult.INCONCLUSIVE for record in evidence):
            return _assessment(control, ComplianceStatus.MANUAL_REVIEW, score, confidence, evidence, "Evidence is inconclusive.", None, True, True, related_findings, assessed_scopes, unassessed_scopes)
        return _assessment(control, ComplianceStatus.NOT_ASSESSED, score, confidence, evidence, "Required evidence is missing from endpoint data.", None, True, False, related_findings, assessed_scopes, unassessed_scopes)

    def _extract(self, requirement, control: ControlDefinition, context: AnalysisContext, findings: list[AuditFinding]) -> EvidenceRecord:
        """Extract one requirement."""

        if requirement.extractor == "composite":
            return self.composite_extractor.extract(requirement, context, findings)
        extractor = self.extractors.get(requirement.source_type)
        if extractor is None:
            from compliance.evidence.base import evidence_record

            return evidence_record(requirement, EvidenceResult.INCONCLUSIVE, None, 0, "No extractor registered")
        record = extractor.extract(requirement, context, findings)
        if requirement.source_type == EvidenceSourceType.FINDING and self.mapping_repository is not None:
            mapping = _select_mapping(
                self.mapping_repository.get_by_control(control.framework_id, control.framework_version, control.control_id),
                requirement.source_reference,
            )
            return _apply_mapping(record, mapping)
        return record


def _is_applicable(control: ControlDefinition, profile: ComplianceProfile) -> bool:
    """Return whether a control applies to a profile."""

    if control.control_id in profile.excluded_controls.get(control.framework_id, []):
        return False
    if profile.enabled_controls.get(control.framework_id) and control.control_id not in profile.enabled_controls[control.framework_id]:
        return False
    if control.implementation_groups and profile.policy_overrides.get("CIS_IG"):
        return profile.policy_overrides["CIS_IG"] in control.implementation_groups
    return True


def _mandatory(control: ControlDefinition, evidence_id: str) -> bool:
    """Return whether evidence requirement is mandatory."""

    return any(req.evidence_id == evidence_id and req.mandatory for req in control.evidence_requirements)


def _select_mapping(
    mappings: list[RuleControlMapping],
    rule_id: str,
) -> RuleControlMapping | None:
    """Select a mapping for a finding requirement."""

    matches = [mapping for mapping in mappings if mapping.rule_id == rule_id]
    if not matches:
        return None
    return sorted(matches, key=lambda mapping: (mapping.validated, mapping.confidence), reverse=True)[0]


def _apply_mapping(record: EvidenceRecord, mapping: RuleControlMapping | None) -> EvidenceRecord:
    """Apply mapping relationship and confidence to a finding evidence record."""

    if mapping is None:
        return replace(
            record,
            result=EvidenceResult.INCONCLUSIVE,
            confidence=0,
            provenance=f"{record.provenance}; no validated control mapping",
        )

    result = record.result
    if not mapping.validated:
        result = EvidenceResult.INCONCLUSIVE
    elif mapping.relationship == MappingRelationship.CONTEXT_ONLY:
        result = EvidenceResult.INCONCLUSIVE
    elif mapping.relationship == MappingRelationship.CONTRADICTS:
        if record.result == EvidenceResult.SUPPORTS:
            result = EvidenceResult.CONTRADICTS
        elif record.result == EvidenceResult.CONTRADICTS:
            result = EvidenceResult.SUPPORTS

    return replace(
        record,
        result=result,
        confidence=min(record.confidence, mapping.confidence),
        mapping_relationship=mapping.relationship,
        mapping_confidence=mapping.confidence,
        mapping_validated=mapping.validated,
        provenance=f"{record.provenance}; mapping {mapping.relationship.value} {mapping.confidence}%",
    )


def _evidence_score(evidence: list[EvidenceRecord]) -> float | None:
    """Calculate evidence-weighted control score."""

    total = sum(record.weight for record in evidence if record.result != EvidenceResult.NOT_APPLICABLE)
    if total <= 0:
        return None
    supported = sum(record.weight for record in evidence if record.result == EvidenceResult.SUPPORTS)
    return round(supported / total, 2)


def _decision_confidence(evidence: list[EvidenceRecord]) -> int:
    """Calculate decision confidence from evaluated evidence."""

    weighted = [
        (
            record.weight,
            record.confidence if record.result != EvidenceResult.INCONCLUSIVE else int(record.confidence * 0.5),
        )
        for record in evidence
        if record.result not in {EvidenceResult.MISSING, EvidenceResult.NOT_APPLICABLE}
    ]
    total_weight = sum(weight for weight, _confidence in weighted)
    if total_weight <= 0:
        return 0
    return round(sum(weight * confidence for weight, confidence in weighted) / total_weight)


def _coverage_counts(evidence: list[EvidenceRecord]) -> tuple[int, int, int, int, float, float]:
    """Return total/covered requirement counts and percentages."""

    total = len([record for record in evidence if record.result != EvidenceResult.NOT_APPLICABLE])
    covered = len([
        record
        for record in evidence
        if record.result not in {EvidenceResult.MISSING, EvidenceResult.NOT_APPLICABLE}
    ])
    mandatory_total = len([
        record
        for record in evidence
        if record.mandatory and record.result != EvidenceResult.NOT_APPLICABLE
    ])
    mandatory_covered = len([
        record
        for record in evidence
        if record.mandatory and record.result not in {EvidenceResult.MISSING, EvidenceResult.NOT_APPLICABLE}
    ])
    coverage = round((covered / total) * 100, 1) if total else 0.0
    mandatory_coverage = round((mandatory_covered / mandatory_total) * 100, 1) if mandatory_total else 0.0
    return total, covered, mandatory_total, mandatory_covered, coverage, mandatory_coverage


def _assessment(
    control: ControlDefinition,
    status: ComplianceStatus,
    score: float | None,
    confidence: int,
    evidence: list[EvidenceRecord],
    rationale: str,
    remediation: str | None,
    applicable: bool,
    manual_review: bool,
    related_findings: list[str] | None = None,
    assessed_scopes: list[AssessmentScope] | None = None,
    unassessed_scopes: list[AssessmentScope] | None = None,
) -> ControlAssessment:
    """Create a control assessment."""

    (
        requirement_count,
        covered_count,
        mandatory_count,
        covered_mandatory_count,
        coverage,
        mandatory_coverage,
    ) = _coverage_counts(evidence)
    return ControlAssessment(
        control=control,
        status=status,
        score=score,
        confidence=confidence,
        evidence=evidence,
        rationale=rationale,
        remediation=remediation,
        applicable=applicable,
        manual_review_required=manual_review,
        related_findings=related_findings or [],
        assessed_at=datetime.now(timezone.utc),
        evidence_coverage_percent=coverage,
        mandatory_evidence_coverage_percent=mandatory_coverage,
        decision_confidence=confidence,
        assessed_scopes=assessed_scopes or [],
        unassessed_scopes=unassessed_scopes or [],
        evidence_requirement_count=requirement_count,
        covered_evidence_requirement_count=covered_count,
        mandatory_requirement_count=mandatory_count,
        covered_mandatory_requirement_count=covered_mandatory_count,
    )
