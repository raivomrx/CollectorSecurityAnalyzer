"""Compliance control evaluator."""

from __future__ import annotations

from datetime import datetime, timezone

from analysis_context import AnalysisContext
from compliance.enums import AssessmentScope, ComplianceStatus, EvidenceResult, EvidenceSourceType
from compliance.evidence.composite_evidence import CompositeEvidenceExtractor
from compliance.evidence.field_evidence import FieldEvidenceExtractor
from compliance.evidence.finding_evidence import FindingEvidenceExtractor
from compliance.models import ComplianceProfile, ControlAssessment, ControlDefinition, EvidenceRecord
from risk import AuditFinding


class ComplianceEvaluator:
    """Evaluate controls against available endpoint evidence."""

    def __init__(self, minimum_confidence: int = 60) -> None:
        """Create an evaluator."""

        self.minimum_confidence = minimum_confidence
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
            return _assessment(control, ComplianceStatus.NOT_APPLICABLE, None, 0, [], "Control is outside profile scope.", None, False, False)
        if any(scope == AssessmentScope.ORGANISATION for scope in control.scope):
            return _assessment(control, ComplianceStatus.NOT_ASSESSED, None, 0, [], "Organisation-level control cannot be assessed from endpoint evidence.", None, True, False)
        if control.metadata.get("alternative_measure_allowed") and not control.evidence_requirements:
            return _assessment(control, ComplianceStatus.MANUAL_REVIEW, None, 0, [], "Alternative equivalent measures require manual review.", None, True, True)

        evidence = [self._extract(requirement, context, findings) for requirement in control.evidence_requirements]
        mandatory = [record for record in evidence if _mandatory(control, record.evidence_id)]
        related_findings = sorted({record.source_reference for record in evidence if record.source_type == EvidenceSourceType.FINDING})
        confidence = min((record.confidence for record in evidence), default=0)

        if any(record.result == EvidenceResult.CONTRADICTS and record.confidence >= self.minimum_confidence for record in mandatory):
            return _assessment(control, ComplianceStatus.NON_COMPLIANT, 0.0, confidence, evidence, "Mandatory evidence contradicts the control.", "Review and remediate the related finding.", True, False, related_findings)
        if any(record.result == EvidenceResult.CONTRADICTS for record in evidence) and any(record.result == EvidenceResult.SUPPORTS for record in evidence):
            return _assessment(control, ComplianceStatus.MANUAL_REVIEW, None, confidence, evidence, "Evidence is conflicting and requires manual review.", None, True, True, related_findings)
        if mandatory and all(record.result == EvidenceResult.SUPPORTS and record.confidence >= self.minimum_confidence for record in mandatory):
            if any(record.result in {EvidenceResult.MISSING, EvidenceResult.INCONCLUSIVE} for record in evidence if record not in mandatory):
                return _assessment(control, ComplianceStatus.PARTIALLY_COMPLIANT, 0.5, confidence, evidence, "Mandatory evidence supports the control, but optional evidence is incomplete.", None, True, False, related_findings)
            return _assessment(control, ComplianceStatus.COMPLIANT, 1.0, confidence, evidence, "Available endpoint evidence supports the control.", None, True, False, related_findings)
        if any(record.result == EvidenceResult.SUPPORTS for record in evidence):
            return _assessment(control, ComplianceStatus.PARTIALLY_COMPLIANT, 0.5, confidence, evidence, "Some endpoint evidence supports the control, but required evidence is incomplete.", None, True, False, related_findings)
        if any(record.result == EvidenceResult.INCONCLUSIVE for record in evidence):
            return _assessment(control, ComplianceStatus.MANUAL_REVIEW, None, confidence, evidence, "Evidence is inconclusive.", None, True, True, related_findings)
        return _assessment(control, ComplianceStatus.NOT_ASSESSED, None, confidence, evidence, "Required evidence is missing from endpoint data.", None, True, False, related_findings)

    def _extract(self, requirement, context: AnalysisContext, findings: list[AuditFinding]) -> EvidenceRecord:
        """Extract one requirement."""

        if requirement.extractor == "composite":
            return self.composite_extractor.extract(requirement, context, findings)
        extractor = self.extractors.get(requirement.source_type)
        if extractor is None:
            from compliance.evidence.base import evidence_record

            return evidence_record(requirement, EvidenceResult.INCONCLUSIVE, None, 0, "No extractor registered")
        return extractor.extract(requirement, context, findings)


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
) -> ControlAssessment:
    """Create a control assessment."""

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
    )
