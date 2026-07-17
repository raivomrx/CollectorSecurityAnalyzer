"""Compliance assessment engine."""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timezone

from analysis_context import AnalysisContext
from compliance.coverage import evidence_coverage
from compliance.enums import ComplianceStatus
from compliance.evaluator import ComplianceEvaluator
from compliance.models import ComplianceProfile, ComplianceSummary, FrameworkAssessment
from compliance.repository import FrameworkRepository
from compliance.scoring import weighted_score
from risk import AuditFinding

LOGGER = logging.getLogger(__name__)


class ComplianceEngine:
    """Assess compliance profiles using existing CSA evidence."""

    def __init__(
        self,
        repository: FrameworkRepository | None = None,
        evaluator: ComplianceEvaluator | None = None,
        framework_filter: list[str] | None = None,
        framework_versions: dict[str, str] | None = None,
    ) -> None:
        """Create an engine."""

        self.repository = repository or FrameworkRepository()
        self.evaluator = evaluator or ComplianceEvaluator()
        self.framework_filter = framework_filter or []
        self.framework_versions = framework_versions or {}

    def assess(
        self,
        context: AnalysisContext,
        findings: list[AuditFinding],
        profiles: list[ComplianceProfile],
    ) -> ComplianceSummary:
        """Assess compliance for profiles."""

        framework_assessments: list[FrameworkAssessment] = []
        warnings: list[str] = []
        for profile in profiles:
            for framework_id, version in profile.framework_versions.items():
                if self.framework_filter and framework_id not in self.framework_filter:
                    continue
                selected_version = self.framework_versions.get(framework_id, version)
                try:
                    framework = self.repository.get_framework(framework_id, selected_version)
                    controls = [
                        self.evaluator.evaluate_control(control, profile, context, findings)
                        for control in framework.controls
                    ]
                    framework_assessments.append(
                        _framework_assessment(
                            framework,
                            profile.profile_id,
                            profile.version,
                            controls,
                        )
                    )
                except Exception as error:
                    LOGGER.exception("Compliance framework assessment failed")
                    warnings.append(f"{framework_id}: {error}")

        total_controls = sum(len(item.controls) for item in framework_assessments)
        applicable_controls = sum(item.applicable_controls for item in framework_assessments)
        assessed_controls = sum(item.assessed_controls for item in framework_assessments)
        coverage = 0.0
        if framework_assessments:
            coverage = round(
                sum(item.evidence_coverage_percent for item in framework_assessments) / len(framework_assessments),
                1,
            )
        overall = _overall_status(framework_assessments, warnings)
        return ComplianceSummary(
            profile_ids=[profile.profile_id for profile in profiles],
            framework_assessments=framework_assessments,
            total_controls=total_controls,
            applicable_controls=applicable_controls,
            assessed_controls=assessed_controls,
            evidence_coverage_percent=coverage,
            overall_status=overall,
            warnings=warnings,
        )


def _framework_assessment(
    framework,
    profile_id: str,
    profile_version: str,
    controls,
) -> FrameworkAssessment:
    """Build framework assessment summary."""

    counts = Counter(control.status for control in controls)
    applicable = [control for control in controls if control.applicable]
    assessed = [
        control for control in applicable
        if control.status
        not in {
            ComplianceStatus.NOT_ASSESSED,
            ComplianceStatus.NOT_APPLICABLE,
        }
    ]
    complete = counts[ComplianceStatus.NOT_ASSESSED] == 0 and counts[ComplianceStatus.MANUAL_REVIEW] == 0
    return FrameworkAssessment(
        framework=framework,
        profile_id=profile_id,
        profile_version=profile_version,
        controls=controls,
        compliant_count=counts[ComplianceStatus.COMPLIANT],
        non_compliant_count=counts[ComplianceStatus.NON_COMPLIANT],
        partially_compliant_count=counts[ComplianceStatus.PARTIALLY_COMPLIANT],
        not_assessed_count=counts[ComplianceStatus.NOT_ASSESSED],
        not_applicable_count=counts[ComplianceStatus.NOT_APPLICABLE],
        manual_review_count=counts[ComplianceStatus.MANUAL_REVIEW],
        assessed_controls=len(assessed),
        applicable_controls=len(applicable),
        evidence_coverage_percent=evidence_coverage(controls),
        weighted_score_percent=weighted_score(controls),
        assessment_complete=complete,
        warnings=[],
        assessed_at=datetime.now(timezone.utc),
    )


def _overall_status(assessments: list[FrameworkAssessment], warnings: list[str]) -> ComplianceStatus:
    """Return overall evidence status without organisation-wide certification."""

    if warnings:
        return ComplianceStatus.MANUAL_REVIEW
    if any(item.non_compliant_count for item in assessments):
        return ComplianceStatus.NON_COMPLIANT
    if any(item.manual_review_count for item in assessments):
        return ComplianceStatus.MANUAL_REVIEW
    if any(item.not_assessed_count for item in assessments):
        return ComplianceStatus.PARTIALLY_COMPLIANT
    if assessments:
        return ComplianceStatus.COMPLIANT
    return ComplianceStatus.NOT_ASSESSED
