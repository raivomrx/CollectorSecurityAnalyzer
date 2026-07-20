"""Compliance assessment engine."""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone

from analysis_context import AnalysisContext
from compliance.coverage import evidence_coverage
from compliance.enums import ComplianceStatus
from compliance.evaluator import ComplianceEvaluator
from compliance.models import ComplianceProfile, ComplianceSummary, FrameworkAssessment
from compliance.repository import ControlMappingRepository, FrameworkRepository
from compliance.scoring import weighted_score
from risk import AuditFinding

LOGGER = logging.getLogger(__name__)


class ComplianceEngine:
    """Assess compliance profiles using existing CSA evidence."""

    def __init__(
        self,
        repository: FrameworkRepository | None = None,
        evaluator: ComplianceEvaluator | None = None,
        mapping_repository: ControlMappingRepository | None = None,
        framework_filter: list[str] | None = None,
        framework_versions: dict[str, str] | None = None,
    ) -> None:
        """Create an engine."""

        self.repository = repository or FrameworkRepository()
        self.mapping_repository = mapping_repository or (
            None if evaluator is not None else ControlMappingRepository(self.repository)
        )
        self.evaluator = evaluator or ComplianceEvaluator(mapping_repository=self.mapping_repository)
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
        warnings: list[str] = list(self.mapping_repository.warnings) if self.mapping_repository else []
        effective_profiles = self._effective_framework_profiles(profiles)
        for framework_id, selected_version, profile in effective_profiles:
            if self.framework_filter and framework_id not in self.framework_filter:
                continue
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
        covered_requirements = sum(item.covered_evidence_requirement_count for item in framework_assessments)
        requirement_count = sum(item.evidence_requirement_count for item in framework_assessments)
        covered_mandatory = sum(item.covered_mandatory_requirement_count for item in framework_assessments)
        mandatory_count = sum(item.mandatory_requirement_count for item in framework_assessments)
        coverage = round((covered_requirements / requirement_count) * 100, 1) if requirement_count else 0.0
        mandatory_coverage = round((covered_mandatory / mandatory_count) * 100, 1) if mandatory_count else 0.0
        overall = _overall_status(framework_assessments, warnings)
        return ComplianceSummary(
            profile_ids=[profile.profile_id for profile in profiles],
            framework_assessments=framework_assessments,
            total_controls=total_controls,
            applicable_controls=applicable_controls,
            assessed_controls=assessed_controls,
            evidence_coverage_percent=coverage,
            mandatory_evidence_coverage_percent=mandatory_coverage,
            overall_status=overall,
            warnings=warnings,
        )

    def _effective_framework_profiles(
        self,
        profiles: list[ComplianceProfile],
    ) -> list[tuple[str, str, ComplianceProfile]]:
        """Return de-duplicated framework/profile combinations."""

        effective: dict[tuple[str, str], ComplianceProfile] = {}
        order: list[tuple[str, str]] = []
        for profile in profiles:
            for framework_id, version in profile.framework_versions.items():
                selected_version = self.framework_versions.get(framework_id, version)
                key = (framework_id, selected_version)
                if key not in effective:
                    effective[key] = replace(
                        profile,
                        framework_versions={framework_id: selected_version},
                    )
                    order.append(key)
                    continue
                effective[key] = _merge_profiles(effective[key], profile, framework_id, selected_version)
        return [
            (framework_id, version, effective[(framework_id, version)])
            for framework_id, version in order
        ]


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
    evidence_requirement_count = sum(control.evidence_requirement_count for control in applicable)
    covered_evidence_requirement_count = sum(control.covered_evidence_requirement_count for control in applicable)
    mandatory_requirement_count = sum(control.mandatory_requirement_count for control in applicable)
    covered_mandatory_requirement_count = sum(control.covered_mandatory_requirement_count for control in applicable)
    complete = (
        complete
        and len(applicable) > 0
        and mandatory_requirement_count == covered_mandatory_requirement_count
    )
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
        mandatory_evidence_coverage_percent=_mandatory_coverage(covered_mandatory_requirement_count, mandatory_requirement_count),
        weighted_score_percent=weighted_score(controls),
        assessment_complete=complete,
        warnings=[],
        assessed_at=datetime.now(timezone.utc),
        evidence_requirement_count=evidence_requirement_count,
        covered_evidence_requirement_count=covered_evidence_requirement_count,
        mandatory_requirement_count=mandatory_requirement_count,
        covered_mandatory_requirement_count=covered_mandatory_requirement_count,
    )


def _merge_profiles(
    base: ComplianceProfile,
    incoming: ComplianceProfile,
    framework_id: str,
    version: str,
) -> ComplianceProfile:
    """Merge duplicate framework profiles deterministically."""

    overrides = {**base.policy_overrides, **incoming.policy_overrides}
    enabled = {**base.enabled_controls}
    excluded = {**base.excluded_controls}
    if incoming.enabled_controls.get(framework_id):
        enabled[framework_id] = incoming.enabled_controls[framework_id]
    if incoming.excluded_controls.get(framework_id):
        excluded[framework_id] = incoming.excluded_controls[framework_id]
    return replace(
        base,
        profile_id=f"{base.profile_id}+{incoming.profile_id}",
        framework_versions={framework_id: version},
        enabled_controls=enabled,
        excluded_controls=excluded,
        policy_overrides=overrides,
    )


def _mandatory_coverage(covered: int, total: int) -> float:
    """Calculate mandatory evidence coverage."""

    if total == 0:
        return 0.0
    return round((covered / total) * 100, 1)


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
    if assessments and sum(item.applicable_controls for item in assessments) == 0:
        return ComplianceStatus.NOT_ASSESSED
    if assessments:
        return ComplianceStatus.COMPLIANT
    return ComplianceStatus.NOT_ASSESSED
