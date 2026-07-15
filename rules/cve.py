"""Known vulnerabilities summary rule."""

from __future__ import annotations

import logging
from typing import Any

from analysis_context import AnalysisContext
from cve.enrichment_models import EnrichedCveAssessment, EnrichedCveScanSummary, ExploitationStatus
from cve.models import ApplicabilityStatus, CveAssessment
from cve.prioritization import PriorityLevel
from risk import Finding, Severity, Status
from rules.base import BaseRule
from rules.categories import RuleCategory
from rules.metadata import RuleMetadata

LOGGER = logging.getLogger(__name__)


class KnownVulnerabilitiesRule(BaseRule):
    """Create a summary finding from CVE scan results."""

    metadata = RuleMetadata(
        id="CVE-001",
        title="Known Vulnerabilities Detected",
        version="1.0",
        author="CSA",
        category=RuleCategory.SOFTWARE,
        severity=Severity.HIGH,
        enabled=True,
        description="Summarizes version-aware CVE scan results.",
    )

    def check(
        self,
        data: dict[str, Any],
        context: AnalysisContext | None = None,
    ) -> list[Finding]:
        """Return a CVE summary finding without performing API requests."""

        LOGGER.info("Running KnownVulnerabilitiesRule")
        if context is None or context.cve_summary is None:
            return [
                Finding(
                    rule_id=self.id,
                    severity=Severity.INFO,
                    status=Status.INFO,
                    evidence={"reason": "CVE scan was not executed"},
                    score=0,
                )
            ]

        summary = context.cve_summary
        enrichment = getattr(context, "cve_enrichment", None)
        affected = [
            item for item in summary.assessments
            if item.applicability == ApplicabilityStatus.AFFECTED
        ]
        possible = [
            item for item in summary.assessments
            if item.applicability == ApplicabilityStatus.POSSIBLY_AFFECTED
        ]
        not_evaluated = [
            item for item in summary.assessments
            if item.applicability == ApplicabilityStatus.NOT_EVALUATED
        ]

        affected_kev = _affected_kev(enrichment)
        possible_p1 = _possible_p1(enrichment)
        if affected_kev:
            status = Status.FAIL
            severity = Severity.CRITICAL
            score = 30
        elif possible_p1:
            status = Status.WARNING
            severity = Severity.HIGH
            score = 15
        elif affected:
            status = Status.FAIL
            severity = _severity_for_affected(affected)
            score = 20
        elif not summary.scan_complete or possible or not_evaluated:
            status = Status.WARNING
            severity = Severity.MEDIUM
            score = 10
        else:
            status = Status.PASS
            severity = Severity.INFO
            score = 0

        return [
            Finding(
                rule_id=self.id,
                severity=severity,
                status=status,
                evidence=_evidence(summary, affected, possible, enrichment),
                score=score,
            )
        ]


def _severity_for_affected(assessments: list[CveAssessment]) -> Severity:
    """Derive finding severity from affected CVSS scores."""

    scores = [item.cve.cvss_score for item in assessments if item.cve.cvss_score is not None]
    if not scores:
        return Severity.HIGH
    highest = max(scores)
    if highest >= 9.0:
        return Severity.CRITICAL
    if highest >= 7.0:
        return Severity.HIGH
    if highest >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _affected_kev(enrichment: EnrichedCveScanSummary | None) -> list[EnrichedCveAssessment]:
    """Return confirmed affected KEV assessments."""

    if enrichment is None:
        return []
    return [
        item for item in enrichment.assessments
        if item.base_assessment.applicability == ApplicabilityStatus.AFFECTED
        and item.exploitation_status == ExploitationStatus.KNOWN_EXPLOITED
    ]


def _possible_p1(enrichment: EnrichedCveScanSummary | None) -> list[EnrichedCveAssessment]:
    """Return P1 assessments that are not confirmed affected."""

    if enrichment is None:
        return []
    return [
        item for item in enrichment.assessments
        if item.priority.level == PriorityLevel.P1_IMMEDIATE
        and item.base_assessment.applicability != ApplicabilityStatus.AFFECTED
    ]


def _evidence(
    summary,
    affected: list[CveAssessment],
    possible: list[CveAssessment],
    enrichment: EnrichedCveScanSummary | None,
) -> dict[str, Any]:
    """Build CVE finding evidence."""

    noteworthy = affected + possible
    evidence = {
        "unique_products_scanned": summary.unique_products,
        "eligible_products": summary.eligible_products,
        "evaluated_products": summary.evaluated_products,
        "coverage_percent": summary.coverage_percent,
        "coverage_complete": summary.coverage_complete,
        "products_with_cpe": summary.products_with_cpe,
        "products_without_cpe": summary.products_without_cpe,
        "ambiguous_cpe_matches": summary.ambiguous_cpe_matches,
        "confirmed_vulnerability_count": summary.confirmed_vulnerabilities,
        "possible_vulnerability_count": summary.possible_vulnerabilities,
        "not_evaluated_count": summary.not_evaluated,
        "api_error_count": summary.api_errors,
        "affected_products": [item.software.product for item in affected],
        "installed_versions": {
            item.software.product: item.software.version for item in noteworthy
        },
        "cve_ids": [item.cve.cve_id for item in noteworthy],
        "cvss": {
            item.cve.cve_id: item.cve.cvss_score for item in noteworthy
        },
        "matched_cpe": {
            item.software.product: item.cpe.cpe_name if item.cpe else None
            for item in noteworthy
        },
        "scan_complete": summary.scan_complete,
    }
    if enrichment is not None:
        priority_counts = {
            level.value: sum(1 for item in enrichment.assessments if item.priority.level == level)
            for level in PriorityLevel
        }
        evidence.update(
            {
                "known_exploited_cve_count": enrichment.known_exploited_count,
                "ransomware_associated_cve_count": enrichment.ransomware_known_count,
                "unique_enriched_cves": enrichment.unique_enriched_cves,
                "enriched_assessment_count": enrichment.enriched_assessment_count,
                "unique_known_exploited_cves": enrichment.unique_known_exploited_cves,
                "known_exploited_assessment_count": enrichment.known_exploited_assessment_count,
                "unique_ransomware_cves": enrichment.unique_ransomware_cves,
                "ransomware_assessment_count": enrichment.ransomware_assessment_count,
                "enrichment_coverage_percent": enrichment.enrichment_coverage_percent,
                "priority_counts": priority_counts,
                "cna_confirmed_affected_count": enrichment.cna_confirmed_count,
                "source_conflict_count": enrichment.conflict_count,
                "manual_review_count": enrichment.manual_review_count,
                "enrichment_complete": enrichment.enrichment_complete,
                "provider_statuses": [
                    {
                        "provider": status.provider,
                        "enabled": status.enabled,
                        "succeeded": status.succeeded,
                        "used_stale_cache": status.used_stale_cache,
                        "records_loaded": status.records_loaded,
                        "error_message": status.error_message,
                    }
                    for status in enrichment.provider_statuses
                ],
                "top_priority_cve_ids": [
                    item.base_assessment.cve.cve_id
                    for item in sorted(
                        enrichment.assessments,
                        key=lambda row: row.priority.score,
                        reverse=True,
                    )[:5]
                ],
                "required_cisa_actions": {
                    item.base_assessment.cve.cve_id: item.kev.required_action
                    for item in enrichment.assessments
                    if item.kev is not None
                },
                "kev_due_dates": {
                    item.base_assessment.cve.cve_id: item.kev.due_date
                    for item in enrichment.assessments
                    if item.kev is not None
                },
                "source_provenance_summary": [
                    {
                        "cve": item.base_assessment.cve.cve_id,
                        "fields": [record.field_name for record in item.provenance],
                    }
                    for item in enrichment.assessments
                ],
            }
        )
    return evidence
