"""Known vulnerabilities summary rule."""

from __future__ import annotations

import logging
from typing import Any

from analysis_context import AnalysisContext
from cve.models import ApplicabilityStatus, CveAssessment
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

        if affected:
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
                evidence=_evidence(summary, affected, possible),
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


def _evidence(summary, affected: list[CveAssessment], possible: list[CveAssessment]) -> dict[str, Any]:
    """Build CVE finding evidence."""

    noteworthy = affected + possible
    return {
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
