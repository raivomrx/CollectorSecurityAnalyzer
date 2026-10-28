"""Evidence extractor for existing CSA findings."""

from __future__ import annotations

from analysis_context import AnalysisContext
from compliance.enums import EvidenceOperator, EvidenceResult
from compliance.evidence.base import EvidenceExtractor, evidence_record
from compliance.models import EvidenceRequirement
from risk import AuditFinding


class FindingEvidenceExtractor(EvidenceExtractor):
    """Extract evidence from AuditFinding results."""

    name = "finding"

    def extract(
        self,
        requirement: EvidenceRequirement,
        context: AnalysisContext,
        findings: list[AuditFinding],
    ):
        """Evaluate a finding-based requirement."""

        finding = next((item.finding for item in findings if item.finding.rule_id == requirement.source_reference), None)
        if finding is None:
            return evidence_record(requirement, EvidenceResult.MISSING, None, 0, "Finding not produced")

        actual = finding.status.value
        if actual in {"NOT_EVALUATED", "NOT_APPLICABLE"}:
            return evidence_record(requirement, EvidenceResult.MISSING, actual, 0,
                                   f"Finding {finding.rule_id} does not establish compliance evidence")
        if actual in {"ERROR", "PARTIAL", "INFO", "WARNING"}:
            return evidence_record(requirement, EvidenceResult.INCONCLUSIVE, actual, 0,
                                   f"Finding {finding.rule_id} is insufficient to establish compliance")
        operator = EvidenceOperator(requirement.operator)
        if operator == EvidenceOperator.STATUS_IS:
            if actual == requirement.expected_result:
                return evidence_record(requirement, EvidenceResult.SUPPORTS, actual, 95, f"Finding {finding.rule_id}")
            return evidence_record(requirement, EvidenceResult.CONTRADICTS, actual, 95, f"Finding {finding.rule_id}")
        if operator == EvidenceOperator.SEVERITY_AT_LEAST:
            order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
            actual_severity = finding.severity.value
            expected = str(requirement.expected_result)
            if order.index(actual_severity) >= order.index(expected):
                return evidence_record(requirement, EvidenceResult.CONTRADICTS, actual_severity, 90, f"Finding {finding.rule_id}")
            return evidence_record(requirement, EvidenceResult.SUPPORTS, actual_severity, 75, f"Finding {finding.rule_id}")
        return evidence_record(requirement, EvidenceResult.INCONCLUSIVE, actual, 40, "Unsupported finding operator")
