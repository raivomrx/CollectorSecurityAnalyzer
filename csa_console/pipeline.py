"""Automated normalization and endpoint analysis pipeline."""

from __future__ import annotations

import json
from pathlib import Path

from analyzer import analyze_file
from csa_console.audit import ConsoleAuditLog
from csa_console.canonical import sha256_value
from csa_console.models import EndpointAnalysis
from csa_console.normalization import normalize_endpoint_package
from csa_console.package import ValidatedPackage
from csa_console.serde import model_to_dict
from csa_console.storage import AssessmentStorage


class ConsoleAnalysisPipeline:
    """Normalize accepted evidence and run the existing CSA analyzer."""

    def __init__(self, storage: AssessmentStorage | None = None) -> None:
        """Create an automated analysis pipeline."""

        self.storage = storage or AssessmentStorage()

    def analyze(
        self,
        package: ValidatedPackage,
        *,
        skip_cve: bool = True,
        skip_enrichment: bool = True,
    ) -> EndpointAnalysis:
        """Normalize and analyze one already-validated package."""

        manifest = package.manifest
        assessment_id = str(manifest["assessmentId"])
        submission_id = str(manifest["submissionId"])
        audit = ConsoleAuditLog(
            self.storage.path(assessment_id, "audit", "audit.jsonl")
        )
        audit.append(
            "evidence_normalization_started",
            {"submissionId": submission_id, "packageDigest": package.package_digest},
        )
        normalized = normalize_endpoint_package(package)
        normalized_data = model_to_dict(normalized)
        normalized_path = self.storage.write_json(
            assessment_id,
            ("normalized", f"{submission_id}.json"),
            normalized_data,
        )
        audit.append(
            "evidence_normalized",
            {
                "submissionId": submission_id,
                "normalizedDigest": sha256_value(normalized_data),
            },
        )
        raw_path = self.storage.write_json(
            assessment_id,
            ("submissions", "accepted", f"{submission_id}.evidence.json"),
            package.evidence,
        )
        audit.append("analysis_started", {"submissionId": submission_id})
        output_dir = self.storage.path(
            assessment_id, "reports", "endpoints"
        )
        findings, score, _inventory, report_path = analyze_file(
            raw_path,
            output_dir=output_dir,
            skip_cve=skip_cve,
            skip_enrichment=skip_enrichment,
            validate_input=True,
            privacy_mode="strict",
        )
        finding_values = [item.to_dict() for item in findings]
        finding_values.sort(
            key=lambda item: (
                str(item["finding"]["rule_id"]),
                str(item["finding"]["status"]),
            )
        )
        analysis = EndpointAnalysis(
            assessment_id=assessment_id,
            session_id=str(manifest["sessionId"]),
            submission_id=submission_id,
            device_id=str(manifest["deviceId"]),
            score=score,
            coverage=normalized.collection_coverage,
            findings=finding_values,
            report_path=str(report_path),
            evidence_set_digest=sha256_value(
                {
                    "normalized": normalized_data,
                    "packageDigest": package.package_digest,
                }
            ),
        )
        self.storage.write_json(
            assessment_id,
            ("findings", f"{submission_id}.json"),
            model_to_dict(analysis),
        )
        audit.append(
            "analysis_completed",
            {
                "submissionId": submission_id,
                "findingCount": len(findings),
                "score": score,
                "evidenceSetDigest": analysis.evidence_set_digest,
            },
        )
        audit.append(
            "endpoint_report_generated",
            {
                "submissionId": submission_id,
                "reportDigest": sha256_value(report_path.read_text(encoding="utf-8")),
            },
        )
        return analysis

    def load_analysis(
        self, assessment_id: str, submission_id: str
    ) -> dict:
        """Load a stored endpoint analysis."""

        return self.storage.read_json(
            assessment_id, "findings", f"{submission_id}.json"
        )

    def retry_analysis(
        self,
        assessment_id: str,
        submission_id: str,
    ) -> EndpointAnalysis:
        """Rerun analysis from already accepted and normalized evidence."""

        existing = self.load_analysis(assessment_id, submission_id)
        raw_path = self.storage.path(
            assessment_id,
            "submissions",
            "accepted",
            f"{submission_id}.evidence.json",
        )
        if not raw_path.exists():
            raise ValueError("Accepted endpoint evidence is unavailable")
        audit = ConsoleAuditLog(
            self.storage.path(assessment_id, "audit", "audit.jsonl")
        )
        audit.append(
            "analysis_retry_started", {"submissionId": submission_id}
        )
        findings, score, _inventory, report_path = analyze_file(
            raw_path,
            output_dir=self.storage.path(
                assessment_id, "reports", "endpoints"
            ),
            skip_cve=True,
            skip_enrichment=True,
            validate_input=True,
            privacy_mode="strict",
        )
        finding_values = [item.to_dict() for item in findings]
        finding_values.sort(
            key=lambda item: (
                str(item["finding"]["rule_id"]),
                str(item["finding"]["status"]),
            )
        )
        coverage_data = existing["coverage"]
        from csa_console.enums import CoverageDomain
        from csa_console.models import AssessmentCoverage, CoverageLimitation

        coverage = AssessmentCoverage(
            overall_coverage_percent=float(
                coverage_data["overallCoveragePercent"]
            ),
            coverage_by_domain={
                str(key): float(value)
                for key, value in coverage_data["coverageByDomain"].items()
            },
            limitations=[
                CoverageLimitation(
                    capability_id=str(item["capabilityId"]),
                    domain=CoverageDomain(item["domain"]),
                    reason=str(item["reason"]),
                )
                for item in coverage_data.get("limitations", [])
            ],
        )
        analysis = EndpointAnalysis(
            assessment_id=assessment_id,
            session_id=str(existing["sessionId"]),
            submission_id=submission_id,
            device_id=str(existing["deviceId"]),
            score=score,
            coverage=coverage,
            findings=finding_values,
            report_path=str(report_path),
            evidence_set_digest=str(existing["evidenceSetDigest"]),
            analysis_engine_version="CSA-5.0",
        )
        self.storage.write_json(
            assessment_id,
            ("findings", f"{submission_id}.json"),
            model_to_dict(analysis),
        )
        audit.append(
            "analysis_retry_completed",
            {
                "submissionId": submission_id,
                "findingCount": len(findings),
                "score": score,
            },
        )
        return analysis
