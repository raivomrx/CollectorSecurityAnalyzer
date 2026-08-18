"""Automated normalization and endpoint analysis pipeline."""

from __future__ import annotations

import json
from collections.abc import Callable
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
        from csa_console.submission import SubmissionService

        submission_service = SubmissionService(self.storage)
        submission_service.update_processing_state(
            assessment_id, submission_id, "NORMALIZING"
        )
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
        submission_service.update_processing_state(
            assessment_id, submission_id, "ANALYZING"
        )
        output_dir = self.storage.path(
            assessment_id, "reports", "endpoints"
        )
        cve_metadata: dict = {}
        findings, score, _inventory, report_path = analyze_file(
            raw_path,
            output_dir=output_dir,
            skip_cve=skip_cve,
            skip_enrichment=skip_enrichment,
            validate_input=True,
            privacy_mode="strict",
            analysis_metadata=cve_metadata,
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
            cve_analysis_status=str(
                cve_metadata.get("status", "NOT_PERFORMED")
            ),
            cve_summary=cve_metadata,
        )
        self.storage.write_json(
            assessment_id,
            ("findings", f"{submission_id}.json"),
            model_to_dict(analysis),
        )
        _append_intelligence_audit(
            audit,
            submission_id,
            normalized_data,
            cve_metadata,
            finding_values,
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
        submission_service.update_processing_state(
            assessment_id, submission_id, "COMPLETE"
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
        *,
        run_cve: bool = False,
        cve_progress_callback: Callable[[dict], None] | None = None,
    ) -> EndpointAnalysis:
        """Rerun analysis and persist failure after any pipeline exception."""

        try:
            return self._retry_analysis(
                assessment_id,
                submission_id,
                run_cve=run_cve,
                cve_progress_callback=cve_progress_callback,
            )
        except Exception:
            if run_cve:
                self.mark_cve_analysis_failed(assessment_id, submission_id)
            raise

    def _retry_analysis(
        self,
        assessment_id: str,
        submission_id: str,
        *,
        run_cve: bool = False,
        cve_progress_callback: Callable[[dict], None] | None = None,
    ) -> EndpointAnalysis:
        """Implement endpoint reanalysis after accepted evidence validation."""

        finding_path = self.storage.path(
            assessment_id, "findings", f"{submission_id}.json"
        )
        normalized_path = self.storage.path(
            assessment_id, "normalized", f"{submission_id}.json"
        )
        raw_path = self.storage.path(
            assessment_id,
            "submissions",
            "accepted",
            f"{submission_id}.evidence.json",
        )
        if not raw_path.exists() or not normalized_path.exists():
            raise ValueError(
                "Accepted and normalized endpoint evidence is required"
            )
        existing = (
            self.load_analysis(assessment_id, submission_id)
            if finding_path.exists()
            else {}
        )
        normalized = self.storage.read_json(
            assessment_id, "normalized", f"{submission_id}.json"
        )
        audit = ConsoleAuditLog(
            self.storage.path(assessment_id, "audit", "audit.jsonl")
        )
        audit.append(
            "analysis_retry_started",
            {
                "submissionId": submission_id,
                "cveAnalysisRequested": run_cve,
            },
        )
        if run_cve and existing:
            running = dict(existing)
            running["cveAnalysisStatus"] = "RUNNING"
            running["cveSummary"] = {
                **dict(existing.get("cveSummary", {})),
                "status": "RUNNING",
            }
            self.storage.write_json(
                assessment_id,
                ("findings", f"{submission_id}.json"),
                running,
            )
            audit.append(
                "cve_analysis_started",
                {"submissionId": submission_id},
            )
        cve_metadata: dict = {}
        try:
            findings, score, _inventory, report_path = analyze_file(
                raw_path,
                output_dir=self.storage.path(
                    assessment_id, "reports", "endpoints"
                ),
                skip_cve=not run_cve,
                skip_enrichment=not run_cve,
                validate_input=True,
                privacy_mode="strict",
                analysis_metadata=cve_metadata,
                cve_progress_callback=cve_progress_callback,
            )
        except Exception:
            if run_cve:
                self.mark_cve_analysis_failed(assessment_id, submission_id)
            raise
        finding_values = [item.to_dict() for item in findings]
        finding_values.sort(
            key=lambda item: (
                str(item["finding"]["rule_id"]),
                str(item["finding"]["status"]),
            )
        )
        coverage_data = existing.get(
            "coverage", normalized["collectionCoverage"]
        )
        from csa_console.enums import CoverageDomain
        from csa_console.models import AssessmentCoverage, CoverageLimitation

        coverage = AssessmentCoverage(
            overall_coverage_percent=float(
                coverage_data["overallCoveragePercent"]
            ),
            core_passive_coverage_percent=float(
                coverage_data.get(
                    "corePassiveCoveragePercent",
                    coverage_data["overallCoveragePercent"],
                )
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
            session_id=str(
                existing.get("sessionId", normalized["sessionId"])
            ),
            submission_id=submission_id,
            device_id=str(existing.get("deviceId", normalized["deviceId"])),
            score=score,
            coverage=coverage,
            findings=finding_values,
            report_path=str(report_path),
            evidence_set_digest=str(
                existing.get("evidenceSetDigest")
                or sha256_value(
                    {
                        "normalized": normalized,
                        "packageDigest": self._package_digest(
                            assessment_id, submission_id
                        ),
                    }
                )
            ),
            analysis_engine_version="CSA-5.2.4",
            cve_analysis_status=str(
                cve_metadata.get("status", "NOT_PERFORMED")
            ),
            cve_summary=cve_metadata,
        )
        self.storage.write_json(
            assessment_id,
            ("findings", f"{submission_id}.json"),
            model_to_dict(analysis),
        )
        _append_intelligence_audit(
            audit,
            submission_id,
            normalized,
            cve_metadata,
            finding_values,
        )
        audit.append(
            "analysis_retry_completed",
            {
                "submissionId": submission_id,
                "findingCount": len(findings),
                "score": score,
            },
        )
        if run_cve:
            audit.append(
                "cve_analysis_completed",
                _cve_audit_details(submission_id, analysis.cve_summary),
            )
        from csa_console.submission import SubmissionService

        submission_service = SubmissionService(self.storage)
        submission_service.update_processing_state(
            assessment_id, submission_id, "COMPLETE"
        )
        return analysis

    def mark_cve_analysis_failed(
        self,
        assessment_id: str,
        submission_id: str,
    ) -> None:
        """Persist an idempotent failed state after any CVE pipeline error."""

        finding_path = self.storage.path(
            assessment_id, "findings", f"{submission_id}.json"
        )
        if not finding_path.exists():
            return
        existing = self.load_analysis(assessment_id, submission_id)
        if existing.get("cveAnalysisStatus") == "FAILED":
            return
        failed = dict(existing)
        failed["cveAnalysisStatus"] = "FAILED"
        failed["cveSummary"] = {
            **dict(existing.get("cveSummary", {})),
            "status": "FAILED",
        }
        self.storage.write_json(
            assessment_id,
            ("findings", f"{submission_id}.json"),
            failed,
        )
        ConsoleAuditLog(
            self.storage.path(assessment_id, "audit", "audit.jsonl")
        ).append(
            "cve_analysis_failed",
            {"submissionId": submission_id},
        )

    def _package_digest(
        self, assessment_id: str, submission_id: str
    ) -> str:
        """Return the accepted package digest used by the evidence-set hash."""

        from csa_console.submission import SubmissionService

        for item in SubmissionService(self.storage).list_submissions(
            assessment_id
        ):
            if item.get("submissionId") == submission_id:
                return str(item.get("packageDigest", ""))
        raise ValueError("Submission metadata is unavailable")


def _append_intelligence_audit(
    audit: ConsoleAuditLog,
    submission_id: str,
    normalized: dict,
    cve_metadata: dict,
    findings: list[dict],
) -> None:
    """Record metadata-only Sprint 5.2 intelligence decisions."""

    identity = normalized.get("identity", {})
    software = normalized.get("softwareCollection", {})
    audit.append(
        "software_inventory_normalized",
        {
            "submissionId": submission_id,
            "records": int(software.get("recordsCollected", 0) or 0),
            "status": str(software.get("status", "NOT_EVALUATED")),
        },
    )
    audit.append(
        "endpoint_identity_resolved",
        {
            "submissionId": submission_id,
            "source": next(
                (
                    key
                    for key in ("computerName", "hostName", "hostname", "fqdn")
                    if identity.get(key)
                ),
                "FALLBACK",
            ),
        },
    )
    audit.append(
        "lifecycle_analysis_completed",
        {
            "submissionId": submission_id,
            "products": len(cve_metadata.get("softwareResults", [])),
            "dataVersion": str(cve_metadata.get("lifecycleDataVersion", "")),
        },
    )
    bitlocker = next(
        (
            item.get("finding", {})
            for item in findings
            if item.get("finding", {}).get("rule_id") == "BIT-001"
        ),
        {},
    )
    evidence = bitlocker.get("evidence", {})
    audit.append(
        "bitlocker_provider_selected",
        {
            "submissionId": submission_id,
            "provider": str(evidence.get("provider", "NOT_AVAILABLE")),
            "confidence": int(evidence.get("confidence", 0) or 0),
            "status": str(bitlocker.get("status", "NOT_EVALUATED")),
            "fallbackCount": len(evidence.get("fallbacks_attempted", [])),
        },
    )
    audit.append(
        "report_identity_mode_selected",
        {"submissionId": submission_id, "mode": "REAL_ENDPOINT_IDENTITIES"},
    )
    for evaluation in cve_metadata.get("productEvaluations", []):
        audit.append(
            "cve_product_evaluated",
            {
                "submissionId": submission_id,
                "productKey": str(evaluation.get("productKey", "")),
                "product": str(evaluation.get("displayName", "")),
                "installedVersion": str(evaluation.get("version", "")),
                "normalizationStatus": str(
                    evaluation.get("normalizationStatus", "UNKNOWN")
                ),
                "eligibilityStatus": str(
                    evaluation.get("eligibilityStatus", "NOT_EVALUATED")
                ),
                "provider": str(evaluation.get("provider", "NVD")),
                "productMappingStatus": str(
                    evaluation.get("productMappingStatus", "NOT_RUN")
                ),
                "mappingSource": str(
                    evaluation.get("mappingSource", "") or ""
                ),
                "cpeCandidateCount": int(
                    evaluation.get("cpeCandidateCount", 0) or 0
                ),
                "cpe": str(evaluation.get("cpe", "") or ""),
                "providerQueryStatus": str(
                    evaluation.get("providerQueryStatus", "NOT_RUN")
                ),
                "providerReason": str(
                    evaluation.get("providerReason", "") or ""
                ),
                "reason": str(evaluation.get("reason", "") or ""),
                "versionEvaluationStatus": str(
                    evaluation.get("versionEvaluationStatus", "NOT_RUN")
                ),
                "cveResultStatus": str(
                    evaluation.get("cveResultStatus", "NOT_EVALUATED")
                ),
                "confirmedCves": int(
                    evaluation.get("confirmedCves", 0) or 0
                ),
                "terminalStatus": str(
                    evaluation.get("terminalStatus", "NOT_EVALUATED")
                ),
                "failureStage": str(
                    evaluation.get("failureStage", "") or ""
                ),
                "failureReason": str(
                    evaluation.get("failureReason", "") or ""
                ),
                "retryable": bool(evaluation.get("retryable", False)),
            },
        )


def _cve_audit_details(
    submission_id: str,
    metadata: dict,
) -> dict:
    """Return metadata-only CVE completion details for the audit trail."""

    software_results = list(metadata.get("softwareResults", []))
    confirmed = sum(
        int(
            item.get("confirmedCveCount", item.get("confirmedCves", 0)) or 0
        )
        for item in software_results
    )
    possible = sum(
        int(
            item.get("possibleCveCount", item.get("possibleCves", 0)) or 0
        )
        for item in software_results
    )
    return {
        "submissionId": submission_id,
        "status": str(metadata.get("status", "NOT_EVALUATED")),
        "coveragePercent": float(metadata.get("coveragePercent", 0.0) or 0.0),
        "eligibleProducts": int(
            metadata.get("eligibleProducts", metadata.get("cveEligibleProducts", 0))
            or 0
        ),
        "evaluatedProducts": int(
            metadata.get(
                "evaluatedProducts",
                metadata.get("successfullyEvaluatedProducts", 0),
            )
            or 0
        ),
        "confirmedMatches": confirmed,
        "possibleMatches": possible,
        "cisaKevMatches": int(
            metadata.get(
                "cisaKevMatches",
                metadata.get("cisaKevUniqueCves", 0),
            )
            or 0
        ),
        "sourceVersions": {
            "lifecycle": str(metadata.get("lifecycleDataVersion", "")),
            "nvd": str(metadata.get("nvdDataVersion", "")),
            "cisaKev": str(metadata.get("kevDataVersion", "")),
        },
    }
