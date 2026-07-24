"""Deterministic endpoint, fleet, executive and dashboard reporting."""

from __future__ import annotations

import shutil
from collections import Counter
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from csa_console.audit import ConsoleAuditLog
from csa_console.canonical import sha256_bytes, sha256_value
from csa_console.fleet import FleetAnalyzer
from csa_console.identifiers import utc_text
from csa_console.sessions import AssessmentSessionService
from csa_console.storage import AssessmentStorage

TEMPLATE_ROOT = Path(__file__).resolve().parent / "templates"


class ConsoleReportGenerator:
    """Generate local reports from canonical Console data only."""

    def __init__(self, storage: AssessmentStorage | None = None) -> None:
        """Create a report generator."""

        self.storage = storage or AssessmentStorage()
        self.environment = Environment(
            loader=FileSystemLoader(TEMPLATE_ROOT),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def endpoint_model(
        self, assessment_id: str, submission_id: str
    ) -> dict[str, Any]:
        """Build a deterministic endpoint report data model."""

        assessment = AssessmentSessionService(self.storage).load_assessment(
            assessment_id
        )
        endpoint = self.storage.read_json(
            assessment_id, "findings", f"{submission_id}.json"
        )
        evidence = self.storage.read_json(
            assessment_id, "normalized", f"{submission_id}.json"
        )
        findings = endpoint.get("findings", [])
        status_counts = Counter(
            str(item.get("finding", {}).get("status", "UNKNOWN"))
            for item in findings
        )
        severity_counts = Counter(
            str(item.get("finding", {}).get("severity", "INFO"))
            for item in findings
        )
        privilege = evidence.get("privilegeContext", {})
        model = {
            "reportType": "ENDPOINT",
            "assessment": {
                "assessmentId": assessment.assessment_id,
                "name": assessment.name,
                "customerReference": assessment.customer_reference,
            },
            "endpoint": endpoint,
            "evidence": evidence,
            "summary": {
                "score": endpoint.get("score", 0),
                "coverage": endpoint.get("coverage", {}),
                "findingCount": len(findings),
                "statusCounts": dict(sorted(status_counts.items())),
                "severityCounts": dict(sorted(severity_counts.items())),
                "collectionMode": "STANDARD USER",
                "administrativeRightsUsed": bool(
                    privilege.get("isElevated", False)
                ),
                "activeValidationPerformed": False,
            },
            "findings": sorted(
                findings,
                key=lambda item: (
                    _severity_order(
                        str(item.get("finding", {}).get("severity", "INFO"))
                    ),
                    str(item.get("finding", {}).get("rule_id", "")),
                ),
            ),
            "integrity": self._integrity(
                assessment_id,
                str(endpoint.get("evidenceSetDigest", "")),
            ),
        }
        model["integrity"]["reportModelDigest"] = sha256_value(model)
        return model

    def fleet_model(self, assessment_id: str) -> dict[str, Any]:
        """Build a deterministic technical fleet report model."""

        fleet_analyzer = FleetAnalyzer(self.storage)
        fleet = fleet_analyzer.analyze(assessment_id)
        assessment = AssessmentSessionService(self.storage).load_assessment(
            assessment_id
        )
        endpoints = []
        latest_endpoints, _all_endpoints, _index = (
            fleet_analyzer.load_latest_endpoint_data(assessment_id)
        )
        for endpoint in latest_endpoints:
            endpoints.append(
                {
                    "submissionId": endpoint["submissionId"],
                    "deviceId": endpoint["deviceId"],
                    "score": endpoint["score"],
                    "coverage": endpoint["coverage"]["overallCoveragePercent"],
                    "critical": _finding_count(endpoint, "CRITICAL"),
                    "high": _finding_count(endpoint, "HIGH"),
                    "bitLocker": _rule_status(endpoint, "BIT-001"),
                    "defender": _rule_status(endpoint, "DEF-001"),
                    "updates": _rule_status(endpoint, "UPD-001"),
                }
            )
        model = {
            "reportType": "FLEET_TECHNICAL",
            "assessment": {
                "assessmentId": assessment.assessment_id,
                "name": assessment.name,
                "customerReference": assessment.customer_reference,
            },
            "fleet": {
                "endpointCount": fleet.endpoint_count,
                "submissionCount": fleet.submission_count,
                "duplicateEndpointSubmissionCount": fleet.duplicate_endpoint_submission_count,
                "rejectedSubmissionCount": fleet.rejected_submission_count,
                "analysisPendingCount": fleet.analysis_pending_count,
                "averageCoveragePercent": fleet.average_coverage_percent,
                "fleetRiskScore": fleet.fleet_risk_score,
                "riskRating": fleet.risk_rating,
                "coverageByDomain": fleet.coverage_by_domain,
                "evidenceSetDigest": fleet.evidence_set_digest,
            },
            "endpoints": endpoints,
            "systemicFindings": [
                _fleet_finding_dict(item)
                for item in fleet.fleet_findings
                if item.systemic
            ],
            "isolatedFindings": [
                _fleet_finding_dict(item)
                for item in fleet.fleet_findings
                if not item.systemic
            ],
            "integrity": self._integrity(
                assessment_id, fleet.evidence_set_digest
            ),
        }
        model["integrity"]["reportModelDigest"] = sha256_value(model)
        return model

    def executive_model(self, assessment_id: str) -> dict[str, Any]:
        """Build a plain-language executive report model."""

        technical = self.fleet_model(assessment_id)
        systemic = technical["systemicFindings"]
        positive_count = 0
        latest_endpoints, _all_endpoints, _index = FleetAnalyzer(
            self.storage
        ).load_latest_endpoint_data(assessment_id)
        for endpoint in latest_endpoints:
            positive_count += sum(
                1
                for item in endpoint.get("findings", [])
                if item.get("finding", {}).get("status") == "PASS"
            )
        model = {
            "reportType": "EXECUTIVE",
            "assessment": technical["assessment"],
            "posture": technical["fleet"],
            "significantRisks": systemic[:10],
            "positiveObservationCount": positive_count,
            "priorityRemediation": [
                {
                    "priority": index,
                    "title": item["title"],
                    "affectedPercent": item["affectedPercent"],
                    "recommendation": item["recommendation"],
                }
                for index, item in enumerate(systemic[:5], start=1)
            ],
            "coverageStatement": (
                "Results reflect standard-user evidence. Controls requiring "
                "elevation remain explicitly unverified and are not treated as failures."
            ),
            "integrity": technical["integrity"],
        }
        model["integrity"] = dict(model["integrity"])
        model["integrity"]["reportModelDigest"] = sha256_value(model)
        return model

    def generate_endpoint(
        self, assessment_id: str, submission_id: str
    ) -> Path:
        """Render one endpoint report."""

        return self._render(
            assessment_id,
            "endpoint.html",
            self.endpoint_model(assessment_id, submission_id),
            "endpoints",
            f"{submission_id}.console.html",
        )

    def generate_fleet(self, assessment_id: str) -> Path:
        """Render the fleet technical report."""

        return self._render(
            assessment_id,
            "fleet.html",
            self.fleet_model(assessment_id),
            "fleet",
            "fleet-technical.html",
        )

    def generate_executive(self, assessment_id: str) -> Path:
        """Render the client executive report."""

        return self._render(
            assessment_id,
            "executive.html",
            self.executive_model(assessment_id),
            "executive",
            "executive.html",
        )

    def generate_dashboard(self, assessment_id: str) -> Path:
        """Render a local read-only fleet dashboard."""

        return self._render(
            assessment_id,
            "dashboard.html",
            self.fleet_model(assessment_id),
            "fleet",
            "dashboard.html",
        )

    def generate_all(self, assessment_id: str) -> list[Path]:
        """Generate all endpoint and fleet-level reports."""

        outputs = []
        for path in sorted(
            self.storage.path(assessment_id, "findings").glob("*.json"),
            key=lambda value: value.name,
        ):
            if path.name != "fleet.json":
                outputs.append(
                    self.generate_endpoint(assessment_id, path.stem)
                )
        outputs.extend(
            (
                self.generate_fleet(assessment_id),
                self.generate_executive(assessment_id),
                self.generate_dashboard(assessment_id),
            )
        )
        return outputs

    def _integrity(
        self, assessment_id: str, evidence_set_digest: str
    ) -> dict[str, Any]:
        """Build common report integrity references."""

        audit = ConsoleAuditLog(
            self.storage.path(assessment_id, "audit", "audit.jsonl")
        )
        audit_summary = audit.verify()
        return {
            "assessmentId": assessment_id,
            "evidenceSetDigest": evidence_set_digest,
            "auditHashAtGeneration": audit_summary["finalAuditEntryHash"],
            "analysisEngineVersion": "CSA-5.0",
            "frameworkPackDigests": self._framework_pack_digests(
                assessment_id
            ),
        }

    def _framework_pack_digests(self, assessment_id: str) -> dict[str, str]:
        """Return the immutable pack references captured by assessment sessions."""

        values: dict[str, str] = {}
        session_root = self.storage.path(assessment_id, "sessions")
        for path in sorted(session_root.glob("*.json"), key=lambda item: item.name):
            session = self.storage.read_json(
                assessment_id, "sessions", path.name
            )
            configured = session.get("reportConfiguration", {}).get(
                "frameworkPackDigests", {}
            )
            if isinstance(configured, dict):
                values.update(
                    {
                        str(key): str(value)
                        for key, value in configured.items()
                    }
                )
        return dict(sorted(values.items()))

    def _render(
        self,
        assessment_id: str,
        template_name: str,
        model: dict[str, Any],
        report_group: str,
        filename: str,
    ) -> Path:
        """Render, digest and audit one report."""

        output = self.storage.path(
            assessment_id, "reports", report_group, filename
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(TEMPLATE_ROOT / "style.css", output.parent / "style.css")
        html = self.environment.get_template(template_name).render(model=model)
        output.write_text(html, encoding="utf-8")
        digest = sha256_bytes(output.read_bytes())
        self.storage.write_json(
            assessment_id,
            ("reports", report_group, f"{filename}.integrity.json"),
            {
                "reportPath": filename,
                "reportDigest": digest,
                "reportModelDigest": model["integrity"]["reportModelDigest"],
                "generatedAt": utc_text(),
            },
        )
        ConsoleAuditLog(
            self.storage.path(assessment_id, "audit", "audit.jsonl")
        ).append(
            "report_generated",
            {
                "reportType": model["reportType"],
                "reportDigest": digest,
                "reportModelDigest": model["integrity"]["reportModelDigest"],
            },
        )
        return output


def _severity_order(value: str) -> int:
    """Return a stable severity sort order."""

    return {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
    }.get(value, 5)


def _finding_count(endpoint: dict[str, Any], severity: str) -> int:
    """Count endpoint findings by severity."""

    return sum(
        1
        for item in endpoint.get("findings", [])
        if item.get("finding", {}).get("severity") == severity
        and item.get("finding", {}).get("status") in {"FAIL", "WARNING"}
    )


def _rule_status(endpoint: dict[str, Any], rule_id: str) -> str:
    """Return one rule status or NOT_EVALUATED."""

    for item in endpoint.get("findings", []):
        finding = item.get("finding", {})
        if finding.get("rule_id") == rule_id:
            return str(finding.get("status", "NOT_EVALUATED"))
    return "NOT_EVALUATED"


def _fleet_finding_dict(value: Any) -> dict[str, Any]:
    """Serialize the fleet finding fields needed by reports."""

    from csa_console.serde import model_to_dict

    return model_to_dict(value)
