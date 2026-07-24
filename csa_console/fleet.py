"""Deterministic fleet-level finding aggregation and risk scoring."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from csa_console.canonical import sha256_value
from csa_console.models import FleetAnalysis, FleetFinding
from csa_console.storage import AssessmentStorage

SEVERITY_WEIGHT = {
    "CRITICAL": 100.0,
    "HIGH": 70.0,
    "MEDIUM": 40.0,
    "LOW": 20.0,
    "INFO": 5.0,
}


class FleetAnalyzer:
    """Aggregate endpoint analyses without multiplying systemic risk."""

    def __init__(self, storage: AssessmentStorage | None = None) -> None:
        """Create a fleet analyzer."""

        self.storage = storage or AssessmentStorage()

    def analyze(self, assessment_id: str) -> FleetAnalysis:
        """Build and persist a deterministic fleet analysis."""

        endpoint_data, all_endpoint_data, index_items = (
            self.load_latest_endpoint_data(assessment_id)
        )
        endpoint_count = len(endpoint_data)
        grouped: dict[str, dict[str, Any]] = {}
        for endpoint in endpoint_data:
            device_id = str(endpoint["deviceId"])
            for audit_finding in endpoint.get("findings", []):
                finding = audit_finding.get("finding", {})
                if finding.get("status") not in {"FAIL", "WARNING"}:
                    continue
                rule_id = str(finding.get("rule_id", finding.get("ruleId", "")))
                if not rule_id:
                    continue
                knowledge = audit_finding.get("knowledge", {})
                item = grouped.setdefault(
                    rule_id,
                    {
                        "title": str(knowledge.get("title", rule_id)),
                        "severity": str(finding.get("severity", "INFO")),
                        "endpoints": set(),
                        "frameworks": knowledge.get("frameworks", {}),
                        "recommendation": str(
                            knowledge.get("recommendation", "Review the affected control.")
                        ),
                    },
                )
                item["endpoints"].add(device_id)
                if SEVERITY_WEIGHT.get(str(finding.get("severity")), 0) > SEVERITY_WEIGHT.get(
                    str(item["severity"]), 0
                ):
                    item["severity"] = str(finding.get("severity"))
        fleet_findings: list[FleetFinding] = []
        for rule_id in sorted(grouped):
            item = grouped[rule_id]
            endpoints = sorted(item["endpoints"])
            affected_count = len(endpoints)
            percent = (
                round(affected_count * 100.0 / endpoint_count, 1)
                if endpoint_count
                else 0.0
            )
            systemic = affected_count >= 2 and percent >= 50.0
            confidence = 100.0
            base = SEVERITY_WEIGHT.get(str(item["severity"]), 5.0)
            prevalence_factor = 0.5 + (percent / 200.0)
            risk_score = round(min(100.0, base * prevalence_factor), 1)
            fleet_findings.append(
                FleetFinding(
                    fleet_finding_id=f"FF-{rule_id}",
                    rule_id=rule_id,
                    title=str(item["title"]),
                    severity=str(item["severity"]),
                    affected_endpoint_count=affected_count,
                    assessed_endpoint_count=endpoint_count,
                    affected_percent=percent,
                    endpoint_references=endpoints,
                    systemic=systemic,
                    framework_mappings={
                        str(key): [str(value) for value in values]
                        for key, values in item["frameworks"].items()
                    },
                    recommendation=str(item["recommendation"]),
                    confidence=confidence,
                    risk_score=risk_score,
                )
            )
        fleet_findings.sort(
            key=lambda item: (
                -SEVERITY_WEIGHT.get(item.severity, 0),
                -item.affected_percent,
                item.rule_id,
            )
        )
        risk_values = [item.risk_score for item in fleet_findings]
        fleet_risk = (
            round(
                min(
                    100.0,
                    max(risk_values)
                    + sum(
                        sorted(risk_values, reverse=True)[1:]
                    )
                    * 0.08,
                ),
                1,
            )
            if risk_values
            else 0.0
        )
        domain_values: dict[str, list[float]] = defaultdict(list)
        coverage_values: list[float] = []
        for endpoint in endpoint_data:
            coverage = endpoint.get("coverage", {})
            coverage_values.append(
                float(coverage.get("overallCoveragePercent", 0.0))
            )
            for domain, value in coverage.get("coverageByDomain", {}).items():
                domain_values[str(domain)].append(float(value))
        coverage_by_domain = {
            domain: round(sum(values) / len(values), 1)
            for domain, values in sorted(domain_values.items())
            if values
        }
        evidence_digest = sha256_value(
            [
                {
                    "submissionId": item["submissionId"],
                    "evidenceSetDigest": item["evidenceSetDigest"],
                }
                for item in sorted(
                    endpoint_data, key=lambda value: str(value["submissionId"])
                )
            ]
        )
        result = FleetAnalysis(
            assessment_id=assessment_id,
            endpoint_count=endpoint_count,
            submission_count=len(all_endpoint_data),
            duplicate_endpoint_submission_count=max(
                0, len(all_endpoint_data) - endpoint_count
            ),
            rejected_submission_count=len(
                list(
                    self.storage.path(
                        assessment_id, "submissions", "rejected"
                    ).glob("*.json")
                )
            ),
            analysis_pending_count=max(
                0, len(index_items) - len(all_endpoint_data)
            ),
            average_coverage_percent=(
                round(sum(coverage_values) / len(coverage_values), 1)
                if coverage_values
                else 0.0
            ),
            fleet_risk_score=fleet_risk,
            risk_rating=_risk_rating(fleet_risk),
            endpoint_analyses=[],
            fleet_findings=fleet_findings,
            coverage_by_domain=coverage_by_domain,
            evidence_set_digest=evidence_digest,
        )
        from csa_console.serde import model_to_dict

        self.storage.write_json(
            assessment_id, ("findings", "fleet.json"), model_to_dict(result)
        )
        return result

    def load_latest_endpoint_data(
        self, assessment_id: str
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """Return one latest analysis per device plus submission metadata."""

        findings_dir = self.storage.path(assessment_id, "findings")
        all_endpoint_data = [
            self.storage.read_json(assessment_id, "findings", path.name)
            for path in sorted(findings_dir.glob("*.json"), key=lambda item: item.name)
            if path.name != "fleet.json"
        ]
        index_path = self.storage.path(
            assessment_id, "submissions", "index.json"
        )
        index_items = (
            self.storage.read_json(
                assessment_id, "submissions", "index.json"
            ).get("items", [])
            if index_path.exists()
            else []
        )
        received_at = {
            str(item.get("submissionId")): str(item.get("receivedAt", ""))
            for item in index_items
            if isinstance(item, dict)
        }
        latest_by_device: dict[str, dict[str, Any]] = {}
        for item in all_endpoint_data:
            device_id = str(item["deviceId"])
            current = latest_by_device.get(device_id)
            item_order = (
                received_at.get(str(item["submissionId"]), ""),
                str(item["submissionId"]),
            )
            current_order = (
                received_at.get(str(current["submissionId"]), ""),
                str(current["submissionId"]),
            ) if current is not None else ("", "")
            if current is None or item_order > current_order:
                latest_by_device[device_id] = item
        endpoint_data = [
            latest_by_device[key] for key in sorted(latest_by_device)
        ]
        return endpoint_data, all_endpoint_data, [
            item for item in index_items if isinstance(item, dict)
        ]


def _risk_rating(score: float) -> str:
    """Return a documented fleet risk band."""

    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFORMATIONAL"
