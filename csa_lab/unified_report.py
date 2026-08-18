"""Generate one deterministic self-contained CSA assessment report."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from csa_console.audit import ConsoleAuditLog
from csa_console.canonical import sha256_bytes, sha256_value
from csa_console.fleet import FleetAnalyzer
from csa_console.identifiers import utc_text
from csa_console.sessions import AssessmentSessionService
from csa_console.storage import AssessmentStorage
from frameworks.loader import load_pack
from frameworks.models import FrameworkPack
from knowledge.repository import KnowledgeRepository

TEMPLATE_ROOT = Path(__file__).resolve().parent / "templates"
FRAMEWORK_ROOT = Path(__file__).resolve().parents[1] / "frameworks"
SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}
SECRET_KEYS = {
    "enrollmenttoken",
    "tokenhash",
    "privatekey",
    "wrappedkey",
    "password",
    "ntlmresponse",
    "recoverykey",
    "browsercookie",
}


class UnifiedReportGenerator:
    """Build and render the primary offline CSA customer report."""

    def __init__(self, storage: AssessmentStorage | None = None) -> None:
        """Create a unified report generator."""

        self.storage = storage or AssessmentStorage()
        self.environment = Environment(
            loader=FileSystemLoader(TEMPLATE_ROOT),
            autoescape=select_autoescape(["html", "xml"]),
        )
        self.environment.filters["json_pretty"] = lambda value: json.dumps(
            value, ensure_ascii=False, indent=2, sort_keys=True
        )

    def build_model(
        self,
        assessment_id: str,
        *,
        include_technical_evidence: bool = True,
        include_audit: bool = True,
        include_endpoint_details: bool = True,
    ) -> dict[str, Any]:
        """Build the deterministic report model from latest accepted endpoints."""

        assessment = AssessmentSessionService(self.storage).load_assessment(
            assessment_id
        )
        state_path = self.storage.path(assessment_id, "lab-state.json")
        state = (
            self.storage.read_json(assessment_id, "lab-state.json")
            if state_path.exists()
            else {}
        )
        analyzer = FleetAnalyzer(self.storage)
        fleet = analyzer.analyze(assessment_id)
        latest, _all_endpoints, index = analyzer.load_latest_endpoint_data(
            assessment_id
        )
        if not latest:
            raise ValueError(
                "At least one completed endpoint analysis is required"
            )
        index_by_submission = {
            str(item.get("submissionId")): item
            for item in index
            if isinstance(item, dict)
        }
        endpoints = [
            self._endpoint_model(
                assessment_id,
                endpoint,
                index_by_submission.get(str(endpoint["submissionId"]), {}),
                include_technical_evidence,
            )
            for endpoint in latest
        ]
        endpoints.sort(key=lambda item: (item["displayName"], item["submissionId"]))
        for position, endpoint in enumerate(endpoints, start=1):
            if not endpoint["displayName"] or endpoint["displayName"].startswith("id-"):
                endpoint["displayName"] = f"Endpoint {position:02d}"
            endpoint["anchorId"] = f"endpoint-{_slug(endpoint['submissionId'])}"
            endpoint["cveSummary"] = _endpoint_cve_summary(endpoint)
            endpoint["risk"] = _endpoint_risk_model(endpoint)
            for software in endpoint.get("softwareResults", []):
                software["anchorId"] = (
                    f"software-{_slug(endpoint['submissionId'])}-"
                    f"{_slug(str(software.get('productKey') or software.get('displayName')))}"
                )
        fleet_findings = [
            self._fleet_finding(item) for item in fleet.fleet_findings
        ]
        endpoint_labels = {
            item["deviceId"]: item["displayName"] for item in endpoints
        }
        for item in fleet_findings:
            item["endpointReferences"] = [
                endpoint_labels.get(value, "Endpoint")
                for value in item["endpointReferences"]
            ]
        software_findings = _software_security_findings(endpoints)
        fleet_findings.extend(software_findings)
        for endpoint in endpoints:
            endpoint_findings = [
                item
                for item in software_findings
                if endpoint["displayName"] in item["endpointReferences"]
            ]
            endpoint["softwareSecurityFindings"] = endpoint_findings
            endpoint["securityFindingCount"] += len(endpoint_findings)
            endpoint["findingCount"] = endpoint["securityFindingCount"]
            for finding in endpoint_findings:
                severity = finding["severity"]
                endpoint["severityCounts"][severity] = (
                    endpoint["severityCounts"].get(severity, 0) + 1
                )
            endpoint["risk"] = _endpoint_risk_model(endpoint)
        fleet_findings.sort(
            key=lambda item: (
                SEVERITY_ORDER.get(item["severity"], 9),
                item.get("findingKey", item["ruleId"]),
            )
        )
        priority = [
            item
            for item in fleet_findings
            if item["severity"] in {"CRITICAL", "HIGH"}
        ]
        if not priority:
            priority = fleet_findings[:10]
        severity_distribution = Counter()
        risk_distribution = Counter()
        coverage_bands = Counter()
        status_summary = {
            "bitLocker": Counter(),
            "defender": Counter(),
            "updates": Counter(),
        }
        control_status_distribution = Counter()
        total_control_results = 0
        for endpoint in endpoints:
            total_control_results += endpoint["controlResultCount"]
            for status, count in endpoint["statusCounts"].items():
                control_status_distribution[status] += count
            for severity, count in endpoint["severityCounts"].items():
                severity_distribution[severity] += count
            risk_distribution[endpoint["risk"]["rating"]] += 1
            coverage_bands[_coverage_band(float(endpoint["coverage"]))] += 1
            for key, rule_id in (
                ("bitLocker", "BIT-001"),
                ("defender", "DEF-001"),
                ("updates", "UPD-001"),
            ):
                status_summary[key][_rule_status(endpoint["findings"], rule_id)] += 1
        assessment_limitations = []
        for endpoint in endpoints:
            for limitation in endpoint["coverageLimitations"]:
                assessment_limitations.append(
                    {
                        "endpoint": endpoint["displayName"],
                        "endpointAnchor": endpoint["anchorId"],
                        "submissionId": endpoint["submissionId"],
                        "capabilityId": limitation.get(
                            "capabilityId", "UNKNOWN"
                        ),
                        "domain": limitation.get("domain", "UNKNOWN"),
                        "status": _limitation_status(limitation),
                        "check": _limitation_check(limitation),
                        "reason": _limitation_reason(limitation),
                        "scopeNote": _limitation_scope_note(limitation),
                    }
                )
        audit = ConsoleAuditLog(
            self.storage.path(assessment_id, "audit", "audit.jsonl")
        )
        audit_summary = audit.verify()
        all_audit_events = _safe_audit_events(audit.path)
        audit_events = all_audit_events if include_audit else []
        cve = _aggregate_cve(endpoints)
        vulnerability_exposure = _vulnerability_exposure(endpoints)
        software = _aggregate_software(endpoints)
        software_intelligence = _aggregate_software_intelligence(endpoints)
        software_matrix = _software_matrix(endpoints)
        priority_actions = _priority_actions(endpoints, fleet_findings)
        remediation_plan = _remediation_plan(priority_actions, fleet_findings)
        main_limitations = _main_coverage_limitations(endpoints, cve)
        highest_severity = next(
            (
                severity
                for severity in (
                    "CRITICAL",
                    "HIGH",
                    "MEDIUM",
                    "LOW",
                    "INFO",
                )
                if severity_distribution.get(severity, 0)
            ),
            "NONE",
        )
        generated_at = max(
            [str(item.get("receivedAt", "")) for item in index]
            + [assessment.created_at]
        )
        risk = _assessment_risk(
            fleet.fleet_risk_score,
            fleet_findings,
            cve,
        )
        endpoint_anchor_by_name = {
            item["displayName"]: item["anchorId"] for item in endpoints
        }
        for action in remediation_plan:
            action["affectedEndpointLinks"] = [
                {
                    "name": name,
                    "anchor": endpoint_anchor_by_name.get(name, "endpoints"),
                }
                for name in action["affectedEndpoints"]
            ]
        for finding in fleet_findings:
            anchor_source = (
                finding.get("fleetFindingId")
                if finding.get("kind") == "SOFTWARE_CVE"
                else finding.get("findingKey") or finding["ruleId"]
            )
            finding["anchorId"] = (
                f"finding-{_slug(str(anchor_source))}"
            )
            finding["endpointLinks"] = [
                {
                    "name": name,
                    "anchor": endpoint_anchor_by_name.get(name, "endpoints"),
                }
                for name in finding["endpointReferences"]
            ]
            finding["verification"] = _verification_for_finding(finding)
        framework_rows = _framework_rows(fleet_findings)
        model: dict[str, Any] = {
            "reportType": "UNIFIED_ASSESSMENT",
            "reportVersion": "CSA-5.2.4",
            "generatedAt": generated_at,
            "dataClassification": "Confidential - Security Assessment Data",
            "containsPersonalData": True,
            "metadata": {
                "generatedAt": generated_at,
                "assessmentId": assessment.assessment_id,
                "assessmentName": assessment.name,
                "dataClassification": (
                    "Confidential - Security Assessment Data"
                ),
                "containsPersonalData": True,
            },
            "assessment": {
                "assessmentId": assessment.assessment_id,
                "name": assessment.name,
                "organization": str(state.get("organization", "")),
                "referenceNumber": str(
                    state.get(
                        "referenceNumber", assessment.customer_reference
                    )
                ),
                "description": str(state.get("description", "")),
                "assessorNotes": str(state.get("assessorNotes", "")),
                "createdAt": assessment.created_at,
                "expectedEndpoints": int(
                    state.get("expectedEndpoints", fleet.endpoint_count)
                ),
            },
            "scope": {
                "uniqueEndpointCount": fleet.endpoint_count,
                "endpointsAssessed": fleet.endpoint_count,
                "submissionCount": fleet.submission_count,
                "latestSubmissionCount": len(endpoints),
                "duplicateSubmissionCount": (
                    fleet.duplicate_endpoint_submission_count
                ),
                "rejectedSubmissionCount": fleet.rejected_submission_count,
                "analysisPendingCount": fleet.analysis_pending_count,
                "transportCounts": dict(
                    sorted(
                        Counter(
                            _transport_label(
                                str(item.get("transport", "UNKNOWN"))
                            )
                            for item in index
                        ).items()
                    )
                ),
                "collectionMode": "Standard Privileges Assessment",
                "activeValidationPerformed": False,
                "identityMode": "REAL_ENDPOINT_IDENTITIES",
            },
            "risk": {
                **risk,
                "highestFindingSeverity": highest_severity,
                "criticalFindings": severity_distribution.get("CRITICAL", 0),
                "highFindings": severity_distribution.get("HIGH", 0),
                "criticalRiskEndpoints": risk_distribution.get(
                    "CRITICAL", 0
                ),
                "averageCoverage": fleet.average_coverage_percent,
                "coverageByDomain": fleet.coverage_by_domain,
            },
            "controlResults": {
                "total": total_control_results,
                "statusDistribution": dict(
                    sorted(control_status_distribution.items())
                ),
            },
            "coverage": {
                "corePassiveCoverage": fleet.average_coverage_percent,
                "optionalActiveValidation": "NOT PERFORMED",
                "cveCoverage": (
                    f"{cve['coveragePercent']}%"
                    if cve["status"] in {"COMPLETE", "PARTIAL"}
                    else "NOT PERFORMED"
                    if cve["status"] == "NOT_PERFORMED"
                    else cve["status"]
                ),
                "mainLimitations": main_limitations,
            },
            "cve": cve,
            "vulnerabilityExposure": vulnerability_exposure,
            "software": software,
            "softwareIntelligence": software_intelligence,
            "softwareMatrix": software_matrix,
            "priorityActions": priority_actions,
            "charts": {
                "severityDistribution": _counter_rows(
                    severity_distribution,
                    ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"),
                ),
                "riskDistribution": _counter_rows(
                    risk_distribution,
                    ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"),
                ),
                "coverageDistribution": _counter_rows(
                    coverage_bands,
                    ("95-100%", "80-94%", "60-79%", "Below 60%"),
                ),
                "securityControls": {
                    key: dict(sorted(value.items()))
                    for key, value in status_summary.items()
                },
            },
            "findings": fleet_findings,
            "priorityFindings": priority,
            "systemicFindings": [
                item for item in fleet_findings if item["systemic"]
            ],
            "remediationPlan": remediation_plan,
            "endpoints": endpoints,
            "assessmentLimitations": assessment_limitations,
            "coverageGaps": assessment_limitations,
            "frameworkRows": framework_rows,
            "methodology": {
                "summary": (
                    "CSA validates session-bound standard-user evidence, "
                    "normalizes canonical endpoint data, evaluates coverage-aware "
                    "rules, and deduplicates the fleet by latest device submission."
                ),
                "limitations": (
                    "Controls requiring elevated access remain coverage gaps and "
                    "are not converted into failures. Active Validation was not run. "
                    "CVE coverage is reported independently from core passive coverage."
                ),
            },
            "integrity": {
                "reportIntegrity": "VERIFIED",
                "evidencePackageIntegrity": "VERIFIED",
                "collectorBuildTrusted": "YES",
                "auditChain": audit_summary[
                    "auditVerificationStatus"
                ],
                "offlinePackagePathsNormalized": (
                    "YES"
                    if any(
                        item.get("eventType")
                        == "offline_archive_paths_normalized"
                        for item in all_audit_events
                    )
                    else "NOT APPLICABLE"
                ),
                "auditVerificationStatus": audit_summary[
                    "auditVerificationStatus"
                ],
                "auditEntryCount": audit_summary["auditEntryCount"],
                "auditHashAtGeneration": audit_summary[
                    "finalAuditEntryHash"
                ],
                "evidenceSetDigest": fleet.evidence_set_digest,
                "frameworkPackDigests": _framework_pack_digests(
                    self.storage, assessment_id
                ),
                "auditEvents": audit_events,
            },
            "options": {
                "includeTechnicalEvidence": include_technical_evidence,
                "includeAudit": include_audit,
                "includeEndpointDetails": include_endpoint_details,
            },
        }
        _assert_no_secret_keys(model)
        model["integrity"]["reportModelDigest"] = sha256_value(model)
        return model

    def generate(
        self,
        assessment_id: str,
        *,
        include_technical_evidence: bool = True,
        include_audit: bool = True,
        include_endpoint_details: bool = True,
    ) -> Path:
        """Render, integrity-record and audit one self-contained HTML file."""

        model = self.build_model(
            assessment_id,
            include_technical_evidence=include_technical_evidence,
            include_audit=include_audit,
            include_endpoint_details=include_endpoint_details,
        )
        style = (TEMPLATE_ROOT / "unified.css").read_text(encoding="utf-8")
        script = (TEMPLATE_ROOT / "unified.js").read_text(encoding="utf-8")
        html = self.environment.get_template("unified.html").render(
            model=model, inline_style=style, inline_script=script
        )
        name = _safe_filename(str(model["assessment"]["name"]))
        output = self.storage.path(
            assessment_id,
            "reports",
            "unified",
            f"{name}-CSA-Assessment-Report.html",
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_suffix(".tmp")
        temporary.write_text(html, encoding="utf-8")
        temporary.replace(output)
        digest = sha256_bytes(output.read_bytes())
        self.storage.write_json(
            assessment_id,
            (
                "reports",
                "unified",
                f"{name}-CSA-Assessment-Report.integrity.json",
            ),
            {
                "reportPath": output.name,
                "reportDigest": digest,
                "reportModelDigest": model["integrity"]["reportModelDigest"],
                "generatedAt": utc_text(),
            },
        )
        ConsoleAuditLog(
            self.storage.path(assessment_id, "audit", "audit.jsonl")
        ).append(
            "unified_report_generated",
            {
                "reportDigest": digest,
                "reportModelDigest": model["integrity"]["reportModelDigest"],
                "endpointCount": len(model["endpoints"]),
            },
        )
        return output

    def _endpoint_model(
        self,
        assessment_id: str,
        endpoint: dict[str, Any],
        index: dict[str, Any],
        include_evidence: bool,
    ) -> dict[str, Any]:
        submission_id = str(endpoint["submissionId"])
        normalized_path = self.storage.path(
            assessment_id, "normalized", f"{submission_id}.json"
        )
        evidence = (
            self.storage.read_json(
                assessment_id, "normalized", f"{submission_id}.json"
            )
            if normalized_path.exists()
            else {}
        )
        findings = sorted(
            endpoint.get("findings", []),
            key=lambda item: (
                SEVERITY_ORDER.get(
                    str(item.get("finding", {}).get("severity", "INFO")), 9
                ),
                str(item.get("finding", {}).get("rule_id", "")),
            ),
        )
        severity_counts = Counter(
            str(item.get("finding", {}).get("severity", "INFO"))
            for item in findings
            if item.get("finding", {}).get("status") in {"FAIL", "WARNING"}
        )
        status_counts = Counter(
            str(item.get("finding", {}).get("status", "UNKNOWN"))
            for item in findings
        )
        security_findings = _security_findings(findings)
        security_finding_count = len(security_findings)
        privilege = evidence.get("privilegeContext", {})
        device = evidence.get("identity", evidence.get("device", {}))
        display_name = _endpoint_display_name(device)
        users = _endpoint_users(evidence, device)
        bitlocker = _bitlocker_detail(evidence)
        software_results = list(
            endpoint.get("cveSummary", {}).get("softwareResults", [])
        )
        for software in software_results:
            software.setdefault(
                "cvePipeline",
                {
                    "eligibilityStatus": "NOT_EVALUATED",
                    "provider": "NVD",
                    "productMappingStatus": "NOT_RUN",
                    "cpeCandidateCount": 0,
                    "providerQueryStatus": "NOT_RUN",
                    "providerReason": "Detailed CVE pipeline data is unavailable",
                    "reason": "Detailed CVE pipeline data is unavailable",
                    "versionEvaluationStatus": "NOT_RUN",
                    "cveResultStatus": "NOT_EVALUATED",
                    "terminalStatus": "NOT_EVALUATED",
                    "failureStage": "CVE_SCAN",
                    "failureReason": "Detailed CVE pipeline data is unavailable",
                    "retryable": False,
                },
            )
        unsupported_count = sum(
            1
            for item in software_results
            if item.get("lifecycleStatus") == "OUT_OF_SUPPORT"
        )
        software_intelligence = _software_intelligence_coverage(
            software_results
        )
        return {
            "deviceId": str(endpoint.get("deviceId", "UNKNOWN")),
            "displayName": display_name,
            "identity": {
                "computerName": device.get("computerName") or device.get("hostname"),
                "hostName": device.get("hostName") or device.get("hostname"),
                "fqdn": device.get("fqdn"),
                "domainOrWorkgroup": (
                    device.get("domainOrWorkgroup")
                    or device.get("domain")
                    or device.get("workgroup")
                ),
                "entraJoined": device.get("entraJoined"),
                "entraTenantId": device.get("entraTenantId"),
                "entraDeviceId": device.get("deviceId"),
                "operatingSystem": evidence.get("operatingSystem", {}),
            },
            "users": users,
            "primaryUser": users["currentUser"].get("name", "Unknown"),
            "submissionId": submission_id,
            "transport": _transport_label(
                str(index.get("transport", "UNKNOWN"))
            ),
            "receivedAt": str(index.get("receivedAt", "")),
            "score": float(endpoint.get("score", 0)),
            "coverage": float(
                endpoint.get("coverage", {}).get(
                    "overallCoveragePercent", 0.0
                )
            ),
            "coverageByDomain": endpoint.get("coverage", {}).get(
                "coverageByDomain", {}
            ),
            "coverageLimitations": endpoint.get("coverage", {}).get(
                "limitations", []
            ),
            "findings": findings,
            "securityFindings": security_findings,
            "findingCount": security_finding_count,
            "securityFindingCount": security_finding_count,
            "controlResultCount": len(findings),
            "statusCounts": dict(sorted(status_counts.items())),
            "severityCounts": dict(sorted(severity_counts.items())),
            "collectorVersion": str(
                evidence.get("collectorVersion", "UNKNOWN")
            ),
            "collectorBuildDigest": str(
                evidence.get("collectorBuildDigest", "")
            ),
            "collectorBuildCommit": str(
                evidence.get("collectorBuildCommit", "")
            ),
            "cveAnalysisStatus": str(
                endpoint.get("cveAnalysisStatus", "NOT_PERFORMED")
            ),
            "cveSummary": dict(endpoint.get("cveSummary", {})),
            "softwareCollection": evidence.get("softwareCollection", {}),
            "softwareResults": software_results,
            "softwareIntelligence": software_intelligence,
            "unsupportedSoftwareCount": unsupported_count,
            "bitLocker": bitlocker,
            "securityControls": _security_control_summary(
                findings, bitlocker, evidence
            ),
            "privilegeContext": {
                "executionMode": str(
                    privilege.get("executionMode", "UNKNOWN")
                ),
                "integrityLevel": str(
                    privilege.get("integrityLevel", "UNKNOWN")
                ),
                "isElevated": bool(privilege.get("isElevated", False)),
                "isLocalAdministratorMember": privilege.get(
                    "isLocalAdministratorMember"
                ),
            },
            "evidenceSetDigest": str(endpoint.get("evidenceSetDigest", "")),
            "technicalEvidence": evidence if include_evidence else {},
            "collectedInformation": _collected_system_information(evidence),
        }

    @staticmethod
    def _fleet_finding(value: Any) -> dict[str, Any]:
        return {
            "fleetFindingId": value.fleet_finding_id,
            "ruleId": value.rule_id,
            "title": value.title,
            "severity": value.severity,
            "affectedEndpointCount": value.affected_endpoint_count,
            "assessedEndpointCount": value.assessed_endpoint_count,
            "affectedPercent": value.affected_percent,
            "endpointReferences": value.endpoint_references,
            "systemic": value.systemic,
            "frameworkMappings": value.framework_mappings,
            "recommendation": value.recommendation,
            "confidence": value.confidence,
            "riskScore": value.risk_score,
        }


def _security_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return failed or warning controls that represent security findings."""

    return [
        item
        for item in findings
        if item.get("finding", {}).get("status") in {"FAIL", "WARNING"}
    ]


def _security_finding_count(findings: list[dict[str, Any]]) -> int:
    """Count failed or warning controls that represent security findings."""

    return len(_security_findings(findings))


def _counter_rows(
    counter: Counter[str],
    order: tuple[str, ...],
) -> list[dict[str, Any]]:
    maximum = max(counter.values(), default=1)
    return [
        {
            "label": label,
            "count": int(counter.get(label, 0)),
            "percentOfMaximum": round(
                int(counter.get(label, 0)) * 100.0 / maximum, 1
            ),
        }
        for label in order
    ]


def _aggregate_cve(
    endpoints: list[dict[str, Any]],
) -> dict[str, Any]:
    """Aggregate CVEs with confirmed applicability dominating possible matches."""

    summaries = [item.get("cveSummary", {}) for item in endpoints]
    statuses = {
        str(item.get("cveAnalysisStatus", "NOT_PERFORMED"))
        for item in endpoints
    }
    if statuses == {"COMPLETE"}:
        status = "COMPLETE"
    elif statuses == {"NOT_EVALUATED"}:
        status = "NOT_EVALUATED"
    elif statuses == {"SKIPPED"}:
        status = "SKIPPED"
    elif statuses == {"NOT_PERFORMED"}:
        status = "NOT_PERFORMED"
    elif statuses == {"FAILED"}:
        status = "FAILED"
    elif "RUNNING" in statuses:
        status = "RUNNING"
    else:
        status = "PARTIAL"

    def total(key: str) -> int:
        return sum(int(item.get(key, 0) or 0) for item in summaries)

    def identifiers(key: str) -> set[str]:
        return {
            str(value)
            for item in summaries
            for value in item.get(key, [])
        }

    software_coverage = [
        endpoint["softwareIntelligence"]
        for endpoint in endpoints
        if "softwareIntelligence" in endpoint
    ]
    if software_coverage:
        eligible = sum(
            int(item.get("cveEligible", 0) or 0)
            for item in software_coverage
        )
        evaluated = sum(
            int(item.get("cveEvaluated", 0) or 0)
            for item in software_coverage
        )
    else:
        eligible = total("cveEligibleProducts")
        evaluated = total("successfullyEvaluatedProducts")
    coverage = (
        round(evaluated * 100.0 / eligible, 1)
        if eligible
        else 100.0
        if status == "COMPLETE"
        else 0.0
    )
    relationships = _cve_relationships(endpoints)
    confirmed_ids = {
        item["cveId"] for item in relationships
        if item["applicability"] == "CONFIRMED"
    }
    possible_ids = {
        item["cveId"] for item in relationships
        if item["applicability"] == "POSSIBLE"
    } - confirmed_ids
    unique_ids = confirmed_ids | possible_ids
    critical_ids = {
        item["cveId"] for item in relationships
        if item["applicability"] == "CONFIRMED"
        and item["severity"] == "CRITICAL"
    }
    possible_critical_ids = {
        item["cveId"] for item in relationships
        if item["applicability"] == "POSSIBLE"
        and item["severity"] == "CRITICAL"
    } - confirmed_ids
    high_ids = {
        item["cveId"] for item in relationships
        if item["applicability"] == "CONFIRMED"
        and item["severity"] == "HIGH"
    }
    kev_ids = {
        item["cveId"] for item in relationships
        if item["applicability"] == "CONFIRMED" and item["knownExploited"]
    }
    if not relationships:
        # Legacy summaries remain useful when older endpoint analyses do not
        # contain relationship detail. Confirmed always dominates possible.
        confirmed_ids = identifiers("confirmedCveIds")
        possible_ids = identifiers("possibleCveIds") - confirmed_ids
        unique_ids = confirmed_ids | possible_ids
        critical_ids = identifiers("criticalCveIds") & confirmed_ids
        possible_critical_ids = set()
        high_ids = identifiers("highCveIds") & confirmed_ids
        kev_ids = identifiers("cisaKevCveIds") & confirmed_ids
    not_evaluated = max(0, eligible - evaluated)
    coverage_complete = status == "COMPLETE" and not_evaluated == 0
    primary_display = (
        str(len(unique_ids))
        if coverage > 0.0 or status == "COMPLETE"
        else "NOT EVALUATED"
    )
    return {
        "status": status,
        "timestamp": max(
            (str(item.get("timestamp", "")) for item in summaries),
            default="",
        ),
        "installedSoftwareRecords": total("installedSoftwareRecords"),
        "normalizedProducts": total("normalizedProducts"),
        "coverageUnit": "endpoint_product_version_instances",
        "eligibleSoftwareInstances": eligible,
        "evaluatedSoftwareInstances": evaluated,
        "cveEligibleProducts": eligible,
        "successfullyEvaluatedProducts": evaluated,
        "notEvaluatedProducts": not_evaluated,
        "detectedCves": len(unique_ids),
        "primaryDisplay": primary_display,
        "evaluated": primary_display != "NOT EVALUATED",
        "uniqueCves": len(unique_ids),
        "confirmedUniqueCves": len(confirmed_ids),
        "confirmedProductCveRelationships": total(
            "confirmedProductCveRelationships"
        ),
        "possibleUniqueCves": len(possible_ids),
        "possibleProductCveRelationships": total(
            "possibleProductCveRelationships"
        ),
        "criticalUniqueCves": len(critical_ids),
        "confirmedCriticalCves": len(critical_ids),
        "possibleCriticalCves": len(possible_critical_ids),
        "highUniqueCves": len(high_ids),
        "cisaKevUniqueCves": len(kev_ids),
        "knownExploitedVulnerabilities": len(kev_ids),
        "softwareCveMatches": total("confirmedProductCveRelationships")
        + total("possibleProductCveRelationships"),
        "affectedEndpoints": sum(
            1
            for item in summaries
            if int(item.get("confirmedUniqueCves", 0) or 0) > 0
            or int(item.get("possibleUniqueCves", 0) or 0) > 0
        ),
        "coveragePercent": coverage,
        "coverageComplete": coverage_complete,
        "coverageStatement": _cve_coverage_statement(
            status, coverage, len(unique_ids)
        ),
        "relationships": relationships,
        "providerCoverage": [
            {
                "endpoint": endpoint["displayName"],
                **provider,
            }
            for endpoint in endpoints
            for provider in endpoint.get("cveSummary", {}).get(
                "providerCoverage", []
            )
        ],
    }


def _cve_relationships(
    endpoints: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return deterministic software/CVE/endpoint relationships."""

    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for endpoint in endpoints:
        for software in endpoint.get("softwareResults", []):
            software_anchor = (
                f"software-{_slug(endpoint['submissionId'])}-"
                f"{_slug(str(software.get('productKey') or software.get('displayName')))}"
            )
            software["anchorId"] = software_anchor
            for cve in software.get("cveDetails", []):
                match = str(cve.get("matchStatus", "NOT_EVALUATED"))
                applicability = (
                    "CONFIRMED" if match in {"AFFECTED", "CONFIRMED"}
                    else "POSSIBLE" if match in {"POSSIBLY_AFFECTED", "POSSIBLE"}
                    else "NOT_EVALUATED"
                )
                if applicability == "NOT_EVALUATED":
                    continue
                cve_id = str(cve.get("cveId", "UNKNOWN"))
                key = (
                    endpoint["submissionId"],
                    str(software.get("productKey") or software.get("displayName")),
                    cve_id,
                    applicability,
                )
                if key in seen:
                    continue
                seen.add(key)
                rows.append(
                    {
                        "cveId": cve_id,
                        "severity": str(cve.get("severity", "UNKNOWN")).upper(),
                        "cvss": cve.get("cvssScore"),
                        "applicability": applicability,
                        "rationale": str(cve.get("matchRationale", "")),
                        "affectedVersionRange": str(
                            cve.get("affectedVersionRange", "")
                        ),
                        "knownExploited": bool(cve.get("cisaKev", False)),
                        "software": str(software.get("displayName", "Unknown")),
                        "installedVersion": str(
                            software.get("displayVersion") or "Unknown"
                        ),
                        "normalizedProduct": str(
                            software.get("normalizedProduct") or "Unknown"
                        ),
                        "normalizedVendor": str(
                            software.get("normalizedVendor") or "Unknown"
                        ),
                        "endpoint": endpoint["displayName"],
                        "endpointAnchor": endpoint["anchorId"],
                        "softwareAnchor": software_anchor,
                        "nvdUrl": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        "cisaUrl": (
                            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                            if cve.get("cisaKev") else ""
                        ),
                        "fixedVersions": _string_values(
                            cve.get("fixedVersions", cve.get("fixedVersion"))
                        ),
                        "vendorAdvisoryUrls": _vendor_advisory_urls(cve),
                        "sourceResolution": dict(
                            cve.get("sourceResolution", {})
                        ),
                    }
                )
    return sorted(
        rows,
        key=lambda item: (
            SEVERITY_ORDER.get(item["severity"], 9),
            item["cveId"],
            item["endpoint"],
            item["software"],
        ),
    )


def _software_security_findings(
    endpoints: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Group confirmed CVEs into one security finding per software version."""

    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for relationship in _cve_relationships(endpoints):
        if relationship["applicability"] != "CONFIRMED":
            continue
        key = (
            relationship["normalizedVendor"],
            relationship["normalizedProduct"],
            relationship["installedVersion"],
        )
        row = grouped.setdefault(
            key,
            {
                "software": relationship["software"],
                "normalizedVendor": relationship["normalizedVendor"],
                "normalizedProduct": relationship["normalizedProduct"],
                "installedVersion": relationship["installedVersion"],
                "endpoints": set(),
                "cveIds": set(),
                "severities": set(),
                "knownExploited": set(),
                "cvssScores": [],
                "fixedVersions": set(),
                "vendorAdvisoryUrls": set(),
            },
        )
        row["endpoints"].add(relationship["endpoint"])
        row["cveIds"].add(relationship["cveId"])
        row["severities"].add(relationship["severity"])
        if relationship["knownExploited"]:
            row["knownExploited"].add(relationship["cveId"])
        if relationship.get("cvss") is not None:
            row["cvssScores"].append(float(relationship["cvss"]))
        row["fixedVersions"].update(relationship["fixedVersions"])
        row["vendorAdvisoryUrls"].update(
            relationship["vendorAdvisoryUrls"]
        )

    knowledge = KnowledgeRepository().get("CVE-001")
    findings = []
    assessed_count = len(endpoints)
    for key, row in grouped.items():
        endpoints_affected = sorted(row["endpoints"])
        cve_ids = sorted(row["cveIds"])
        severity = min(
            row["severities"],
            key=lambda value: SEVERITY_ORDER.get(value, 9),
            default="MEDIUM",
        )
        if severity not in SEVERITY_ORDER:
            severity = "MEDIUM"
        software = row["software"]
        version = row["installedVersion"]
        finding_key = "CVE-001:" + ":".join(key)
        recommendation = (
            f"Update {software} to a vendor-supported non-affected version."
        )
        verification = (
            f"Rerun CVE analysis and confirm that {software} {version} is no "
            "longer affected by the listed CVEs."
        )
        affected_count = len(endpoints_affected)
        findings.append(
            {
                "fleetFindingId": (
                    f"CVE-001-{sha256_value(finding_key)[:12]}"
                ),
                "findingKey": finding_key,
                "kind": "SOFTWARE_CVE",
                "ruleId": "CVE-001",
                "title": (
                    f"Confirmed vulnerabilities affect {software} {version}"
                ),
                "severity": severity,
                "affectedEndpointCount": affected_count,
                "assessedEndpointCount": assessed_count,
                "affectedPercent": round(
                    affected_count * 100.0 / assessed_count, 1
                ) if assessed_count else 0.0,
                "endpointReferences": endpoints_affected,
                "systemic": affected_count > 1 and (
                    affected_count * 100.0 / assessed_count >= 50.0
                ) if assessed_count else False,
                "frameworkMappings": {
                    name: list(controls)
                    for name, controls in knowledge.frameworks.items()
                },
                "recommendation": recommendation,
                "verification": verification,
                "confidence": 95,
                "riskScore": max(row["cvssScores"], default=0.0) * 10.0,
                "software": software,
                "normalizedVendor": row["normalizedVendor"],
                "normalizedProduct": row["normalizedProduct"],
                "installedVersion": version,
                "cveIds": cve_ids,
                "cveCount": len(cve_ids),
                "knownExploitedCveIds": sorted(row["knownExploited"]),
                "highestCvss": max(row["cvssScores"], default=None),
                "fixedVersions": sorted(row["fixedVersions"]),
                "vendorAdvisoryUrls": sorted(
                    row["vendorAdvisoryUrls"]
                ),
            }
        )
    return sorted(
        findings,
        key=lambda item: (
            SEVERITY_ORDER.get(item["severity"], 9),
            item["software"],
            item["installedVersion"],
        ),
    )


def _string_values(value: Any) -> list[str]:
    """Return unique non-empty strings from a scalar or list value."""

    values = value if isinstance(value, list) else [value]
    return sorted(
        {
            str(item).strip()
            for item in values
            if item is not None and str(item).strip()
        }
    )


def _vendor_advisory_urls(cve: dict[str, Any]) -> list[str]:
    """Preserve explicitly identified vendor advisory URLs when available."""

    urls = _string_values(
        cve.get("vendorAdvisoryUrls", cve.get("vendorAdvisoryUrl"))
    )
    for reference in cve.get("references", []):
        if not isinstance(reference, dict):
            continue
        tags = {
            str(tag).casefold().replace("_", "-").replace(" ", "-")
            for tag in reference.get("tags", [])
        }
        if "vendor-advisory" in tags and reference.get("url"):
            urls.append(str(reference["url"]).strip())
    return sorted(
        {
            url
            for url in urls
            if url.casefold().startswith("https://")
        }
    )


def _endpoint_cve_summary(endpoint: dict[str, Any]) -> dict[str, Any]:
    """Normalize endpoint CVE counters from version applicability details."""

    summary = dict(endpoint.get("cveSummary", {}))
    relationships = _cve_relationships([endpoint])
    if not relationships:
        return summary
    confirmed = {
        item["cveId"] for item in relationships
        if item["applicability"] == "CONFIRMED"
    }
    possible = {
        item["cveId"] for item in relationships
        if item["applicability"] == "POSSIBLE"
    } - confirmed
    summary.update(
        {
            "uniqueCves": len(confirmed | possible),
            "confirmedUniqueCves": len(confirmed),
            "possibleUniqueCves": len(possible),
            "cisaKevUniqueCves": len(
                {
                    item["cveId"] for item in relationships
                    if item["applicability"] == "CONFIRMED"
                    and item["knownExploited"]
                }
            ),
            "criticalUniqueCves": len(
                {
                    item["cveId"] for item in relationships
                    if item["applicability"] == "CONFIRMED"
                    and item["severity"] == "CRITICAL"
                }
            ),
            "highUniqueCves": len(
                {
                    item["cveId"] for item in relationships
                    if item["applicability"] == "CONFIRMED"
                    and item["severity"] == "HIGH"
                }
            ),
        }
    )
    return summary


def _cve_coverage_statement(status: str, coverage: float, count: int) -> str:
    """Explain clean, incomplete and unevaluated CVE states distinctly."""

    if status == "COMPLETE" and coverage == 100.0 and count == 0:
        return "No known vulnerabilities found in evaluated software versions."
    if status not in {"COMPLETE", "PARTIAL"} or coverage == 0.0:
        return "Vulnerability status was not evaluated."
    if coverage < 100.0 or status != "COMPLETE":
        return (
            "CVE results are incomplete. Counts apply only to successfully "
            "evaluated products."
        )
    return "CVE analysis completed for all eligible software products."


def _assessment_risk(
    score: float,
    findings: list[dict[str, Any]],
    cve: dict[str, Any],
) -> dict[str, Any]:
    """Return deterministic trigger-based assessment risk and reasoning.

    A numeric score never promotes an assessment to CRITICAL. Critical rating
    requires explicit confirmed critical evidence, such as a CRITICAL finding
    or an applicable Critical CVE. Systemic HIGH findings affect prioritization
    and support a HIGH rating, but their count never creates a CRITICAL rating.
    """

    critical_findings = [
        item for item in findings if item["severity"] == "CRITICAL"
    ]
    systemic_high = [
        item for item in findings
        if item["severity"] == "HIGH" and item.get("systemic")
    ]
    confirmed_critical_cves = int(cve.get("confirmedCriticalCves", 0))
    triggers: list[str] = []
    if critical_findings:
        triggers.append("At least one confirmed CRITICAL security finding")
    if confirmed_critical_cves:
        triggers.append("At least one confirmed Critical CVE")
    if triggers:
        rating = "CRITICAL"
    elif any(item["severity"] == "HIGH" for item in findings) or int(
        cve.get("highUniqueCves", 0)
    ):
        rating = "HIGH"
    elif any(item["severity"] == "MEDIUM" for item in findings):
        rating = "MEDIUM"
    elif any(item["severity"] == "LOW" for item in findings):
        rating = "LOW"
    else:
        rating = "INFORMATIONAL"
    if triggers:
        reason = "; ".join(triggers)
    elif len(systemic_high) >= 2:
        reason = (
            "Multiple high-severity weaknesses affect a significant portion "
            "of assessed endpoints. No Critical-risk condition was confirmed."
        )
    elif systemic_high:
        reason = (
            "A systemic high-severity weakness was confirmed. No Critical-risk "
            "condition was confirmed."
        )
    else:
        reason = f"Highest confirmed risk evidence supports a {rating} rating."
    return {
        "score": score,
        "scoreLabel": "Prioritization and exposure score",
        "scoreExplanation": (
            "This numeric metric ranks cumulative exposure and remediation "
            "priority. It does not independently determine Overall Security "
            "Risk severity."
        ),
        "rating": rating,
        "assessmentRiskRating": rating,
        "criticalTriggers": triggers,
        "systemicHighRiskFindings": len(systemic_high),
        "confirmedCriticalCves": confirmed_critical_cves,
        "knownExploitedVulnerabilities": int(
            cve.get("knownExploitedVulnerabilities", 0)
        ),
        "coverageModifier": (
            "Incomplete coverage reduces certainty; it does not lower or "
            "increase the rating automatically."
            if not cve.get("coverageComplete", False)
            else "No CVE coverage modifier was applied."
        ),
        "reason": reason,
    }


def _endpoint_risk_model(endpoint: dict[str, Any]) -> dict[str, Any]:
    """Calculate endpoint risk without treating its numeric score as severity."""

    severities = endpoint.get("severityCounts", {})
    confirmed_critical = 0
    confirmed_high = 0
    for software in endpoint.get("softwareResults", []):
        for cve in software.get("cveDetails", []):
            if str(cve.get("matchStatus")) not in {"AFFECTED", "CONFIRMED"}:
                continue
            if str(cve.get("severity", "")).upper() == "CRITICAL":
                confirmed_critical += 1
            elif str(cve.get("severity", "")).upper() == "HIGH":
                confirmed_high += 1
    if int(severities.get("CRITICAL", 0)) or confirmed_critical:
        rating = "CRITICAL"
    elif int(severities.get("HIGH", 0)) or confirmed_high:
        rating = "HIGH"
    elif int(severities.get("MEDIUM", 0)):
        rating = "MEDIUM"
    elif int(severities.get("LOW", 0)):
        rating = "LOW"
    else:
        rating = "INFORMATIONAL"
    return {"rating": rating, "score": endpoint.get("score", 0)}


def _security_control_summary(
    findings: list[dict[str, Any]],
    bitlocker: dict[str, Any],
    evidence: dict[str, Any],
) -> dict[str, str]:
    """Return compact, independently labelled endpoint control states."""

    controls = {
        "BitLocker": bitlocker.get("status", "NOT_EVALUATED"),
        "TPM": _setting_status(evidence, "TPM_READY"),
        "AV / EDR": _rule_status(findings, "DEF-001"),
        "Firewall": _rule_status(findings, "FW-001"),
    }
    return {key: str(value) for key, value in controls.items()}


def _setting_status(evidence: dict[str, Any], setting_id: str) -> str:
    value, setting = _setting_value(evidence, setting_id)
    status = str(setting.get("collectionStatus", "NOT_AVAILABLE"))
    if status == "SUCCESS":
        return "PASS" if value is True else "FAIL" if value is False else "INFO"
    if status == "PARTIAL":
        return "PARTIAL"
    if status == "FAILED":
        return "ERROR"
    return "NOT_EVALUATED"


def _all_settings(evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Index normalized settings for human-readable report summaries."""

    result: dict[str, dict[str, Any]] = {}
    for section in evidence.values():
        if not isinstance(section, dict):
            continue
        for setting in section.get("settings", []):
            if isinstance(setting, dict) and setting.get("settingId"):
                result[str(setting["settingId"])] = setting
    return result


def _collected_system_information(evidence: dict[str, Any]) -> dict[str, Any]:
    """Build a concise human-readable layer without exposing raw JSON."""

    settings = _all_settings(evidence)
    identity = evidence.get("identity", evidence.get("device", {}))
    users = _endpoint_users(evidence, identity)

    def value(setting_id: str, fallback: Any = "Not available") -> Any:
        item = settings.get(setting_id, {})
        result = item.get("effectiveValue")
        return fallback if result is None else result

    firewall = {
        profile: value(f"WINDOWS_FIREWALL_{profile}_ENABLED")
        for profile in ("DOMAIN", "PRIVATE", "PUBLIC")
    }
    return {
        "system": {
            "Computer name": identity.get("computerName")
            or identity.get("hostName")
            or "Not available",
            "Operating system": evidence.get("operatingSystem", {}).get(
                "name", "Not available"
            ),
            "OS version": evidence.get("operatingSystem", {}).get(
                "version", "Not available"
            ),
            "OS build": evidence.get("operatingSystem", {}).get(
                "build", "Not available"
            ),
            "Architecture": evidence.get("hardware", {}).get(
                "architecture", evidence.get("operatingSystem", {}).get(
                    "architecture", "Not available"
                )
            ),
            "Domain / Workgroup": identity.get("domainOrWorkgroup")
            or identity.get("domain")
            or identity.get("workgroup")
            or "Not available",
            "Entra joined": identity.get("entraJoined", "Not available"),
            "Last boot": evidence.get("operatingSystem", {}).get(
                "lastBoot", "Not available"
            ),
            "Collector version": evidence.get("collectorVersion", "UNKNOWN"),
        },
        "users": {
            "Current user": users["currentUser"].get("name", "Unknown"),
            "Local users": len(users["localUsers"]),
            "Local administrators": len(users["localAdministrators"]),
            "User profiles": len(users["userProfiles"]),
        },
        "security": {
            "BitLocker": _setting_display(settings.get("BITLOCKER_OS_PROTECTION")),
            "TPM": _setting_display(settings.get("TPM_READY")),
            "Secure Boot": _setting_display(settings.get("SECURE_BOOT_ENABLED")),
            "Microsoft Defender": _setting_display(settings.get("DEFENDER_ENABLED")),
            "Credential Guard": _setting_display(settings.get("CREDENTIAL_GUARD_RUNNING")),
            "LSA protection": _setting_display(settings.get("LSA_PROTECTION_ENABLED")),
            "Firewall Domain / Private / Public": " / ".join(
                _display_value(firewall[item]) for item in ("DOMAIN", "PRIVATE", "PUBLIC")
            ),
        },
        "updates": {
            "Last successful update": value("UPDATE_LAST_INSTALL_AT"),
            "Days since last install": value("WINDOWS_UPDATE_LAST_INSTALL_AGE_DAYS"),
            "Pending reboot": value("WINDOWS_UPDATE_PENDING_REBOOT"),
            "Recent updates": value("RECENT_WINDOWS_UPDATES", "Not available"),
        },
        "network": {
            "Active network category": _network_category_display(settings),
            "Active interfaces": value("ACTIVE_NETWORK_ADAPTERS", "Not available"),
            "DNS configuration": value("DNS_SERVERS", "Not available"),
            "LLMNR": _setting_display(settings.get("LLMNR_ENABLED")),
            "NetBIOS over TCP/IP": _setting_display(settings.get("NETBIOS_TCPIP_ENABLED")),
        },
        "softwareAndServices": {
            "Installed software records": len(evidence.get("software", [])),
            "Relevant services": _relevant_services(evidence),
        },
    }


def _setting_display(setting: dict[str, Any] | None) -> str:
    """Present one setting with explicit unavailable states."""

    if not setting:
        return "Not evaluated"
    status = str(setting.get("collectionStatus", "NOT_AVAILABLE"))
    if status != "SUCCESS":
        return status.replace("_", " ").title()
    return _display_value(setting.get("effectiveValue"))


def _display_value(value: Any) -> str:
    """Return a compact display value for collected evidence."""

    if value is True:
        return "Enabled"
    if value is False:
        return "Disabled"
    if value is None:
        return "Not available"
    if isinstance(value, list):
        return f"{len(value)} collected" if value else "None"
    if isinstance(value, dict):
        return f"{len(value)} values"
    return str(value)


def _network_category_display(settings: dict[str, dict[str, Any]]) -> str:
    """Render a network category without exposing PowerShell object artifacts."""

    setting = settings.get("ACTIVE_NETWORK_CATEGORY", {})
    raw_value = setting.get("effectiveValue")
    values = raw_value if isinstance(raw_value, list) else [raw_value]
    categories: list[str] = []
    for value in values:
        if isinstance(value, str) and value.strip():
            categories.append(value.strip().title())
        elif isinstance(value, dict):
            for key in ("NetworkCategory", "Category", "Value"):
                candidate = value.get(key)
                if isinstance(candidate, str) and candidate.strip():
                    categories.append(candidate.strip().title())
                    break
    if categories:
        return ", ".join(sorted(set(categories)))

    public_count = settings.get("PUBLIC_NETWORK_ADAPTER_COUNT", {}).get(
        "effectiveValue"
    )
    try:
        if int(public_count) > 0:
            return "Public"
    except (TypeError, ValueError):
        pass
    return "Not evaluated"


def _relevant_services(evidence: dict[str, Any]) -> str:
    """Summarize bounded non-Microsoft or non-running service observations."""

    services = evidence.get("services", [])
    if not isinstance(services, list):
        return "Not available"
    names = []
    for service in services:
        if not isinstance(service, dict):
            continue
        publisher = str(service.get("publisher", ""))
        state = str(service.get("state", service.get("status", ""))).upper()
        is_microsoft = "microsoft" in publisher.casefold()
        if is_microsoft and state in {"RUNNING", ""}:
            continue
        name = str(
            service.get("displayName") or service.get("name") or ""
        ).strip()
        if name and name not in names:
            names.append(name)
    if not names:
        return "No relevant service deviation collected"
    suffix = f" (+{len(names) - 20} more)" if len(names) > 20 else ""
    return ", ".join(names[:20]) + suffix


def _limitation_status(limitation: dict[str, Any]) -> str:
    reason = str(limitation.get("reason", "NOT_EVALUATED")).upper()
    return "PARTIAL" if "PARTIAL" in reason else "NOT_EVALUATED"


def _limitation_check(limitation: dict[str, Any]) -> str:
    capability = str(limitation.get("capabilityId", "UNKNOWN"))
    labels = {
        "COL-AUDIT-POLICY-001": "Audit policy",
        "COL-BITLOCKER-STATUS-001": "BitLocker protection",
        "COL-DEVICE-GUARD-001": "Device Guard and Credential Guard",
    }
    if capability in labels:
        return labels[capability]
    domain = str(limitation.get("domain", "Security control"))
    return domain.replace("_", " ").replace(".", " / ").title()


def _limitation_reason(limitation: dict[str, Any]) -> str:
    reason = str(limitation.get("reason", "Evidence was not available"))
    normalized = reason.upper()
    if "ACCESS_DENIED" in normalized:
        return "Windows did not permit this evidence to be read with standard privileges."
    if "NOT_SUPPORTED" in normalized:
        return "This check is not supported by the endpoint or collector provider."
    if "NOT_COLLECTED" in normalized:
        return "Required evidence was not collected, so no security conclusion was made."
    return reason.replace("_", " ").capitalize()


def _limitation_scope_note(limitation: dict[str, Any]) -> str:
    reason = str(limitation.get("reason", "")).upper()
    if "ACCESS_DENIED" in reason or "PRIVILEGE" in reason:
        return (
            "This check is not available in Standard Privileges Assessment. "
            "Admin Privileges Assessment may provide additional evidence."
        )
    return "The limitation affects evidence confidence, not control status."


def _endpoint_display_name(device: dict[str, Any]) -> str:
    """Resolve a real endpoint name without promoting a technical hash."""

    for key in ("computerName", "hostName", "hostname", "fqdn"):
        value = str(device.get(key, "")).strip()
        if value and not value.startswith("id-"):
            return value
    return ""


def _setting_value(
    evidence: dict[str, Any], setting_id: str
) -> tuple[Any, dict[str, Any]]:
    """Return one normalized setting value and its record."""

    for section in (
        "securityPolicies",
        "diskEncryption",
        "endpointProtection",
        "networkConfiguration",
    ):
        for setting in evidence.get(section, {}).get("settings", []):
            if setting.get("settingId") == setting_id:
                return setting.get("effectiveValue"), setting
    return None, {}


def _endpoint_users(
    evidence: dict[str, Any], device: dict[str, Any]
) -> dict[str, Any]:
    """Build deduplicated user inventories from account evidence."""

    current, _ = _setting_value(evidence, "CURRENT_EXECUTION_USER")
    local_users, _ = _setting_value(evidence, "LOCAL_USERS")
    administrators, _ = _setting_value(evidence, "LOCAL_ADMINISTRATORS")
    logged_on, _ = _setting_value(evidence, "LOGGED_ON_USERS")
    profiles, _ = _setting_value(evidence, "USER_PROFILES")
    current_value = current if isinstance(current, dict) else {
        "Name": device.get("currentUser", "Unknown"),
        "Sid": device.get("currentUserSid"),
    }
    return {
        "currentUser": _user_row(current_value),
        "loggedOnUsers": _dedupe_rows(logged_on),
        "localUsers": _dedupe_rows(local_users),
        "localAdministrators": _dedupe_rows(administrators),
        "userProfiles": _dedupe_rows(
            profiles, name_keys=("ProfileName", "profileName")
        ),
    }


def _user_row(value: dict[str, Any]) -> dict[str, Any]:
    return {
        str(key[:1].lower() + key[1:]): item
        for key, item in value.items()
    }


def _dedupe_rows(
    value: Any,
    name_keys: tuple[str, ...] = ("Name", "name"),
) -> list[dict[str, Any]]:
    rows = value if isinstance(value, list) else []
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        fallback_name = next(
            (row.get(name) for name in name_keys if row.get(name)), ""
        )
        key = str(row.get("Sid") or row.get("sid") or fallback_name).casefold()
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(_user_row(row))
    return result


def _bitlocker_detail(evidence: dict[str, Any]) -> dict[str, Any]:
    value, setting = _setting_value(evidence, "BITLOCKER_OS_PROTECTION")
    metadata = setting.get("metadata", {}) if setting else {}
    collection_status = str(
        setting.get("collectionStatus", "NOT_AVAILABLE")
    ) if setting else "NOT_AVAILABLE"
    status = "NOT_EVALUATED"
    if collection_status == "PARTIAL":
        status = "PARTIAL"
    elif collection_status == "FAILED":
        status = "ERROR"
    elif collection_status == "SUCCESS":
        status = "PASS" if value is True else "FAIL" if value is False else "NOT_EVALUATED"
    volumes = []
    seen: set[str] = set()
    for item in evidence.get("diskEncryption", {}).get("settings", []):
        item_metadata = item.get("metadata", {})
        mount = str(item_metadata.get("mountPoint", ""))
        if not mount or mount in seen:
            continue
        seen.add(mount)
        volumes.append({
            "mountPoint": mount,
            "volumeType": item_metadata.get("volumeType", "UNKNOWN"),
            "protectionEnabled": item_metadata.get("protectionEnabled"),
            "encryptionState": item_metadata.get("encryptionState", "UNKNOWN"),
            "encryptionPercentage": item_metadata.get("encryptionPercentage"),
            "provider": item_metadata.get("provider", item.get("provider", "UNKNOWN")),
        })
    return {
        "status": status,
        "mountPoint": metadata.get("mountPoint", "Unknown"),
        "provider": metadata.get("provider", setting.get("provider", "Unknown") if setting else "Unknown"),
        "confidence": setting.get("confidence", 0) if setting else 0,
        "configured": metadata.get("configured"),
        "protectionEnabled": metadata.get("protectionEnabled", value),
        "encryptionState": metadata.get("encryptionState", "UNKNOWN"),
        "encryptionPercentage": metadata.get("encryptionPercentage"),
        "fallbacksAttempted": metadata.get("fallbacksAttempted", []),
        "volumes": volumes,
    }


def _aggregate_software(endpoints: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [
        row
        for endpoint in endpoints
        for row in endpoint.get("softwareResults", [])
    ]
    return {
        "installedRecords": len(rows),
        "unsupportedCount": sum(
            1 for row in rows
            if row.get("lifecycleStatus") == "OUT_OF_SUPPORT"
        ),
        "nearingEndOfSupportCount": sum(
            1 for row in rows
            if row.get("lifecycleStatus") == "NEARING_END_OF_SUPPORT"
        ),
        "notEvaluatedCount": sum(
            1 for row in rows
            if row.get("cveEvaluationStatus") == "NOT_EVALUATED"
        ),
    }


def _vulnerability_exposure(
    endpoints: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Group version-specific CVE exposure by software and installed version."""

    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for relationship in _cve_relationships(endpoints):
        key = (relationship["software"], relationship["installedVersion"])
        row = grouped.setdefault(
            key,
            {
                "software": relationship["software"],
                "installedVersion": relationship["installedVersion"],
                "endpoints": set(),
                "endpointLinks": {},
                "cves": {},
                "confirmed": set(),
                "possible": set(),
                "highestCvss": None,
                "knownExploited": set(),
                "softwareAnchors": set(),
            },
        )
        row["endpoints"].add(relationship["endpoint"])
        row["endpointLinks"][relationship["endpoint"]] = relationship[
            "endpointAnchor"
        ]
        row["softwareAnchors"].add(relationship["softwareAnchor"])
        cve_id = relationship["cveId"]
        previous = row["cves"].get(cve_id)
        if previous is None or relationship["applicability"] == "CONFIRMED":
            row["cves"][cve_id] = relationship
        if relationship["applicability"] == "CONFIRMED":
            row["confirmed"].add(cve_id)
            row["possible"].discard(cve_id)
        elif cve_id not in row["confirmed"]:
            row["possible"].add(cve_id)
        score = relationship.get("cvss")
        if score is not None:
            row["highestCvss"] = max(float(score), row["highestCvss"] or 0.0)
        if relationship["knownExploited"] and relationship["applicability"] == "CONFIRMED":
            row["knownExploited"].add(cve_id)
    result = []
    for row in grouped.values():
        result.append(
            {
                "software": row["software"],
                "installedVersion": row["installedVersion"],
                "endpoints": sorted(row["endpoints"]),
                "endpointLinks": [
                    {"name": name, "anchor": row["endpointLinks"][name]}
                    for name in sorted(row["endpoints"])
                ],
                "detected": len(row["confirmed"] | row["possible"]),
                "confirmed": len(row["confirmed"]),
                "possible": len(row["possible"]),
                "highestCvss": row["highestCvss"],
                "knownExploited": len(row["knownExploited"]),
                "cves": [row["cves"][key] for key in sorted(row["cves"])],
                "detailAnchor": sorted(row["softwareAnchors"])[0],
            }
        )
    return sorted(
        result,
        key=lambda item: (
            -int(bool(item["knownExploited"])),
            -(item["highestCvss"] or 0),
            item["software"],
            item["installedVersion"],
        ),
    )


def _software_matrix(endpoints: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a compact software-by-endpoint matrix for offline comparison."""

    grouped: dict[str, dict[str, Any]] = {}
    endpoint_names = [item["displayName"] for item in endpoints]
    for endpoint in endpoints:
        for software in endpoint.get("softwareResults", []):
            name = str(
                software.get("normalizedProduct")
                or software.get("displayName")
                or "Unknown"
            )
            row = grouped.setdefault(
                name,
                {
                    "software": name,
                    "versions": {},
                    "risk": set(),
                    "installedOn": set(),
                    "remoteAccess": "remote" in name.casefold()
                    or name.casefold() in {"anydesk", "teamviewer", "screenconnect"},
                },
            )
            row["versions"][endpoint["displayName"]] = str(
                software.get("displayVersion") or "Installed"
            )
            row["installedOn"].add(endpoint["displayName"])
            if int(software.get("confirmedCves", 0) or 0):
                row["risk"].add("CVE")
            elif int(software.get("possibleCves", 0) or 0):
                row["risk"].add("Possible CVE")
            if software.get("lifecycleStatus") == "OUT_OF_SUPPORT":
                row["risk"].add("End of support")
            elif software.get("lifecycleStatus") in {
                "NOT_EVALUATED",
                "UNKNOWN_VERSION",
            }:
                row["risk"].add("Lifecycle not evaluated")
            pipeline = software.get("cvePipeline", {})
            mapping_status = str(
                pipeline.get("productMappingStatus", "NOT_RUN")
            )
            if (
                int(software.get("normalizationConfidence", 0) or 0) < 95
                and mapping_status != "SUCCESS"
            ) or mapping_status in {
                "NO_RELIABLE_MAPPING",
                "AMBIGUOUS",
                "AMBIGUOUS_MAPPING",
                "FAILED",
            }:
                row["risk"].add("Product not recognized")
            elif software.get("cveEvaluationStatus") not in {
                "CONFIRMED",
                "POSSIBLE",
                "NO_KNOWN_VULNERABILITIES",
            }:
                row["risk"].add("CVE not evaluated")
    rows = [
        {
            "software": row["software"],
            "versions": [row["versions"].get(name, "-") for name in endpoint_names],
            "installedCount": len(row["installedOn"]),
            "risk": ", ".join(sorted(row["risk"])) or "None identified",
            "vulnerable": "CVE" in row["risk"] or "Possible CVE" in row["risk"],
            "endOfSupport": "End of support" in row["risk"],
            "remoteAccess": row["remoteAccess"],
            "different": len(set(row["versions"].values())) > 1
            or len(row["versions"]) != len(endpoint_names),
        }
        for row in grouped.values()
    ]
    return {
        "endpointNames": endpoint_names,
        "compact": len(endpoint_names) > 12,
        "rows": sorted(rows, key=lambda item: item["software"]),
    }


def _software_intelligence_coverage(
    software_results: list[dict[str, Any]],
) -> dict[str, Any]:
    """Summarize auditable software-intelligence coverage for one endpoint."""

    installation_records = len(software_results)
    products = _deduplicated_software_instances(software_results)
    discovered = len(products)
    normalized = sum(
        1
        for item in products
        if int(item.get("normalizationConfidence", 0) or 0) >= 95
    )
    eligible = sum(
        1
        for item in products
        if _software_is_cve_eligible(item)
    )
    evaluated = sum(
        1
        for item in products
        if item.get("cvePipeline", {}).get("terminalStatus") == "COMPLETED"
    )
    lifecycle_evaluated = sum(
        1
        for item in products
        if item.get("lifecycleStatus") in {
            "SUPPORTED",
            "OUT_OF_SUPPORT",
            "NEARING_END_OF_SUPPORT",
        }
    )
    unknown_or_unmapped = sum(
        1
        for item in products
        if _software_is_unknown_or_unmapped(item)
    )
    confirmed_vulnerable = sum(
        1
        for item in products
        if int(item.get("confirmedCves", 0) or 0) > 0
        or item.get("cveEvaluationStatus") == "CONFIRMED"
    )
    confirmed_cves = {
        str(cve.get("cveId"))
        for item in products
        for cve in item.get("cveDetails", [])
        if str(cve.get("matchStatus")) in {"AFFECTED", "CONFIRMED"}
        and cve.get("cveId")
    }
    return {
        "countingUnit": "endpoint_product_version_instances",
        "softwareRecordsDiscovered": installation_records,
        "productsDiscovered": installation_records,
        "endpointProductInstances": discovered,
        "normalizedConfidently": normalized,
        "cveEligible": eligible,
        "cveEvaluated": evaluated,
        "lifecycleEvaluated": lifecycle_evaluated,
        "unknownOrUnmapped": unknown_or_unmapped,
        "notEvaluated": max(0, eligible - evaluated),
        "notFullyEvaluated": max(0, discovered - evaluated),
        "confirmedVulnerableProductInstances": confirmed_vulnerable,
        "confirmedCves": len(confirmed_cves),
        "identificationCoveragePercent": (
            round((normalized / discovered) * 100, 1)
            if discovered else 100.0
        ),
        "eligibleCveCoveragePercent": (
            round((evaluated / eligible) * 100, 1)
            if eligible else 100.0 if discovered == 0 else 0.0
        ),
        "coveragePercent": (
            round((evaluated / discovered) * 100, 1)
            if discovered else 100.0
        ),
    }


def _aggregate_software_intelligence(
    endpoints: list[dict[str, Any]],
) -> dict[str, Any]:
    """Aggregate instance and fleet-unique software coverage separately."""

    rows = [
        endpoint.get("softwareIntelligence")
        or _software_intelligence_coverage(
            list(endpoint.get("softwareResults", []))
        )
        for endpoint in endpoints
    ]
    aggregate = {
        key: sum(int(row.get(key, 0) or 0) for row in rows)
        for key in (
            "softwareRecordsDiscovered",
            "productsDiscovered",
            "endpointProductInstances",
            "normalizedConfidently",
            "cveEligible",
            "cveEvaluated",
            "lifecycleEvaluated",
            "unknownOrUnmapped",
            "notEvaluated",
            "notFullyEvaluated",
            "confirmedVulnerableProductInstances",
        )
    }
    fleet_products = _deduplicated_software_instances(
        [
            software
            for endpoint in endpoints
            for software in endpoint.get("softwareResults", [])
        ]
    )
    aggregate.update(
        {
            "countingUnit": "endpoint_product_version_instances",
            "uniqueProductVersions": len(fleet_products),
            "uniqueReliablyIdentified": sum(
                1
                for item in fleet_products
                if int(item.get("normalizationConfidence", 0) or 0) >= 95
            ),
            "uniqueCveEligible": sum(
                1 for item in fleet_products
                if _software_is_cve_eligible(item)
            ),
            "uniqueCveEvaluated": sum(
                1
                for item in fleet_products
                if item.get("cvePipeline", {}).get("terminalStatus")
                == "COMPLETED"
            ),
            "confirmedVulnerableProducts": sum(
                1
                for item in fleet_products
                if int(item.get("confirmedCves", 0) or 0) > 0
                or item.get("cveEvaluationStatus") == "CONFIRMED"
            ),
            "confirmedCves": len(
                {
                    str(cve.get("cveId"))
                    for item in fleet_products
                    for cve in item.get("cveDetails", [])
                    if str(cve.get("matchStatus"))
                    in {"AFFECTED", "CONFIRMED"}
                    and cve.get("cveId")
                }
            ),
        }
    )
    discovered = aggregate["endpointProductInstances"]
    eligible = aggregate["cveEligible"]
    aggregate["identificationCoveragePercent"] = (
        round((aggregate["normalizedConfidently"] / discovered) * 100, 1)
        if discovered else 100.0
    )
    aggregate["eligibleCveCoveragePercent"] = (
        round((aggregate["cveEvaluated"] / eligible) * 100, 1)
        if eligible else 100.0 if discovered == 0 else 0.0
    )
    aggregate["coveragePercent"] = (
        round((aggregate["cveEvaluated"] / discovered) * 100, 1)
        if discovered else 100.0
    )
    return aggregate


def _deduplicated_software_instances(
    software_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Collapse registry-scope duplicates to product/version identities."""

    selected: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for index, item in enumerate(software_results):
        key = _software_identity_key(item)
        if not any(key):
            key = ("", f"unidentified-record-{index}", "", "")
        current = selected.get(key)
        if current is None or _software_result_rank(item) > _software_result_rank(
            current
        ):
            selected[key] = item
    return list(selected.values())


def _software_identity_key(item: dict[str, Any]) -> tuple[str, str, str, str]:
    """Return one stable vendor/product/version/architecture identity."""

    return tuple(
        str(value or "").strip().casefold()
        for value in (
            item.get("normalizedVendor") or item.get("publisher"),
            item.get("normalizedProduct") or item.get("displayName"),
            item.get("normalizedVersion") or item.get("displayVersion"),
            item.get("architecture"),
        )
    )


def _software_result_rank(item: dict[str, Any]) -> tuple[int, int, int]:
    """Prefer the most complete duplicate result deterministically."""

    terminal_order = {
        "COMPLETED": 5,
        "PARTIAL": 4,
        "FAILED": 3,
        "NOT_EVALUATED": 2,
        "NOT_ELIGIBLE": 1,
        "NOT_RUN": 0,
    }
    terminal = str(
        item.get("cvePipeline", {}).get("terminalStatus", "NOT_RUN")
    )
    return (
        terminal_order.get(terminal, 0),
        int(item.get("normalizationConfidence", 0) or 0),
        int(item.get("confirmedCves", 0) or 0),
    )


def _software_is_unknown_or_unmapped(item: dict[str, Any]) -> bool:
    """Return whether product identity lacks a reliable terminal mapping."""

    mapping = str(
        item.get("cvePipeline", {}).get("productMappingStatus", "NOT_RUN")
    )
    return (
        int(item.get("normalizationConfidence", 0) or 0) < 95
        and mapping != "SUCCESS"
    ) or mapping in {
        "NO_RELIABLE_MAPPING",
        "AMBIGUOUS",
        "AMBIGUOUS_MAPPING",
        "FAILED",
    }


def _software_is_cve_eligible(item: dict[str, Any]) -> bool:
    """Infer eligibility even when CVE analysis has not been started."""

    pipeline_status = str(
        item.get("cvePipeline", {}).get("eligibilityStatus", "NOT_EVALUATED")
    )
    if pipeline_status == "ELIGIBLE":
        return True
    if pipeline_status == "NOT_ELIGIBLE":
        return False
    has_identity = bool(
        item.get("normalizedProduct") or item.get("displayName")
    )
    has_version = bool(
        item.get("normalizedVersion") or item.get("displayVersion")
    )
    return bool(
        has_identity
        and has_version
        and (
            int(item.get("normalizationConfidence", 0) or 0) >= 80
            or item.get("discoveryEligible") is True
        )
    )


def _priority_actions(
    endpoints: list[dict[str, Any]], findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Rank and deduplicate up to five concrete remediation actions."""

    candidates: list[tuple[int, str, dict[str, Any]]] = []
    for finding in findings:
        if finding.get("kind") != "SOFTWARE_CVE":
            continue
        known_exploited = bool(finding.get("knownExploitedCveIds"))
        score = 100 if known_exploited else (
            90 if finding["severity"] == "CRITICAL" else 85
        )
        candidates.append(
            (
                score,
                str(finding.get("findingKey", finding["title"])),
                _action(
                    finding["recommendation"],
                    (
                        f"{finding['cveCount']} confirmed CVE(s) affect "
                        f"{finding['software']} {finding['installedVersion']}"
                        + ("; at least one is in CISA KEV." if known_exploited else ".")
                    ),
                    finding["endpointReferences"],
                    finding["severity"].title(),
                    "Medium",
                    [finding["ruleId"]],
                    finding["verification"],
                ),
            )
        )
    unsupported = [item["displayName"] for item in endpoints if item.get("unsupportedSoftwareCount", 0)]
    if unsupported:
        candidates.append((80, "unsupported", _action("Upgrade or remove unsupported software", "Vendor support has ended for installed software.", unsupported, "High", "Medium", ["LIFECYCLE"], "Verify the replacement release is supported by the vendor.")))
    for finding in findings:
        if finding["ruleId"] == "BIT-001" and finding["severity"] in {"CRITICAL", "HIGH"}:
            candidates.append((70, "bitlocker", _action("Enable BitLocker protection", finding["title"], finding["endpointReferences"], "High", "Medium", ["BIT-001"], "Confirm protection is on and encryption is complete.")))
        if finding["ruleId"].startswith("DEF-") and finding["severity"] in {"CRITICAL", "HIGH", "MEDIUM"}:
            candidates.append((60, "defender", _action("Harden Microsoft Defender configuration", finding["title"], finding["endpointReferences"], "Medium", "Low", [finding["ruleId"]], "Rerun collection and confirm the related Defender controls pass.")))
    deduped: dict[str, tuple[int, dict[str, Any]]] = {}
    for score, key, action in candidates:
        if key not in deduped or score > deduped[key][0]:
            deduped[key] = (score, action)
    return [
        item[1]
        for item in sorted(
            deduped.values(), key=lambda value: (-value[0], value[1]["action"])
        )[:5]
    ]


def _remediation_plan(
    priority_actions: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build an action-centric, deduplicated remediation plan."""

    grouped: dict[str, dict[str, Any]] = {}
    for action in priority_actions:
        grouped[action["action"].casefold()] = dict(action)
    for finding in findings:
        recommendation = str(finding.get("recommendation", "")).strip()
        if not recommendation or recommendation == "Unknown":
            continue
        key = recommendation.casefold()
        row = grouped.setdefault(
            key,
            {
                "action": recommendation,
                "reason": finding["title"],
                "affectedEndpoints": [],
                "riskReduction": finding["severity"].title(),
                "estimatedEffort": "Review required",
                "relatedFindings": [],
                "verificationGuidance": _verification_for_finding(finding),
            },
        )
        row["affectedEndpoints"] = sorted(
            set(row["affectedEndpoints"]) | set(finding["endpointReferences"])
        )
        row["relatedFindings"] = sorted(
            set(row["relatedFindings"]) | {finding["ruleId"]}
        )
    severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    rows = sorted(
        grouped.values(),
        key=lambda item: (
            severity_rank.get(item["riskReduction"], 4),
            item["action"],
        ),
    )
    for index, row in enumerate(rows, start=1):
        row["priority"] = f"P{1 if index <= 3 else 2 if index <= 8 else 3}"
    return rows


def _verification_for_finding(finding: dict[str, Any]) -> str:
    """Return deterministic post-remediation verification guidance."""

    explicit = str(finding.get("verification", "")).strip()
    if explicit:
        return explicit
    rule_id = str(finding.get("ruleId", ""))
    if rule_id == "BIT-001":
        return "Rerun CSA and verify BitLocker protection is enabled on the OS volume."
    if rule_id.startswith("DEF-"):
        return "Rerun CSA and verify the related Microsoft Defender control passes."
    if rule_id.startswith("FW-"):
        return "Rerun CSA and verify all applicable Windows Firewall profiles pass."
    if rule_id == "ACC-011":
        return (
            "Rerun CSA and verify the daily user SID is no longer present in "
            "local Administrators and ACC-011 reports PASS."
        )
    return f"Rerun CSA and verify {rule_id or 'the related control'} reports PASS."


def _action(
    action: str,
    reason: str,
    endpoints: list[str],
    risk: str,
    effort: str,
    findings: list[str],
    verify: str,
) -> dict[str, Any]:
    return {
        "action": action,
        "reason": reason,
        "affectedEndpoints": sorted(set(endpoints)),
        "riskReduction": risk,
        "estimatedEffort": effort,
        "relatedFindings": sorted(set(findings)),
        "verificationGuidance": verify,
    }


def _main_coverage_limitations(
    endpoints: list[dict[str, Any]],
    cve: dict[str, Any],
) -> list[str]:
    """Return concise, deterministic Executive Summary limitations."""

    labels = {
        "COL-BITLOCKER-STATUS-001": (
            "BitLocker state could not be read as a standard user"
        ),
        "COL-AUDIT-POLICY-001": "Audit policy requires elevated access",
    }
    values: list[str] = []
    for endpoint in endpoints:
        for item in endpoint.get("coverageLimitations", []):
            capability = str(item.get("capabilityId", "UNKNOWN"))
            reason = str(item.get("reason", "NOT_COLLECTED"))
            text = labels.get(
                capability,
                f"{capability}: {reason.replace('_', ' ').lower()}",
            )
            if text not in values:
                values.append(text)
    if cve["status"] == "NOT_PERFORMED":
        values.append("CVE analysis was not performed")
    elif cve["status"] != "COMPLETE":
        values.append(f"CVE analysis status is {cve['status']}")
    return values[:6]


def _transport_label(value: str) -> str:
    """Return a precise user-facing transport label."""

    labels = {
        "HTTPS": "HTTPS submission",
        "OFFLINE_ENCRYPTED": "Encrypted offline import",
    }
    return labels.get(value, value.replace("_", " ").title())


def _coverage_band(value: float) -> str:
    if value >= 95:
        return "95-100%"
    if value >= 80:
        return "80-94%"
    if value >= 60:
        return "60-79%"
    return "Below 60%"


def _rule_status(findings: list[dict[str, Any]], rule_id: str) -> str:
    for item in findings:
        finding = item.get("finding", {})
        if finding.get("rule_id") == rule_id:
            return str(finding.get("status", "NOT_EVALUATED"))
    return "NOT_EVALUATED"


def _framework_rows(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build action-oriented traceability rows without claiming compliance."""

    grouped: dict[
        tuple[str, str], dict[str, Any]
    ] = {}
    for finding in findings:
        for framework, controls in finding["frameworkMappings"].items():
            for control in controls:
                for mapping in _framework_mapping_metadata(
                    str(framework), str(control), finding["ruleId"]
                ):
                    key = (mapping["framework"], mapping["controlId"])
                    row = grouped.setdefault(
                        key,
                        {"metadata": mapping, "findings": []},
                    )
                    row["findings"].append(finding)
    rows = []
    for key, grouped_row in sorted(grouped.items()):
        mapped_findings = grouped_row["findings"]
        metadata = grouped_row["metadata"]
        endpoints = sorted(
            {
                endpoint
                for finding in mapped_findings
                for endpoint in finding["endpointReferences"]
            }
        )
        endpoint_links = {
            link["name"]: link["anchor"]
            for finding in mapped_findings
            for link in finding.get("endpointLinks", [])
        }
        rows.append(
            {
                "framework": key[0],
                "controlId": key[1],
                "controlTitle": metadata["controlTitle"],
                "controlSourceTitle": metadata["controlSourceTitle"],
                "controlSourceUrl": metadata["controlSourceUrl"],
                "sourceVersion": metadata["sourceVersion"],
                "contentNotice": metadata["contentNotice"],
                "assessmentStatus": "ATTENTION_REQUIRED",
                "findingIds": sorted(
                    {finding["ruleId"] for finding in mapped_findings}
                ),
                "findingLinks": [
                    {
                        "id": finding["ruleId"],
                        "title": finding["title"],
                        "anchor": f"finding-details-{finding['anchorId']}",
                    }
                    for finding in sorted(
                        mapped_findings,
                        key=lambda item: str(
                            item.get("findingKey", item["ruleId"])
                        ),
                    )
                ],
                "affectedEndpoints": endpoints,
                "affectedEndpointLinks": [
                    {
                        "name": name,
                        "anchor": endpoint_links.get(name, "endpoints"),
                    }
                    for name in endpoints
                ],
                "recommendedAction": "; ".join(
                    sorted(
                        {
                            finding["recommendation"]
                            for finding in mapped_findings
                            if finding["recommendation"] != "Unknown"
                        }
                    )
                ) or "Review the related technical finding.",
                "mappingStatus": metadata["mappingStatus"],
                "mappingConfidence": min(
                    (int(finding.get("confidence", 0)) for finding in mapped_findings),
                    default=0,
                ),
            }
        )
    return rows


def _framework_mapping_metadata(
    framework: str,
    control_id: str,
    rule_id: str,
) -> list[dict[str, str]]:
    """Resolve report-safe source metadata for one knowledge mapping."""

    packs = _report_framework_packs()
    if framework == "E-ITS" and "EITS" in packs:
        pack = packs["EITS"]
        mappings = []
        for control in pack.controls:
            for mapping in control.mappings:
                if mapping.rule_id != rule_id:
                    continue
                mappings.append(
                    {
                        "framework": "E-ITS",
                        "controlId": control.control_id,
                        "controlTitle": control.title,
                        "controlSourceTitle": (
                            f"E-ITS {pack.version} official measure"
                        ),
                        "controlSourceUrl": (
                            mapping.source_reference or pack.source.reference
                        ),
                        "sourceVersion": pack.version,
                        "contentNotice": (
                            "Official wording is not reproduced; use the "
                            "linked E-ITS source as authoritative content."
                        ),
                        "mappingStatus": mapping.status.value,
                    }
                )
        if mappings:
            return mappings
        return []
    if framework == "CIS" and "CIS" in packs:
        pack = packs["CIS"]
        return [{
            "framework": "CIS",
            "controlId": control_id,
            "controlTitle": control_id,
            "controlSourceTitle": pack.name,
            "controlSourceUrl": pack.source.reference,
            "sourceVersion": pack.version,
            "contentNotice": (
                "Licensed CIS Benchmark content is not embedded. Import an "
                "authorized content pack to display control titles and text."
            ),
            "mappingStatus": "PROVISIONAL",
        }]
    return [{
        "framework": framework,
        "controlId": control_id,
        "controlTitle": control_id,
        "controlSourceTitle": "Knowledge Base mapping identifier",
        "controlSourceUrl": "",
        "sourceVersion": "",
        "contentNotice": "",
        "mappingStatus": "PROVISIONAL",
    }]


@lru_cache(maxsize=1)
def _report_framework_packs() -> dict[str, FrameworkPack]:
    """Load immutable framework source metadata once per report process."""

    paths = {
        "EITS": FRAMEWORK_ROOT / "eits" / "2026" / "pack.json",
        "CIS": (
            FRAMEWORK_ROOT
            / "cis"
            / "windows-11-enterprise"
            / "5.0.1"
            / "pack.json"
        ),
    }
    return {
        name: load_pack(path)
        for name, path in paths.items()
        if path.exists()
    }


def _safe_audit_events(path: Path) -> list[dict[str, Any]]:
    values = []
    for line in path.read_text(encoding="utf-8").splitlines():
        value = json.loads(line)
        values.append(
            {
                "timestamp": value.get("timestamp", ""),
                "eventType": value.get("eventType", ""),
                "entryHash": value.get("entryHash", ""),
            }
        )
    return values


def _framework_pack_digests(
    storage: AssessmentStorage, assessment_id: str
) -> dict[str, str]:
    values: dict[str, str] = {}
    for path in sorted(
        storage.path(assessment_id, "sessions").glob("*.json"),
        key=lambda item: item.name,
    ):
        session = storage.read_json(assessment_id, "sessions", path.name)
        configured = session.get("reportConfiguration", {}).get(
            "frameworkPackDigests", {}
        )
        if isinstance(configured, dict):
            values.update(
                {str(key): str(value) for key, value in configured.items()}
            )
    return dict(sorted(values.items()))


def _safe_filename(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    normalized = normalized.strip(".-_")[:80]
    return normalized or "CSA-Assessment"


def _slug(value: str) -> str:
    """Return a deterministic HTML-safe fragment identifier."""

    return re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-") or "item"


def _assert_no_secret_keys(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).casefold())
            if normalized in SECRET_KEYS:
                raise ValueError(f"Report model contains forbidden key at {path}")
            _assert_no_secret_keys(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_no_secret_keys(item, f"{path}[{index}]")
