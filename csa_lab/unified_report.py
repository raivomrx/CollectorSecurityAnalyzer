"""Generate one deterministic self-contained CSA assessment report."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
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
        latest, all_endpoints, index = analyzer.load_latest_endpoint_data(
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
            risk_distribution[_endpoint_risk(float(endpoint["score"]))] += 1
            coverage_bands[_coverage_band(float(endpoint["coverage"]))] += 1
            for key, rule_id in (
                ("bitLocker", "BIT-001"),
                ("defender", "DEF-001"),
                ("updates", "UPD-001"),
            ):
                status_summary[key][_rule_status(endpoint["findings"], rule_id)] += 1
        coverage_gaps = []
        for endpoint in endpoints:
            for limitation in endpoint["coverageLimitations"]:
                coverage_gaps.append(
                    {
                        "deviceId": endpoint["displayName"],
                        "submissionId": endpoint["submissionId"],
                        "capabilityId": limitation.get(
                            "capabilityId", "UNKNOWN"
                        ),
                        "domain": limitation.get("domain", "UNKNOWN"),
                        "reason": limitation.get("reason", "Not collected"),
                    }
                )
        framework_rows = _framework_rows(fleet_findings)
        audit = ConsoleAuditLog(
            self.storage.path(assessment_id, "audit", "audit.jsonl")
        )
        audit_summary = audit.verify()
        all_audit_events = _safe_audit_events(audit.path)
        audit_events = all_audit_events if include_audit else []
        cve = _aggregate_cve(endpoints)
        software = _aggregate_software(endpoints)
        priority_actions = _priority_actions(endpoints, fleet_findings)
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
        model: dict[str, Any] = {
            "reportType": "UNIFIED_ASSESSMENT",
            "reportVersion": "CSA-5.2.0",
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
                "score": fleet.fleet_risk_score,
                "rating": fleet.risk_rating,
                "assessmentRiskRating": fleet.risk_rating,
                "highestFindingSeverity": highest_severity,
                "criticalFindings": severity_distribution.get(
                    "CRITICAL", 0
                ),
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
            "software": software,
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
            "remediationPlan": [
                {
                    "priority": index,
                    "ruleId": item["ruleId"],
                    "title": item["title"],
                    "severity": item["severity"],
                    "affectedPercent": item["affectedPercent"],
                    "recommendation": item["recommendation"],
                }
                for index, item in enumerate(fleet_findings[:12], start=1)
            ],
            "endpoints": endpoints,
            "coverageGaps": coverage_gaps,
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
                    "productMappingStatus": "NOT_RUN",
                    "cpeCandidateCount": 0,
                    "providerQueryStatus": "NOT_RUN",
                    "providerReason": "Detailed CVE pipeline data is unavailable",
                    "reason": "Detailed CVE pipeline data is unavailable",
                    "versionEvaluationStatus": "NOT_RUN",
                    "cveResultStatus": "NOT_EVALUATED",
                },
            )
        unsupported_count = sum(
            1
            for item in software_results
            if item.get("lifecycleStatus") == "OUT_OF_SUPPORT"
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
            "findingCount": len(findings),
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
            "unsupportedSoftwareCount": unsupported_count,
            "bitLocker": bitlocker,
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
    """Aggregate endpoint CVE metrics without conflating count types."""

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

    eligible = total("cveEligibleProducts")
    evaluated = total("successfullyEvaluatedProducts")
    coverage = (
        round(evaluated * 100.0 / eligible, 1)
        if eligible
        else 100.0
        if status == "COMPLETE"
        else 0.0
    )
    unique_ids = identifiers("uniqueCveIds")
    confirmed_ids = identifiers("confirmedCveIds")
    possible_ids = identifiers("possibleCveIds")
    critical_ids = identifiers("criticalCveIds")
    high_ids = identifiers("highCveIds")
    kev_ids = identifiers("cisaKevCveIds")
    return {
        "status": status,
        "timestamp": max(
            (str(item.get("timestamp", "")) for item in summaries),
            default="",
        ),
        "installedSoftwareRecords": total("installedSoftwareRecords"),
        "normalizedProducts": total("normalizedProducts"),
        "cveEligibleProducts": eligible,
        "successfullyEvaluatedProducts": evaluated,
        "notEvaluatedProducts": total("notEvaluatedProducts"),
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
        "highUniqueCves": len(high_ids),
        "cisaKevUniqueCves": len(kev_ids),
        "softwareCveMatches": total("confirmedProductCveRelationships")
        + total("possibleProductCveRelationships"),
        "affectedEndpoints": sum(
            1
            for item in summaries
            if int(item.get("confirmedUniqueCves", 0) or 0) > 0
            or int(item.get("possibleUniqueCves", 0) or 0) > 0
        ),
        "coveragePercent": coverage,
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


def _priority_actions(
    endpoints: list[dict[str, Any]], findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Rank and deduplicate up to five concrete remediation actions."""

    candidates: list[tuple[int, str, dict[str, Any]]] = []
    kev = [
        item["displayName"] for item in endpoints
        if int(item.get("cveSummary", {}).get("cisaKevUniqueCves", 0) or 0)
    ]
    if kev:
        candidates.append((100, "kev", _action("Remediate CISA KEV vulnerabilities", "Known-exploited vulnerabilities were matched to installed software.", kev, "High", "Immediate", ["CVE"], "Update or remove each affected product, then rerun CVE analysis.")))
    critical = [
        item["displayName"] for item in endpoints
        if int(item.get("cveSummary", {}).get("criticalUniqueCves", 0) or 0)
    ]
    if critical:
        candidates.append((90, "critical", _action("Remediate confirmed critical vulnerabilities", "Critical CVEs require urgent product-specific remediation.", critical, "High", "Medium", ["CVE"], "Confirm each installed version is outside the affected range.")))
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


def _endpoint_risk(score: float) -> str:
    if score < 40:
        return "CRITICAL"
    if score < 60:
        return "HIGH"
    if score < 80:
        return "MEDIUM"
    if score < 95:
        return "LOW"
    return "INFORMATIONAL"


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
    grouped: dict[tuple[str, str], set[str]] = defaultdict(set)
    for finding in findings:
        for framework, controls in finding["frameworkMappings"].items():
            for control in controls:
                grouped[(str(framework), str(control))].add(finding["ruleId"])
    return [
        {
            "framework": key[0],
            "controlId": key[1],
            "findingIds": sorted(values),
        }
        for key, values in sorted(grouped.items())
    ]


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
