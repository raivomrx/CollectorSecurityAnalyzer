"""Presentation-only vulnerability and observed-administrator regressions."""

from __future__ import annotations

import copy
from collections import Counter
from pathlib import Path
import tempfile
import unittest

from analysis_context import AnalysisContext
from collector_schema.loader import _parse_setting
from csa_console.fleet import FleetAnalyzer
from csa_console.reporting import ConsoleReportGenerator
from csa_lab.unified_report import (
    _administrative_privileges_summary, _assessment_risk, _endpoint_risk_model,
    _software_security_findings,
)
from evidence.administrative_privileges import administrative_privilege_posture
from evidence.registry import WindowsEvidenceRegistry
from knowledge.repository import KnowledgeRepository
from report import generate_html_report
from risk import AuditFinding, Finding, Severity, Status
from rules.windows.account_rules import Acc011Rule
from software.models import SoftwareInventory
from tests.test_console_sprint5 import Sprint5TestCase
from tests.test_sprint531_semantics import build_semantics_fixture

SID = "S-1-5-21-100-200-300-1001"


def audit(rule_id="ACC-011", status="FAIL", severity="HIGH", evidence=None):
    return AuditFinding(Finding(rule_id=rule_id, status=Status(status), severity=Severity(severity),
                                evidence=evidence or {}), KnowledgeRepository().get(rule_id)).to_dict()


def membership(sid=SID, name="DEMO\\admin", member=True, classification="DOMAIN"):
    value = {"current_user": name, "current_user_sid": sid, "matched": member,
             "membership_source": "LOCAL_ADMINISTRATORS_SID_CORRELATION"}
    if member:
        value["matched_principal"] = {"sid": sid, "name": name, "classification": classification, "resolved": True}
    return audit(status="FAIL" if member else "PASS", evidence=value)


def endpoint(label="DEMO-01", *, sid=SID, name="DEMO\\admin", member=True,
             classification="DOMAIN", elevated=False, findings=None):
    rows = [membership(sid, name, member, classification)] if findings is None else findings
    evidence = {"privilegeContext": {"isElevated": elevated, "isLocalAdministratorMember": member}}
    return {"deviceId": label, "displayName": label, "submissionId": label,
            "anchorId": "endpoint-" + label.lower(), "findings": rows,
            "administrativePrivileges": administrative_privilege_posture(evidence, rows)}


class AdministrativePrivilegeTests(unittest.TestCase):
    def test_membership_display_is_deterministic_after_fleet_input_reordering(self):
        rows = [endpoint("DEMO-02", name="DEMO\\renamed"), endpoint("DEMO-01")]
        self.assertEqual(_administrative_privileges_summary(rows), _administrative_privileges_summary(rows[::-1]))

    def test_device_sid_fallback_matches_the_existing_acc011_contract(self):
        evidence = {"identity": {"currentUserSid": SID}, "securityPolicies": {"settings": [{
            "settingId": "CURRENT_EXECUTION_USER", "collectionStatus": "SUCCESS", "effectiveValue": {"Name": "DEMO\\admin"},
        }]}}
        self.assertEqual(administrative_privilege_posture(evidence, [membership()])["status"], "FAIL")

    def test_domain_identity_is_deduplicated_across_endpoints_despite_alias_names(self):
        summary = _administrative_privileges_summary([
            endpoint("DEMO-01"), endpoint("DEMO-02", name="DEMO\\renamed"),
        ])
        self.assertEqual(summary["observedAdminUsers"], 1)
        self.assertEqual(summary["affectedEndpoints"], 2)
        self.assertEqual(summary["status"], "EVALUATED")
        self.assertEqual(len(summary["users"][0]["endpointLinks"]), 2)
        self.assertEqual(summary["elevatedCollectorProcesses"], 0)

    def test_same_name_different_sid_and_local_account_scopes_do_not_merge(self):
        summary = _administrative_privileges_summary([
            endpoint("DEMO-01"), endpoint("DEMO-02", sid=SID[:-1] + "2"),
        ])
        self.assertEqual(summary["observedAdminUsers"], 2)
        summary = _administrative_privileges_summary([
            endpoint("DEMO-01", classification="LOCAL"), endpoint("DEMO-02", classification="LOCAL"),
        ])
        self.assertEqual(summary["observedAdminUsers"], 2)

    def test_existing_sid_pseudonyms_are_usable_without_recovering_identifiers(self):
        summary = _administrative_privileges_summary([
            endpoint("DEMO-01", sid="id-012345abcdef", name="id-000000000001"),
            endpoint("DEMO-02", sid="id-012345abcdef", name="id-000000000002"),
        ])
        self.assertEqual(summary["observedAdminUsers"], 1)

    def test_elevation_and_membership_are_independent_and_absence_is_not_zero(self):
        for status in ("NOT_EVALUATED", "PARTIAL", "ERROR", "WARNING"):
            summary = _administrative_privileges_summary([
                endpoint(findings=[audit(status=status)], elevated=True),
            ])
            self.assertEqual(summary["status"], "NOT_EVALUATED")
            self.assertIsNone(summary["observedAdminUsers"])
            self.assertIsNone(summary["affectedEndpoints"])
            self.assertEqual(summary["elevatedCollectorProcesses"], 1)
        self.assertEqual(_administrative_privileges_summary([endpoint(member=False, elevated=True)])["observedAdminUsers"], 0)
        self.assertIsNone(_administrative_privileges_summary([endpoint(findings=[], elevated=None)])["elevatedCollectorProcesses"])

    def test_missing_malformed_or_conflicting_membership_evidence_stays_not_evaluated(self):
        valid = membership()
        cases = []
        for key, value in (("current_user_sid", ""), ("current_user_sid", "same-display-name"),
                           ("matched", "true"), ("matched", False), ("membership_source", "NAME_MATCH")):
            bad = copy.deepcopy(valid)
            bad["finding"]["evidence"][key] = value
            cases.append([bad])
        mismatched = copy.deepcopy(valid)
        mismatched["finding"]["evidence"]["matched_principal"]["sid"] = SID[:-1] + "2"
        cases.extend(([mismatched], [valid, membership(member=False)], [membership(sid="S-1-5-18")], []))
        for rows in cases:
            with self.subTest(rows=rows):
                self.assertEqual(endpoint(findings=rows)["administrativePrivileges"]["status"], "NOT_EVALUATED")

    def test_partial_current_user_collection_and_identity_conflict_remain_unknown(self):
        for status, sid in (("PARTIAL", SID), ("ACCESS_DENIED", SID), ("SUCCESS", SID[:-1] + "2")):
            evidence = {"securityPolicies": {"settings": [{"settingId": "CURRENT_EXECUTION_USER",
                "collectionStatus": status, "effectiveValue": {"Sid": sid}}]}}
            self.assertEqual(administrative_privilege_posture(evidence, [membership()])["status"], "NOT_EVALUATED")

    def test_partial_fleet_counts_only_confirmed_observations(self):
        rows = [endpoint(), endpoint("DEMO-02", member=False), endpoint("DEMO-03", findings=[])]
        original = copy.deepcopy(rows)
        summary = _administrative_privileges_summary(rows)
        self.assertEqual(summary["status"], "PARTIAL")
        self.assertEqual(summary["observedAdminUsers"], 1)
        self.assertEqual(summary["affectedEndpoints"], 1)
        self.assertEqual(summary["evaluatedEndpoints"], 2)
        self.assertEqual(summary["notEvaluatedEndpoints"], 1)
        self.assertEqual(rows, original)


def build_review_fixture(case):
    generator = build_semantics_fixture(case)
    for label, admin_status in (("ENABLED", "SUCCESS"), ("DISABLED", "SUCCESS"), ("UNKNOWN", "ACCESS_DENIED")):
        submission = "SUB-531-" + label
        normalized = case.storage.read_json(case.assessment.assessment_id, "normalized", submission + ".json")
        settings = [
            {"settingId": "CURRENT_EXECUTION_USER", "effectiveValue": {"Name": "DEMO\\admin õäöü", "Sid": SID}},
            {"settingId": "LOCAL_ADMINISTRATORS", "effectiveValue": [{"Name": "DEMO\\admin õäöü", "Sid": SID,
                "Classification": "DOMAIN", "Resolved": True}]},
        ]
        for setting in settings:
            setting.update(category="Accounts", source="RUNTIME_STATE", collectionStatus=admin_status,
                           confidence=100, collectedAt="2026-10-26T08:00:00Z", provider="Synthetic review fixture")
        normalized["securityPolicies"] = {"settings": settings}
        normalized["privilegeContext"] = {"isElevated": False, "isLocalAdministratorMember": True}
        case.storage.write_json(case.assessment.assessment_id, ("normalized", submission + ".json"), normalized)
        analysis = case.storage.read_json(case.assessment.assessment_id, "findings", submission + ".json")
        context = AnalysisContext(raw_data={}, software_inventory=SoftwareInventory(),
                                  evidence_registry=WindowsEvidenceRegistry([_parse_setting(item) for item in settings]))
        acc = Acc011Rule().check({}, context)[0]
        analysis["findings"] = [row for row in analysis["findings"] if row["finding"]["rule_id"] not in {"CVE-001", "ACC-011"}]
        analysis["findings"] += [AuditFinding(acc, KnowledgeRepository().get("ACC-011")).to_dict(),
                                  audit("CVE-001", "FAIL", "CRITICAL", {"confirmed_vulnerability_count": 2})]
        details = [
            {"cveId": "CVE-2026-0001", "matchStatus": "AFFECTED", "severity": "HIGH", "cvssScore": 8.1,
             "cisaKev": True, "fixedVersion": "2.1", "vendorAdvisoryUrl": "https://example.com/security/demo"},
            {"cveId": "CVE-2026-0002", "matchStatus": "CONFIRMED", "severity": "MEDIUM", "cvssScore": 6.0},
            {"cveId": "CVE-2026-0003", "matchStatus": "POSSIBLY_AFFECTED", "severity": "CRITICAL", "cvssScore": 9.8},
        ]
        software = {"productKey": "demo|reader|1.0", "displayName": "Demo Reader õäöü", "displayVersion": "1.0",
            "normalizedVendor": "Demo", "normalizedProduct": "Demo Reader", "normalizedVersion": "1.0",
            "cveEvaluationStatus": "CONFIRMED", "cveDetails": details,
            "cvePipeline": {"eligibilityStatus": "ELIGIBLE", "terminalStatus": "COMPLETED"},
            "lifecycleStatus": "SUPPORTED"}
        analysis["cveAnalysisStatus"] = "COMPLETE" if label != "UNKNOWN" else "PARTIAL"
        analysis["cveSummary"] = {"status": analysis["cveAnalysisStatus"], "softwareResults": [software] if label != "UNKNOWN" else [],
            "cveEligibleProducts": 1, "successfullyEvaluatedProducts": 1 if label != "UNKNOWN" else 0,
            "confirmedCveIds": ["CVE-2026-0001", "CVE-2026-0002"] if label != "UNKNOWN" else ["CVE-2026-0004"],
            "possibleCveIds": ["CVE-2026-0003"] if label != "UNKNOWN" else [], "confirmedUniqueCves": 2 if label != "UNKNOWN" else 1}
        case.storage.write_json(case.assessment.assessment_id, ("findings", submission + ".json"), analysis)
    return generator


class ReportSemanticsTests(Sprint5TestCase):
    def setUp(self):
        super().setUp()
        self.generator = build_review_fixture(self)

    def test_internal_control_is_retained_without_a_duplicate_customer_finding(self):
        model = self.generator.build_model(self.assessment.assessment_id)
        self.assertFalse(any(item["ruleId"] == "CVE-001" and item.get("kind") != "SOFTWARE_CVE" for item in model["findings"]))
        self.assertEqual(model["controlResults"]["vulnerabilityAssessmentStatusCounts"], {"FAIL": 3})
        concrete = [item for item in model["findings"] if item.get("kind") == "SOFTWARE_CVE"]
        self.assertEqual(len(concrete), 1)
        self.assertEqual(concrete[0]["cveIds"], ["CVE-2026-0001", "CVE-2026-0002"])
        self.assertEqual(concrete[0]["affectedEndpointCount"], 2)
        self.assertIn("1.0", concrete[0]["recommendation"])
        self.assertIn("2.1", concrete[0]["recommendation"])
        self.assertIn("CVE-2026-0001", concrete[0]["verification"])
        self.assertTrue(concrete[0]["displayId"].startswith("SW-VULN-"))
        for endpoint_model in model["endpoints"]:
            self.assertTrue(any(row["finding"]["rule_id"] == "CVE-001" for row in endpoint_model["findings"]))
            self.assertFalse(any(row["finding"]["rule_id"] == "CVE-001" for row in endpoint_model["securityFindings"]))
        self.assertEqual(model["cve"]["confirmedUniqueCves"], 3)
        self.assertEqual(model["cve"]["possibleUniqueCves"], 1)
        self.assertEqual(model["cve"]["summaryOnlyEndpointCount"], 1)
        self.assertEqual(model["cve"]["confirmedCriticalCves"], 0)

    def test_client_filtering_preserves_the_existing_risk_inputs_scores_and_stored_evidence(self):
        before = {path.name: path.read_bytes() for path in self.storage.path(self.assessment.assessment_id, "findings").glob("SUB-*.json")}
        model = self.generator.build_model(self.assessment.assessment_id)
        fleet = FleetAnalyzer(self.storage).analyze(self.assessment.assessment_id)
        risk_findings = [self.generator._fleet_finding(row) for row in fleet.fleet_findings]
        risk_findings += _software_security_findings(model["endpoints"])
        expected = _assessment_risk(fleet.fleet_risk_score, risk_findings, model["cve"])
        for key, value in expected.items():
            self.assertEqual(model["risk"][key], value, key)
        for row in model["endpoints"]:
            previous_counts = Counter(item["finding"]["severity"] for item in row["findings"]
                                      if item["finding"]["status"] in {"FAIL", "WARNING"})
            previous_counts.update(item["severity"] for item in row["softwareSecurityFindings"])
            previous = {key: value for key, value in row.items() if key != "riskSeverityCounts"}
            previous["severityCounts"] = dict(previous_counts)
            self.assertEqual(row["risk"], _endpoint_risk_model(previous))
        after = {path.name: path.read_bytes() for path in self.storage.path(self.assessment.assessment_id, "findings").glob("SUB-*.json")}
        self.assertEqual(before, after)

    def test_remediation_is_product_version_cve_specific_and_kev_is_p1(self):
        model = self.generator.build_model(self.assessment.assessment_id)
        rows = [row for row in model["remediationPlan"] if "Demo Reader" in row["action"]]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["priority"], "P1")
        self.assertEqual(rows[0]["relatedFindings"], ["CVE-2026-0001", "CVE-2026-0002"])
        self.assertNotIn("CVE-001", str(model["remediationPlan"]))
        self.assertNotIn("known vulnerability assessment", str(model["priorityFindings"]).lower())

    def test_executive_membership_scope_unicode_and_html_finding_sections(self):
        model = self.generator.build_model(self.assessment.assessment_id, include_technical_evidence=False)
        summary = model["administrativePrivileges"]
        self.assertEqual((summary["observedAdminUsers"], summary["affectedEndpoints"], summary["notEvaluatedEndpoints"]), (1, 2, 1))
        self.assertEqual(summary["status"], "PARTIAL")
        self.assertEqual(summary["elevatedCollectorProcesses"], 0)
        html = self.generator.generate(self.assessment.assessment_id, include_technical_evidence=False).read_text(encoding="utf-8")
        self.assertIn('href="#administrative-privileges"', html)
        self.assertIn('id="administrative-privileges"', html)
        self.assertIn("1 distinct observed interactive administrator user across 2 affected endpoints", html)
        self.assertIn("DEMO\\admin õäöü", html)
        self.assertIn("Other processes and sessions were not evaluated", html)
        for left, right in (("priority", "systemic"), ("systemic", "remediation"), ("remediation", "cve")):
            section = html.split('id="' + left + '"', 1)[1].split('id="' + right + '"', 1)[0]
            self.assertNotIn("CVE-001", section)
            self.assertNotIn("known vulnerability assessment", section.lower())
        self.assertIn("aggregate control, not a CVE identifier", html)

    def test_console_client_views_also_exclude_the_generic_control(self):
        reports = ConsoleReportGenerator(self.storage)
        model = reports.endpoint_model(self.assessment.assessment_id, "SUB-531-ENABLED")
        self.assertFalse(any(row["finding"]["rule_id"] == "CVE-001" for row in model["findings"]))
        self.assertTrue(any(row["finding"]["rule_id"] == "CVE-001" for row in model["endpoint"]["findings"]))
        fleet = reports.fleet_model(self.assessment.assessment_id)
        self.assertFalse(any(row["ruleId"] == "CVE-001" for row in fleet["isolatedFindings"] + fleet["systemicFindings"]))


class LegacyReportSemanticsTests(unittest.TestCase):
    def test_legacy_html_keeps_the_internal_audit_record_out_of_finding_cards(self):
        controls = [AuditFinding(Finding(rule_id="CVE-001", status=Status.FAIL, severity=Severity.CRITICAL),
                                 KnowledgeRepository().get("CVE-001"))]
        with tempfile.TemporaryDirectory() as directory:
            html = generate_html_report({}, controls, 70, SoftwareInventory(), {}, None,
                                        Path(directory) / "review.html").read_text(encoding="utf-8")
        findings = html.split("<h2>All Findings</h2>", 1)[1].split("</section>", 1)[0]
        self.assertNotIn("CVE-001", findings)
        self.assertEqual(controls[0].finding.rule_id, "CVE-001")


if __name__ == "__main__":
    unittest.main()
