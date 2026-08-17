"""Sprint 5.2.1 reporting correctness and customer usability tests."""

from __future__ import annotations

import unittest
from pathlib import Path

from csa_lab.unified_report import (
    _aggregate_cve,
    _assessment_risk,
    _endpoint_cve_summary,
    _framework_rows,
    _limitation_reason,
    _limitation_scope_note,
    _security_finding_count,
    _software_matrix,
    _vulnerability_exposure,
)

ROOT = Path(__file__).resolve().parents[1]


def _finding(
    rule_id: str,
    severity: str,
    *,
    systemic: bool = False,
) -> dict[str, object]:
    return {
        "ruleId": rule_id,
        "severity": severity,
        "systemic": systemic,
        "title": f"{rule_id} finding",
        "endpointReferences": ["PC-01"],
        "frameworkMappings": {"CIS": ["CIS-4.1"]},
        "recommendation": "Apply the approved baseline.",
        "confidence": 90,
        "anchorId": f"finding-{rule_id.lower()}",
        "endpointLinks": [{"name": "PC-01", "anchor": "endpoint-pc-01"}],
    }


def _endpoint(
    *,
    status: str = "COMPLETE",
    eligible: int = 1,
    evaluated: int = 1,
    cves: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    details = cves or []
    confirmed = {
        item["cveId"]
        for item in details
        if item.get("matchStatus") in {"AFFECTED", "CONFIRMED"}
    }
    possible = {
        item["cveId"]
        for item in details
        if item.get("matchStatus") in {"POSSIBLY_AFFECTED", "POSSIBLE"}
    } - confirmed
    return {
        "displayName": "PC-01",
        "submissionId": "SUB-01",
        "anchorId": "endpoint-sub-01",
        "cveAnalysisStatus": status,
        "cveSummary": {
            "status": status,
            "cveEligibleProducts": eligible,
            "successfullyEvaluatedProducts": evaluated,
            "notEvaluatedProducts": max(0, eligible - evaluated),
            "confirmedCveIds": sorted(confirmed),
            "possibleCveIds": sorted(possible),
            "uniqueCveIds": sorted(confirmed | possible),
        },
        "softwareResults": [
            {
                "productKey": "vendor|product|1.0",
                "displayName": "Product",
                "displayVersion": "1.0",
                "normalizedProduct": "Product",
                "cveDetails": details,
                "confirmedCves": len(confirmed),
                "possibleCves": len(possible),
                "lifecycleStatus": "SUPPORTED",
            }
        ],
    }


class RiskCorrectnessTests(unittest.TestCase):
    """Verify explicit assessment-risk escalation rules."""

    def test_two_high_findings_do_not_automatically_become_critical(self) -> None:
        cve = _aggregate_cve([_endpoint(eligible=0, evaluated=0)])
        risk = _assessment_risk(
            94.0,
            [_finding("A", "HIGH"), _finding("B", "HIGH")],
            cve,
        )
        self.assertEqual(risk["rating"], "HIGH")

    def test_two_systemic_high_findings_do_not_trigger_escalation(self) -> None:
        risk = _assessment_risk(
            99.0,
            [
                _finding("A", "HIGH", systemic=True),
                _finding("B", "HIGH", systemic=True),
            ],
            _aggregate_cve([_endpoint(eligible=0, evaluated=0)]),
        )
        self.assertEqual(risk["rating"], "HIGH")

    def test_any_count_of_systemic_high_findings_remains_high(self) -> None:
        cve = _aggregate_cve([_endpoint(eligible=0, evaluated=0)])
        for count in (3, 10):
            with self.subTest(count=count):
                risk = _assessment_risk(
                    100.0,
                    [
                        _finding(f"HIGH-{index}", "HIGH", systemic=True)
                        for index in range(count)
                    ],
                    cve,
                )
                self.assertEqual(risk["rating"], "HIGH")
                self.assertEqual(risk["criticalTriggers"], [])
                self.assertIn(
                    "No Critical-risk condition was confirmed",
                    risk["reason"],
                )

    def test_confirmed_critical_finding_allows_critical(self) -> None:
        risk = _assessment_risk(
            40.0,
            [_finding("A", "CRITICAL")],
            _aggregate_cve([_endpoint(eligible=0, evaluated=0)]),
        )
        self.assertEqual(risk["rating"], "CRITICAL")

    def test_confirmed_critical_kev_allows_critical(self) -> None:
        cve = _aggregate_cve([_endpoint(cves=[{
            "cveId": "CVE-2026-0001",
            "matchStatus": "AFFECTED",
            "severity": "CRITICAL",
            "cvssScore": 9.8,
            "cisaKev": True,
        }])])
        self.assertEqual(_assessment_risk(20.0, [], cve)["rating"], "CRITICAL")
        self.assertEqual(cve["knownExploitedVulnerabilities"], 1)

    def test_possible_critical_cve_does_not_become_critical(self) -> None:
        cve = _aggregate_cve([_endpoint(cves=[{
            "cveId": "CVE-2026-0002",
            "matchStatus": "POSSIBLY_AFFECTED",
            "severity": "CRITICAL",
            "cvssScore": 9.8,
            "cisaKev": False,
        }])])
        self.assertNotEqual(_assessment_risk(99.0, [], cve)["rating"], "CRITICAL")
        self.assertEqual(cve["confirmedCriticalCves"], 0)
        self.assertEqual(cve["possibleCriticalCves"], 1)

    def test_possible_critical_kev_is_not_endpoint_confirmed(self) -> None:
        endpoint = _endpoint(cves=[{
            "cveId": "CVE-2026-0004",
            "matchStatus": "POSSIBLY_AFFECTED",
            "severity": "CRITICAL",
            "cvssScore": 10.0,
            "cisaKev": True,
        }])
        summary = _endpoint_cve_summary(endpoint)
        self.assertEqual(summary["criticalUniqueCves"], 0)
        self.assertEqual(summary["cisaKevUniqueCves"], 0)


class CveSemanticsTests(unittest.TestCase):
    """Verify typed CVE counts and coverage wording."""

    def test_two_possible_cves_are_detected_but_not_confirmed(self) -> None:
        endpoint = _endpoint(cves=[
            {"cveId": "CVE-1", "matchStatus": "POSSIBLY_AFFECTED", "severity": "HIGH"},
            {"cveId": "CVE-2", "matchStatus": "POSSIBLY_AFFECTED", "severity": "MEDIUM"},
        ])
        cve = _aggregate_cve([endpoint])
        self.assertEqual(cve["detectedCves"], 2)
        self.assertEqual(cve["confirmedUniqueCves"], 0)
        self.assertEqual(cve["possibleUniqueCves"], 2)

    def test_zero_cves_with_full_coverage_is_evaluated_clean(self) -> None:
        cve = _aggregate_cve([_endpoint(cves=[])])
        self.assertEqual(cve["coveragePercent"], 100.0)
        self.assertIn("No known vulnerabilities found", cve["coverageStatement"])

    def test_zero_cves_with_zero_coverage_is_not_evaluated(self) -> None:
        cve = _aggregate_cve([
            _endpoint(status="NOT_EVALUATED", eligible=1, evaluated=0)
        ])
        self.assertEqual(cve["coveragePercent"], 0.0)
        self.assertEqual(cve["primaryDisplay"], "NOT EVALUATED")
        self.assertFalse(cve["evaluated"])
        self.assertEqual(
            cve["coverageStatement"],
            "Vulnerability status was not evaluated.",
        )

    def test_zero_cves_with_full_coverage_displays_evaluated_zero(self) -> None:
        cve = _aggregate_cve([_endpoint(cves=[])])
        self.assertEqual(cve["primaryDisplay"], "0")
        self.assertTrue(cve["evaluated"])

    def test_vulnerability_exposure_links_product_cve_and_endpoint(self) -> None:
        rows = _vulnerability_exposure([_endpoint(cves=[{
            "cveId": "CVE-2026-0003",
            "matchStatus": "AFFECTED",
            "severity": "HIGH",
            "cvssScore": 8.8,
            "cisaKev": False,
        }])])
        self.assertEqual(rows[0]["confirmed"], 1)
        self.assertEqual(rows[0]["endpointLinks"][0]["anchor"], "endpoint-sub-01")
        self.assertIn("nvd.nist.gov", rows[0]["cves"][0]["nvdUrl"])


class ReportStructureTests(unittest.TestCase):
    """Verify report navigation, limitations, framework and offline constraints."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.template = (ROOT / "csa_lab" / "templates" / "unified.html").read_text(
            encoding="utf-8"
        )
        cls.script = (ROOT / "csa_lab" / "templates" / "unified.js").read_text(
            encoding="utf-8"
        )
        cls.style = (ROOT / "csa_lab" / "templates" / "unified.css").read_text(
            encoding="utf-8"
        )

    def test_customer_sections_and_drill_down_are_present(self) -> None:
        for text in (
            "Endpoint Overview",
            "Affected endpoints",
            "Security Findings",
            "Control Results",
            "Vulnerability Exposure",
            "Assessment Limitations",
            "Framework &amp; Compliance Impact",
            "Collected System Information",
            "Advanced Technical Evidence",
        ):
            self.assertIn(text, self.template)
        self.assertIn('href="#{{ endpoint.anchorId }}"', self.template)
        self.assertIn("openFragment", self.script)

    def test_copy_markdown_and_filters_are_offline(self) -> None:
        self.assertIn("remediationMarkdown", self.script)
        self.assertIn("vulnerability-filter", self.template)
        self.assertIn("matrix-filter", self.template)
        self.assertNotIn("<script src=", self.template)
        self.assertNotIn("<link ", self.template)
        self.assertNotIn("@import", self.style)

    def test_access_denied_is_client_friendly_and_mode_aware(self) -> None:
        limitation = {"reason": "NOT_COLLECTED_ACCESS_DENIED"}
        self.assertIn("standard privileges", _limitation_reason(limitation))
        self.assertIn("Standard Privileges Assessment", _limitation_scope_note(limitation))

    def test_framework_mapping_is_provisional_and_actionable(self) -> None:
        row = _framework_rows([_finding("DEF-001", "HIGH")])[0]
        self.assertEqual(row["mappingStatus"], "PROVISIONAL")
        self.assertEqual(row["findingLinks"][0]["anchor"], "finding-def-001")
        self.assertEqual(row["affectedEndpointLinks"][0]["anchor"], "endpoint-pc-01")
        self.assertIn("baseline", row["recommendedAction"])

    def test_large_software_matrix_uses_compact_mode(self) -> None:
        endpoints = []
        for index in range(100):
            endpoint = _endpoint(cves=[])
            endpoint["displayName"] = f"PC-{index:03d}"
            endpoint["submissionId"] = f"SUB-{index:03d}"
            endpoints.append(endpoint)
        matrix = _software_matrix(endpoints)
        self.assertTrue(matrix["compact"])
        self.assertEqual(len(matrix["endpointNames"]), 100)

    def test_endpoint_findings_exclude_pass_and_info_control_results(self) -> None:
        controls = [
            {"finding": {"status": "FAIL"}},
            {"finding": {"status": "WARNING"}},
            {"finding": {"status": "PASS"}},
            {"finding": {"status": "INFO"}},
        ]
        self.assertEqual(_security_finding_count(controls), 2)

    def test_full_report_search_contract_is_present(self) -> None:
        for element_id in (
            "report-search",
            "search-status",
            "search-previous",
            "search-next",
            "search-clear",
        ):
            self.assertIn(f'id="{element_id}"', self.template)
        for implementation in (
            "createTreeWalker",
            "toLocaleLowerCase",
            "data-report-search-match",
            "detailsOpenedBySearch",
            "scrollIntoView",
            "window.CSAReportSearch",
        ):
            self.assertIn(implementation, self.script)
        self.assertIn("0 matches", self.script)
        self.assertIn("event.shiftKey", self.script)
        self.assertIn('event.key === "Escape"', self.script)

    def test_risk_score_is_explicitly_non_severity_metric(self) -> None:
        risk = _assessment_risk(
            100.0,
            [_finding("A", "HIGH", systemic=True)],
            _aggregate_cve([_endpoint(eligible=0, evaluated=0)]),
        )
        self.assertEqual(
            risk["scoreLabel"],
            "Prioritization and exposure score",
        )
        self.assertIn(
            "does not independently determine",
            risk["scoreExplanation"],
        )


if __name__ == "__main__":
    unittest.main()
