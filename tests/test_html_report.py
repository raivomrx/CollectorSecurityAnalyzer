"""Tests for HTML report generation."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from analysis_context import AnalysisContext
from active_validation.engine import disabled_run
from compliance.engine import ComplianceEngine
from compliance.repository import FrameworkRepository
from knowledge.models import Knowledge, Reference
from report import generate_html_report
from risk import AuditFinding, Finding, Severity, Status
from rules.categories import RuleCategory
from rules.metadata import RuleMetadata
from cve.models import (
    ApplicabilityStatus,
    CpeCandidate,
    CpeMatchStatus,
    CveAssessment,
    CveDataQuality,
    CveRecord,
    CveScanSummary,
)
from software.inventory import build_inventory
from software.models import SoftwareProduct


class HtmlReportTests(unittest.TestCase):
    """Validate HTML report output."""

    def test_html_report_contains_required_sections(self) -> None:
        """Generated HTML should contain summary, findings, software, and unknowns."""

        data = {
            "ComputerName": "EE-D3147",
            "OS": "Windows 11",
            "Domain": "EXAMPLE",
            "ForensicsDate": "2026-07-07",
            "Current_user": "alice",
        }
        audit_findings = [_audit_finding()]
        inventory = build_inventory(
            [
                {
                    "Vendor": "Unknown Vendor",
                    "Product": "Unknown Product",
                    "Version": "1.0",
                }
            ],
            unknown_products_path=Path(tempfile.gettempdir()) / "csa-test-unknown.json",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "EE-D3147.html"
            report_path = generate_html_report(
                data=data,
                audit_findings=audit_findings,
                score=82,
                software_inventory=inventory,
                rule_metadata={"BIT-001": _rule_metadata()},
                cve_summary=_cve_summary(),
                compliance_summary=_compliance_summary(audit_findings),
                active_validation=disabled_run(),
                output_path=output_path,
            )
            html = report_path.read_text(encoding="utf-8")
            script_exists = (report_path.parent / "report.js").exists()

        self.assertTrue(report_path.name.endswith(".html"))
        self.assertTrue(script_exists)
        self.assertIn("EE-D3147", html)
        self.assertIn("Security Score", html)
        self.assertIn("BIT-001", html)
        self.assertIn("Software Inventory", html)
        self.assertIn("Unknown Product", html)
        self.assertIn("Known Vulnerabilities", html)
        self.assertIn("This product uses the NVD API", html)
        self.assertIn("Coverage percent", html)
        self.assertIn("Compliance &amp; Policy Assessment", html)
        self.assertIn("automated evidence-based endpoint assessment", html)
        self.assertIn("MSB-BITLOCKER-001", html)
        self.assertIn("Profile version", html)
        self.assertIn("Assessment incomplete", html)
        self.assertIn("data-compliance-filters", html)
        self.assertIn("Active Validation", html)
        self.assertIn("Responder Attack Surface", html)
        self.assertIn("Authorization verified", html)
        self.assertIn(
            "Active validation performs only explicitly authorized",
            html,
        )
        self.assertIn(
            "Aktiivvalideerimine teeb ainult selgesõnaliselt lubatud",
            html,
        )

    def test_reporter_does_not_load_registry(self) -> None:
        """Reporter should render with provided metadata and not load registry."""

        data = {"ComputerName": "EE-D3147"}
        inventory = build_inventory([])
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "report.html"
            with patch("rules.loader.load_registry", side_effect=AssertionError):
                report_path = generate_html_report(
                    data=data,
                    audit_findings=[_audit_finding()],
                    score=90,
                    software_inventory=inventory,
                    rule_metadata={"BIT-001": _rule_metadata()},
                    cve_summary=None,
                    output_path=output_path,
                )

        self.assertEqual(report_path.name, "report.html")


def _audit_finding() -> AuditFinding:
    """Create a report test finding."""

    return AuditFinding(
        finding=Finding(
            rule_id="BIT-001",
            severity=Severity.HIGH,
            status=Status.FAIL,
            score=20,
            evidence={"Bitlocker-C": False},
        ),
        knowledge=Knowledge(
            id="BIT-001",
            title="BitLocker is disabled",
            description="BitLocker is not enabled.",
            risk="Data exposure.",
            recommendation="Enable BitLocker.",
            frameworks={"CIS": ["CIS-4.3"]},
            references=[
                Reference(
                    title="Microsoft Learn",
                    url="https://learn.microsoft.com/windows/security",
                    vendor="Microsoft",
                    type="Official",
                )
            ],
            knowledge_version="CSA-KB-2026.1",
        ),
    )


def _rule_metadata() -> RuleMetadata:
    """Create test rule metadata."""

    return RuleMetadata(
        id="BIT-001",
        title="BitLocker Enabled",
        version="1.0",
        author="CSA",
        category=RuleCategory.ENCRYPTION,
        severity=Severity.HIGH,
        enabled=True,
        description="Checks BitLocker.",
    )


def _cve_summary() -> CveScanSummary:
    """Create a report test CVE summary."""

    software = SoftwareProduct(
        vendor="Google LLC",
        product="Google Chrome",
        version="144.0.7559.60",
        normalized_vendor="Google",
        normalized_product="Google Chrome",
        normalized_version="144.0.7559.60",
        confidence=100,
    )
    cpe = CpeCandidate(
        cpe_name="cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
        title="Google Chrome",
        vendor="google",
        product="chrome",
        version=None,
        deprecated=False,
        confidence=100,
        match_status=CpeMatchStatus.EXACT,
        source="LOCAL_MAPPING",
    )
    cve = CveRecord(
        cve_id="CVE-2026-0001",
        description="Example vulnerability.",
        published=None,
        last_modified=None,
        cvss_version="3.1",
        cvss_score=9.8,
        severity="CRITICAL",
        vector=None,
        cwes=["CWE-79"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-0001"],
        configurations=[],
        source_identifier="nvd",
        vuln_status="Analyzed",
        data_quality=CveDataQuality.PARTIAL,
    )
    assessment = CveAssessment(
        software=software,
        cpe=cpe,
        cve=cve,
        applicability=ApplicabilityStatus.AFFECTED,
        reason="Installed version is within vulnerable range",
        confidence=95,
    )
    return CveScanSummary(
        scanned_products=1,
        unique_products=1,
        eligible_products=1,
        evaluated_products=1,
        coverage_percent=100.0,
        coverage_complete=True,
        products_with_cpe=1,
        products_without_cpe=0,
        ambiguous_cpe_matches=0,
        confirmed_vulnerabilities=1,
        possible_vulnerabilities=0,
        not_evaluated=0,
        api_errors=0,
        assessments=[assessment],
        errors=[],
        scan_complete=True,
    )


def _compliance_summary(audit_findings: list[AuditFinding]):
    """Create a report test compliance summary."""

    repository = FrameworkRepository()
    profile = repository.get_profile("windows_11_workstation")
    context = AnalysisContext(raw_data={"OS": "Windows 11"}, software_inventory=build_inventory([]))
    return ComplianceEngine(
        repository=repository,
        framework_filter=["MICROSOFT_BASELINE"],
    ).assess(context, audit_findings, [profile])


if __name__ == "__main__":
    unittest.main()
