"""Tests for HTML report generation."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from knowledge.models import Knowledge, Reference
from report import generate_html_report
from risk import AuditFinding, Finding, Severity, Status
from software.inventory import build_inventory


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
                output_path=output_path,
            )
            html = report_path.read_text(encoding="utf-8")

        self.assertTrue(report_path.name.endswith(".html"))
        self.assertIn("EE-D3147", html)
        self.assertIn("Security Score", html)
        self.assertIn("BIT-001", html)
        self.assertIn("Software Inventory", html)
        self.assertIn("Unknown Product", html)


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


if __name__ == "__main__":
    unittest.main()
