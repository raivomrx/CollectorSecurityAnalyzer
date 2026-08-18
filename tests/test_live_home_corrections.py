"""Regressions derived from sanitized HOME live-acceptance evidence."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from analysis_context import AnalysisContext
from collector_schema.enums import CollectionStatus, ConfigurationSource
from csa_lab.unified_report import (
    _collected_system_information,
    _executive_endpoint_metrics,
)
from evidence.registry import WindowsEvidenceRegistry
from evidence.windows_models import SecuritySettingEvidence
from risk import Status
from rules.network import NetworkRule
from rules.windows.account_rules import Acc010Rule, Acc011Rule
from software.inventory import build_inventory

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "home_endpoint_sanitized.json"


class HomeLiveAcceptanceTests(unittest.TestCase):
    """Protect correctness issues observed on the sanitized HOME endpoint."""

    @classmethod
    def setUpClass(cls) -> None:
        """Load the non-identifying shape-preserving HOME fixture."""

        cls.fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))

    def test_daily_user_local_admin_is_a_separate_finding(self) -> None:
        """A SID match must fail ACC-011 while ACC-010 remains independent."""

        context = self._context()
        daily_admin = Acc011Rule().check({}, context)[0]
        unresolved = Acc010Rule().check({}, context)[0]

        self.assertEqual(daily_admin.status, Status.FAIL)
        self.assertEqual(daily_admin.rule_id, "ACC-011")
        self.assertTrue(daily_admin.evidence["matched"])
        self.assertEqual(daily_admin.affected_asset, "LAB-HOME-01")
        self.assertEqual(unresolved.status, Status.FAIL)
        self.assertEqual(unresolved.rule_id, "ACC-010")

    def test_network_rule_recovers_public_without_rendering_object_artifact(
        self,
    ) -> None:
        """Legacy Length objects must resolve from public-adapter evidence."""

        finding = NetworkRule().check({}, self._context())[0]

        self.assertEqual(finding.status, Status.FAIL)
        self.assertEqual(finding.evidence["NetworkCategory"], ["Public"])

    def test_home_report_renders_human_readable_public_category(self) -> None:
        """The client report must not expose internal PowerShell object text."""

        information = _collected_system_information(self.fixture)
        category = information["network"]["Active network category"]

        self.assertEqual(category, "Public")
        self.assertNotIn("Length", category)

    def test_partial_cve_fixture_has_auditable_terminal_failure(self) -> None:
        """Every eligible product that stops early must explain its outcome."""

        evaluation = self.fixture["cveSummary"]["productEvaluations"][0]

        for field in (
            "displayName",
            "version",
            "productMappingStatus",
            "cpe",
            "provider",
            "failureStage",
            "failureReason",
            "retryable",
            "terminalStatus",
        ):
            self.assertIn(field, evaluation)
        self.assertEqual(evaluation["terminalStatus"], "NOT_EVALUATED")

    def test_executive_summary_counts_bitlocker_and_daily_admin_endpoints(
        self,
    ) -> None:
        """Executive metrics must count endpoint facts, not control rows."""

        metrics = _executive_endpoint_metrics([
            {
                "bitLocker": {"status": "PASS"},
                "privilegeContext": self.fixture["privilegeContext"],
                "findings": [],
            },
            {
                "bitLocker": {"status": "FAIL"},
                "privilegeContext": {
                    "isLocalAdministratorMember": False,
                },
                "findings": [],
            },
        ])

        self.assertEqual(metrics["assessedEndpoints"], 2)
        self.assertEqual(metrics["bitLockerEnabledEndpoints"], 1)
        self.assertEqual(metrics["dailyUserLocalAdminEndpoints"], 1)

    def test_executive_summary_renders_endpoint_posture_labels(self) -> None:
        """Both requested fleet counters must be visible in section 01."""

        template = (
            Path(__file__).parents[1]
            / "csa_lab"
            / "templates"
            / "unified.html"
        ).read_text(encoding="utf-8")

        self.assertIn("Computers with BitLocker enabled", template)
        self.assertIn("Computers with daily-user admin privileges", template)

    def test_report_and_lab_expose_terminal_diagnostics(self) -> None:
        """Both customer report and Advanced Details must expose root cause."""

        root = Path(__file__).parents[1]
        report_template = (
            root / "csa_lab" / "templates" / "unified.html"
        ).read_text(encoding="utf-8")
        lab_script = (
            root / "csa_lab" / "templates" / "lab.js"
        ).read_text(encoding="utf-8")

        for label in ("Failure stage", "Failure reason", "Retryable"):
            self.assertIn(label, report_template)
            self.assertIn(label, lab_script)
        for field in (
            "pipeline.cpe",
            "pipeline.provider",
            "pipeline.terminalStatus",
        ):
            self.assertIn(field, report_template)

    def _context(self) -> AnalysisContext:
        settings = [
            _setting(item)
            for item in self.fixture["securityPolicies"]["settings"]
        ]
        document = SimpleNamespace(
            device=SimpleNamespace(
                computer_name="LAB-HOME-01",
                current_user_sid=self.fixture["identity"]["currentUserSid"],
            )
        )
        return AnalysisContext(
            raw_data=self.fixture,
            software_inventory=build_inventory([]),
            collector_document=document,
            evidence_registry=WindowsEvidenceRegistry(settings),
        )


def _setting(item: dict[str, Any]) -> SecuritySettingEvidence:
    """Convert one shape-preserving fixture setting into normalized evidence."""

    return SecuritySettingEvidence(
        setting_id=str(item["settingId"]),
        category=str(item.get("category", "")),
        configured_value=item.get("configuredValue"),
        effective_value=item.get("effectiveValue"),
        source=ConfigurationSource(item.get("source", "RUNTIME_STATE")),
        collection_status=CollectionStatus(
            item.get("collectionStatus", "SUCCESS")
        ),
        confidence=int(item.get("confidence", 90)),
        collected_at=datetime.now(timezone.utc),
        provider=str(item.get("provider", "fixture")),
        source_path=item.get("sourcePath"),
        error_code=None,
        error_message=None,
    )


if __name__ == "__main__":
    unittest.main()
