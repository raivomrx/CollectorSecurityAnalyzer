"""Tests for AnalysisContext integration."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import analyzer
from analysis_context import AnalysisContext
from evidence.registry import WindowsEvidenceRegistry
from risk import Status
from rules.admins import AdminRule
from rules.bitlocker import BitLockerRule
from rules.defender import DefenderRule
from rules.firewall import FirewallRule
from rules.network import NetworkRule
from rules.software import SoftwareInventoryRule
from rules.updates import UpdatesRule
from software.inventory import build_inventory
from software.models import SoftwareInventory, SoftwareProduct


class AnalysisContextTests(unittest.TestCase):
    """Validate shared analysis context behavior."""

    def test_analyzer_builds_software_inventory_once(self) -> None:
        """Analyzer flow should build software inventory once and share it."""

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "output"
            with patch("analyzer.build_inventory", wraps=build_inventory) as mocked:
                analyzer.analyze_file("samples/EE-D3147.json", output_dir=output_dir)

        self.assertEqual(mocked.call_count, 1)

    def test_software_rule_uses_context_inventory(self) -> None:
        """Software rule should use context inventory instead of rebuilding it."""

        product = SoftwareProduct(
            vendor="Unknown Vendor",
            product="Unknown Product",
            version="1.0",
            normalized_vendor="Unknown Vendor",
            normalized_product="Unknown Product",
            normalized_version="1.0",
            confidence=0,
        )
        context = AnalysisContext(
            raw_data={"Software": []},
            software_inventory=SoftwareInventory(
                products=[product],
                product_count=1,
                vendor_count=1,
                unknown_products=[product],
            ),
        )

        with patch("rules.software.build_inventory", side_effect=AssertionError):
            findings = SoftwareInventoryRule().check({"Software": []}, context)

        self.assertEqual(findings[0].evidence["unknown_product_count"], 1)
        self.assertEqual(findings[0].evidence["unknown_product_names"], ["Unknown Product"])

    def test_missing_canonical_evidence_never_becomes_failure(self) -> None:
        """Canonical Console runs must not treat absent evidence as false."""

        context = AnalysisContext(
            raw_data={},
            software_inventory=build_inventory([]),
            evidence_registry=WindowsEvidenceRegistry([]),
        )
        for rule in (
            BitLockerRule(),
            DefenderRule(),
            FirewallRule(),
            AdminRule(),
            NetworkRule(),
            UpdatesRule(),
        ):
            with self.subTest(rule_id=rule.id):
                findings = rule.run({}, context)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].status, Status.NOT_EVALUATED)
                self.assertEqual(findings[0].score, 0)

    def test_passive_analysis_records_active_validation_disabled(self) -> None:
        """Normal analyzer flow should explicitly report that active testing was disabled."""

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "output"
            analyzer.analyze_file("samples/EE-D3147.json", output_dir=output_dir)
            analysis_path = output_dir / "EE-D3147.analysis.json"
            document = json.loads(analysis_path.read_text(encoding="utf-8"))

        self.assertIn("activeValidation", document)
        self.assertFalse(document["activeValidation"]["enabled"])
        self.assertEqual("DISABLED", document["activeValidation"]["state"])
        self.assertFalse(
            document["activeValidation"]["formalAuthorizationVerified"]
        )


if __name__ == "__main__":
    unittest.main()
