"""Tests for AnalysisContext integration."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import analyzer
from analysis_context import AnalysisContext
from rules.software import SoftwareInventoryRule
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


if __name__ == "__main__":
    unittest.main()
