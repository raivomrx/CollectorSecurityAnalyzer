"""Tests for the Software Intelligence Engine."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from software.inventory import build_inventory
from software.normalizer import normalize_product, normalize_software, normalize_vendor
from software.version import compare_versions, parse_version


class SoftwareIntelligenceTests(unittest.TestCase):
    """Validate software normalization, versioning, and inventory behavior."""

    def test_vendor_normalization(self) -> None:
        """Known vendor aliases should normalize to canonical names."""

        self.assertEqual(normalize_vendor("Google LLC").value, "Google")
        self.assertEqual(normalize_vendor("Microsoft Corporation").value, "Microsoft")
        self.assertEqual(normalize_vendor("Dell Technologies, Inc.").value, "Dell")

    def test_product_normalization(self) -> None:
        """Known product aliases should normalize to canonical names."""

        self.assertEqual(normalize_product("Zoom Workplace (64-bit)").value, "Zoom Workplace")
        self.assertEqual(normalize_product("Google Chrome").value, "Google Chrome")
        self.assertEqual(normalize_product("Java 8 Update 471 (64-bit)").value, "Java 8")
        self.assertEqual(
            normalize_product("Microsoft Visual C++ 2022 X64 Additional Runtime").value,
            "Microsoft Visual C++ 2022 Redistributable",
        )

    def test_version_parser(self) -> None:
        """Versions should normalize and compare by numeric parts."""

        self.assertEqual(parse_version("25.01").normalized, "25.1")
        self.assertEqual(parse_version("144.0.7559.60").parts, (144, 0, 7559, 60))
        self.assertEqual(compare_versions("25.01.0", "25.01.00.0"), 0)
        self.assertEqual(compare_versions("8.0.4710.9", "8.0.4700.9"), 1)

    def test_confidence_score(self) -> None:
        """Confidence should reflect exact, fuzzy, vendor-only, and unknown matches."""

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "unknown_products.json"
            exact = normalize_software("Google LLC", "Google Chrome", "144.0.7559.60", unknown_products_path=path)
            fuzzy = normalize_software("Zoom", "Zoom Workplace (32-bit)", "25.01", unknown_products_path=path)
            vendor_only = normalize_software("Microsoft Corporation", "Unknown App", "1.0", unknown_products_path=path)
            unknown = normalize_software("Mystery Vendor", "Mystery App", "1.0", unknown_products_path=path)

        self.assertEqual(exact.confidence, 100)
        self.assertEqual(fuzzy.confidence, 95)
        self.assertEqual(vendor_only.confidence, 60)
        self.assertEqual(unknown.confidence, 0)

    def test_unknown_software_detection(self) -> None:
        """Unknown software should be written to the unknown products file."""

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "unknown_products.json"
            software = normalize_software(
                "Unknown Vendor",
                "Unknown Product",
                "1.0",
                unknown_products_path=path,
            )

            entries = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(software.confidence, 0)
            self.assertEqual(entries[0]["product"], "Unknown Product")

    def test_inventory_builder(self) -> None:
        """Inventory should count products, vendors, duplicates, and unknowns."""

        with tempfile.TemporaryDirectory() as temp_dir:
            inventory = build_inventory(
                [
                    {"Vendor": "Google LLC", "Product": "Google Chrome", "Version": "144.0.7559.60"},
                    {"Vendor": "Google", "Product": "Google Chrome", "Version": "144.0.7559.60"},
                    {"Vendor": "Dell Inc.", "Product": "Unknown Dell Tool", "Version": "1.0"},
                ],
                unknown_products_path=Path(temp_dir) / "unknown_products.json",
            )

        self.assertEqual(inventory.product_count, 3)
        self.assertEqual(inventory.vendor_count, 2)
        self.assertEqual(len(inventory.duplicate_entries), 2)
        self.assertEqual(len(inventory.unknown_products), 1)


if __name__ == "__main__":
    unittest.main()
