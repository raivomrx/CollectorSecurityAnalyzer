"""Sprint 5.2.3 software intelligence coverage hardening tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from csa_lab.unified_report import (
    _software_intelligence_coverage,
    _software_matrix,
)
from cve.cpe_resolver import CpeResolver
from cve.models import ApplicabilityStatus, CpeMatchStatus
from cve.service import CveService
from software.inventory import build_inventory
from software.lifecycle import LifecycleRepository
from software.models import SoftwareProduct

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "home_software_inventory_sanitized.json"
ADOBE_ADVISORY = (
    "https://helpx.adobe.com/security/products/illustrator/apsb21-42.html"
)


class HomeInventoryAcceptanceTests(unittest.TestCase):
    """Verify the sanitized HOME acceptance inventory."""

    def setUp(self) -> None:
        """Load the minimized, privacy-safe HOME inventory."""

        self.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_fixture_contains_every_declared_legacy_problem(self) -> None:
        """Every legacy FAILED/PARTIAL/mapping issue must remain reproducible."""

        names = {item["DisplayName"] for item in self.fixture["software"]}
        problems = self.fixture["legacyProblemStates"]
        self.assertTrue(problems)
        self.assertEqual(
            {item["state"] for item in problems},
            {"FAILED", "PARTIAL", "NO_RELIABLE_MAPPING"},
        )
        self.assertTrue({item["product"] for item in problems} <= names)
        self.assertFalse(self.fixture["privacy"]["realComputerNames"])
        self.assertFalse(self.fixture["privacy"]["installLocations"])

    def test_mainstream_home_products_normalize_confidently(self) -> None:
        """Controlled aliases should normalize unambiguous mainstream products."""

        with tempfile.TemporaryDirectory() as temp_dir:
            inventory = build_inventory(
                self.fixture["software"],
                unknown_products_path=Path(temp_dir) / "unknown.json",
            )
        products = {item.product: item for item in inventory.products}
        expected = {
            "7-Zip 26.00 (x64)": ("7-Zip", "7-Zip"),
            "Adobe Illustrator 2021": ("Adobe", "Adobe Illustrator"),
            "Adobe Lightroom Classic": ("Adobe", "Adobe Lightroom Classic"),
            "Adobe Premiere Pro 2019": ("Adobe", "Adobe Premiere Pro"),
            "IrfanView 4.58 (64-bit)": ("IrfanView", "IrfanView"),
            "VLC media player": ("VideoLAN", "VLC media player"),
            "XAMPP": ("Apache Friends", "XAMPP"),
        }
        for name, normalized in expected.items():
            with self.subTest(product=name):
                product = products[name]
                self.assertEqual(
                    (product.normalized_vendor, product.normalized_product),
                    normalized,
                )
                self.assertGreaterEqual(product.confidence, 95)

    def test_unknown_mainstream_identity_enters_discovery_not_confirmation(self) -> None:
        """A raw identity may enter discovery without claiming normalization."""

        with tempfile.TemporaryDirectory() as temp_dir:
            inventory = build_inventory(
                self.fixture["software"],
                unknown_products_path=Path(temp_dir) / "unknown.json",
            )
        internal = next(
            item for item in inventory.products
            if item.product == "Internal Client"
        )
        driver = next(
            item for item in inventory.products
            if item.product.startswith("Windows Driver Package")
        )
        self.assertEqual(internal.confidence, 0)
        self.assertTrue(internal.discovery_eligible)
        self.assertEqual(internal.normalization_status, "DISCOVERY_CANDIDATE")
        self.assertFalse(driver.discovery_eligible)
        self.assertEqual(driver.normalization_status, "FAILED")


class CpeDiscoveryTests(unittest.TestCase):
    """Verify local and automatic NVD CPE mapping decisions."""

    def test_7zip_vendor_and_local_mapping_are_deterministic(self) -> None:
        """Igor Pavlov inventory must resolve through canonical 7-Zip identity."""

        with tempfile.TemporaryDirectory() as temp_dir:
            product = build_inventory(
                [{
                    "Publisher": "Igor Pavlov",
                    "DisplayName": "7-Zip 26.00 (x64)",
                    "DisplayVersion": "26.00",
                }],
                unknown_products_path=Path(temp_dir) / "unknown.json",
            ).products[0]
        resolution = CpeResolver(client=None).resolve_with_trace(product)
        self.assertEqual(product.normalized_vendor, "7-Zip")
        self.assertEqual(resolution.status, "SUCCESS")
        self.assertEqual(resolution.candidate_count, 1)
        self.assertIsNotNone(resolution.candidate)
        self.assertIn("7-zip:7-zip", resolution.candidate.cpe_name)

    def test_nvd_versions_collapse_to_one_product_identity(self) -> None:
        """NVD version rows for one product must not create false ambiguity."""

        resolver = CpeResolver(client=_DiscoveryClient([
            _cpe_product("acme", "acme_tool", "1.0", "Acme Tool 1.0"),
            _cpe_product("acme", "acme_tool", "2.0", "Acme Tool 2.0"),
        ]))
        resolution = resolver.resolve_with_trace(_discovery_product())
        self.assertEqual(resolution.status, "SUCCESS")
        self.assertEqual(resolution.candidate_count, 1)
        self.assertEqual(
            resolution.candidate.source,
            "NVD_CPE_API_DISCOVERY",
        )

    def test_equally_strong_distinct_products_are_ambiguous(self) -> None:
        """Discovery must not choose between distinct top-ranked identities."""

        resolver = CpeResolver(client=_DiscoveryClient([
            _cpe_product("acme", "acme_tool", "1.0", "Acme Tool"),
            _cpe_product("acme", "acme_tool_2026", "1.0", "Acme Tool 2026"),
        ]))
        resolution = resolver.resolve_with_trace(_discovery_product())
        self.assertEqual(resolution.status, "AMBIGUOUS")
        self.assertEqual(resolution.candidate.match_status, CpeMatchStatus.AMBIGUOUS)

    def test_no_reliable_candidate_is_not_evaluated(self) -> None:
        """An unrelated NVD result must not become a guessed mapping."""

        resolver = CpeResolver(client=_DiscoveryClient([
            _cpe_product("other", "unrelated", "1.0", "Other Product"),
        ]))
        resolution = resolver.resolve_with_trace(_discovery_product())
        self.assertEqual(resolution.status, "NO_RELIABLE_MAPPING")
        self.assertIsNone(resolution.candidate)


class AdobeAcceptanceTests(unittest.TestCase):
    """Verify Illustrator CVE and Creative Cloud lifecycle acceptance."""

    def test_illustrator_2523_confirms_two_source_backed_cves(self) -> None:
        """Illustrator 25.2.3 must confirm APSB21-42 version-range CVEs."""

        with tempfile.TemporaryDirectory() as temp_dir:
            inventory = build_inventory(
                [{
                    "Publisher": "Adobe Inc.",
                    "DisplayName": "Adobe Illustrator 2021",
                    "DisplayVersion": "25.2.3",
                }],
                unknown_products_path=Path(temp_dir) / "unknown.json",
            )
        client = _AdobeClient()
        summary = CveService(
            client=client,
            resolver=CpeResolver(client=client),
        ).scan_inventory(inventory)
        confirmed = {
            item.cve.cve_id
            for item in summary.assessments
            if item.applicability == ApplicabilityStatus.AFFECTED
        }
        self.assertEqual(
            confirmed,
            {"CVE-2021-36009", "CVE-2021-36011"},
        )
        self.assertEqual(summary.coverage_percent, 100.0)
        self.assertEqual(
            summary.product_evaluations[0].cve_result_status,
            "CONFIRMED",
        )
        self.assertEqual(
            summary.product_evaluations[0].mapping_source,
            "LOCAL_MAPPING",
        )
        self.assertTrue(
            all(
                item.cve.vendor_advisory_urls == [ADOBE_ADVISORY]
                for item in summary.assessments
            )
        )

    def test_adobe_lifecycle_uses_release_channel_policy(self) -> None:
        """Old Adobe releases should be assessed through N/N-1/LTS policy."""

        repository = LifecycleRepository()
        old = SoftwareProduct(
            vendor="Adobe Inc.",
            product="Adobe Illustrator 2021",
            version="25.2.3",
            normalized_vendor="Adobe",
            normalized_product="Adobe Illustrator",
            normalized_version="25.2.3",
            confidence=100,
        )
        current = SoftwareProduct(
            vendor="Adobe Inc.",
            product="Adobe Illustrator",
            version="30.1",
            normalized_vendor="Adobe",
            normalized_product="Adobe Illustrator",
            normalized_version="30.1",
            confidence=100,
        )
        self.assertEqual(
            repository.assess(old, assessed_on=date(2026, 8, 18)).status.value,
            "OUT_OF_SUPPORT",
        )
        self.assertEqual(
            repository.assess(current, assessed_on=date(2026, 8, 18)).status.value,
            "SUPPORTED",
        )


class SoftwareCoverageReportTests(unittest.TestCase):
    """Verify report coverage and honest risk wording."""

    def test_software_intelligence_coverage_counts_terminal_products(self) -> None:
        """Coverage should expose every pipeline denominator and outcome."""

        rows = [
            _report_product("COMPLETED", "SUPPORTED", 100, "SUCCESS"),
            _report_product("NOT_EVALUATED", "NOT_EVALUATED", 100, "NO_RELIABLE_MAPPING"),
            _report_product("NOT_ELIGIBLE", "NOT_EVALUATED", 0, "NOT_RUN", eligible=False),
        ]
        coverage = _software_intelligence_coverage(rows)
        self.assertEqual(coverage["productsDiscovered"], 3)
        self.assertEqual(coverage["normalizedConfidently"], 2)
        self.assertEqual(coverage["cveEligible"], 2)
        self.assertEqual(coverage["cveEvaluated"], 1)
        self.assertEqual(coverage["lifecycleEvaluated"], 1)
        self.assertEqual(coverage["unknownOrUnmapped"], 2)
        self.assertEqual(coverage["coveragePercent"], 50.0)

    def test_unified_template_exposes_coverage_and_source_links(self) -> None:
        """Customer report must expose coverage plus NVD/vendor references."""

        template = (
            ROOT / "csa_lab" / "templates" / "unified.html"
        ).read_text(encoding="utf-8")
        for label in (
            "Software Intelligence Coverage",
            "Software products discovered",
            "Normalized confidently",
            "Unknown / unmapped products",
            "cve.nvdUrl",
            "cve.vendorAdvisoryUrls",
        ):
            self.assertIn(label, template)

    def test_none_identified_requires_complete_cve_and_lifecycle_evaluation(self) -> None:
        """Unassessed products must never appear clean in the matrix."""

        endpoint = {
            "displayName": "HOME-01",
            "softwareResults": [
                {
                    **_report_product(
                        "NOT_EVALUATED",
                        "NOT_EVALUATED",
                        100,
                        "NO_RELIABLE_MAPPING",
                    ),
                    "normalizedProduct": "Unmapped Product",
                    "displayName": "Unmapped Product",
                    "displayVersion": "1.0",
                },
                {
                    **_report_product(
                        "COMPLETED",
                        "SUPPORTED",
                        100,
                        "SUCCESS",
                    ),
                    "normalizedProduct": "Evaluated Product",
                    "displayName": "Evaluated Product",
                    "displayVersion": "2.0",
                    "cveEvaluationStatus": "NO_KNOWN_VULNERABILITIES",
                },
            ],
        }
        matrix = {
            item["software"]: item["risk"]
            for item in _software_matrix([endpoint])["rows"]
        }
        self.assertIn("Product not recognized", matrix["Unmapped Product"])
        self.assertIn("Lifecycle not evaluated", matrix["Unmapped Product"])
        self.assertEqual(matrix["Evaluated Product"], "None identified")


class _DiscoveryClient:
    def __init__(self, products: list[dict]) -> None:
        self.products = products

    def get_cpes(self, _params: dict) -> list[dict]:
        return self.products


class _AdobeClient:
    def get_cpes(self, _params: dict) -> list[dict]:
        raise AssertionError("Illustrator must use its validated local mapping")

    def get_cves(self, _params: dict) -> list[dict]:
        return [
            {"cve": _adobe_cve("CVE-2021-36009", 7.8)},
            {"cve": _adobe_cve("CVE-2021-36011", 8.3)},
        ]


def _discovery_product() -> SoftwareProduct:
    return SoftwareProduct(
        vendor="Acme Inc.",
        product="Acme Tool",
        version="1.0",
        normalized_vendor="Acme",
        normalized_product="Acme Tool",
        normalized_version="1.0",
        confidence=0,
        discovery_eligible=True,
        normalization_status="DISCOVERY_CANDIDATE",
    )


def _cpe_product(vendor: str, product: str, version: str, title: str) -> dict:
    return {
        "cpe": {
            "cpeName": f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*",
            "deprecated": False,
            "titles": [{"lang": "en", "title": title}],
        }
    }


def _adobe_cve(cve_id: str, score: float) -> dict:
    return {
        "id": cve_id,
        "descriptions": [{
            "lang": "en",
            "value": "Adobe Illustrator 25.2.3 and earlier is affected.",
        }],
        "metrics": {
            "cvssMetricV31": [{
                "type": "Primary",
                "cvssData": {
                    "baseScore": score,
                    "baseSeverity": "HIGH",
                },
            }]
        },
        "references": [{
            "url": ADOBE_ADVISORY,
            "tags": ["Vendor Advisory"],
        }],
        "configurations": [{
            "nodes": [{
                "operator": "OR",
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:adobe:illustrator:*:*:*:*:*:*:*:*",
                    "versionEndIncluding": "25.2.3",
                }],
            }],
        }],
    }


def _report_product(
    terminal: str,
    lifecycle: str,
    confidence: int,
    mapping: str,
    *,
    eligible: bool = True,
) -> dict:
    return {
        "normalizationConfidence": confidence,
        "lifecycleStatus": lifecycle,
        "cveEvaluationStatus": (
            "NO_KNOWN_VULNERABILITIES"
            if terminal == "COMPLETED"
            else "NOT_EVALUATED"
        ),
        "confirmedCves": 0,
        "possibleCves": 0,
        "cvePipeline": {
            "eligibilityStatus": "ELIGIBLE" if eligible else "NOT_ELIGIBLE",
            "productMappingStatus": mapping,
            "terminalStatus": terminal,
        },
    }


if __name__ == "__main__":
    unittest.main()
