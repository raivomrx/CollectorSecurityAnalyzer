"""Sprint 5.4.1 product identity, request volume and operator controls."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from csa_lab.unified_report import (
    _aggregate_software_intelligence,
    _product_label,
    _remediation_plan,
    _software_intelligence_coverage,
)
from cve.cache import NvdCache
from cve.client import NvdClient
from cve.cpe_resolver import CpeResolver
from cve.exceptions import CveScanCancelled
from cve.rate_limiter import SlidingWindowRateLimiter
from cve.service import CveService
from software.inventory import build_inventory
from software.normalizer import normalize_product


HOME_PRODUCTS = json.loads(
    (Path(__file__).parent / "fixtures" / "sprint541" / "home_mainstream_sanitized.json")
    .read_text(encoding="utf-8")
)["software"]


def _cpe(vendor: str, product: str, version: str = "-", *, target_sw: str = "*") -> dict:
    """Create a sanitized NVD-like CPE row without CVE content."""

    return {"cpe": {
        "cpeName": f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:{target_sw}:*:*",
        "titles": [{"lang": "en", "title": f"{vendor} {product} {version}"}],
        "deprecated": False,
    }}


class CatalogClient:
    """Record product-family discovery and reuse a persistent local catalog."""

    def __init__(self, cache: NvdCache) -> None:
        self.cache = cache
        self.queries: list[str] = []
        self.cve_queries: list[dict] = []

    def get_cpes(self, params: dict) -> list[dict]:
        """Return only verified family identities and decoy platform variants."""

        query = params["keywordSearch"]
        self.queries.append(query)
        if query == "Notepad++":
            return [_cpe("notepad-plus-plus", r"notepad\+\+", "7.8.8")]
        if query == "Microsoft Visual Studio Code":
            return [_cpe("microsoft", "visual_studio_code", "1.137.0"),
                    _cpe("microsoft", "visual_studio_code", "1.137.0", target_sw="python")]
        if query == "Microsoft Teams":
            return [_cpe("microsoft", "teams", "1.4.00.32771"),
                    _cpe("microsoft", "teams", "1.4.00.32771", target_sw="android")]
        if query == "NVIDIA GPU Display Driver":
            return [_cpe("nvidia", "gpu_display_driver", "466.11"),
                    _cpe("nvidia", "gpu_display_driver", "466.11", target_sw="windows"),
                    _cpe("nvidia", "gpu_display_driver", "466.11", target_sw="linux")]
        return []

    def get_cves(self, params: dict) -> list[dict]:
        """Return no CVEs; this test verifies mapping and pipeline completion."""

        self.cve_queries.append(params)
        return []


class Sprint541Tests(unittest.TestCase):
    """Keep HOME-like mainstream software auditable without hard-coded CVEs."""

    def setUp(self) -> None:
        """Use an isolated catalog and unknown-product backlog per test."""

        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def _inventory(self):
        """Build the sanitized four-product HOME inventory."""

        return build_inventory(
            [{"Publisher": row["publisher"], "DisplayName": row["displayName"],
              "DisplayVersion": row["displayVersion"]} for row in HOME_PRODUCTS],
            unknown_products_path=self.root / "unknown.json",
        )

    def test_home_products_reach_reliable_evaluation(self) -> None:
        """Packaging and scope suffixes must not break mainstream identities."""

        inventory = self._inventory()
        self.assertEqual(
            [item.normalized_product for item in inventory.products],
            [row["expectedProduct"] for row in HOME_PRODUCTS],
        )
        client = CatalogClient(NvdCache(self.root / "nvd.sqlite3"))
        summary = CveService(client=client, resolver=CpeResolver(client=client)).scan_inventory(
            inventory, raw_data={"OS": "Microsoft Windows 11"}
        )
        self.assertEqual(summary.eligible_products, 4)
        self.assertEqual(summary.evaluated_products, 4)
        self.assertEqual(len(client.queries), 4)
        self.assertEqual(len(client.cve_queries), 4)
        for row in summary.product_evaluations:
            with self.subTest(row.display_name):
                self.assertEqual(row.product_mapping_status, "SUCCESS")
                self.assertEqual(row.terminal_status, "COMPLETED")
                self.assertEqual(row.mapping_source, "NVD_CPE_API_DISCOVERY")
                self.assertTrue(row.cpe)
                self.assertEqual(len(row.discovery_trace["queries"]), 1)
        driver = next(row for row in summary.product_evaluations if row.display_name.startswith("NVIDIA"))
        self.assertIn(":windows:*:*", driver.cpe)
        teams_query = next(
            query for query in client.cve_queries
            if "teams" in str(query).casefold()
        )
        self.assertIn(":1.4.00.32771:", teams_query["cpeName"])
        teams = next(row for row in summary.product_evaluations if row.display_name == "Microsoft Teams")
        self.assertTrue(teams.discovery_trace["installedVersionCatalogued"])
        self.assertTrue(teams.discovery_trace["topCandidates"][0]["installedVersionAvailable"])

    def test_uncatalogued_version_uses_family_range_query(self) -> None:
        """A CPE snapshot without the installed version cannot prove zero CVEs."""

        class OlderCatalog(CatalogClient):
            def get_cpes(self, params):
                self.queries.append(params["keywordSearch"])
                return [_cpe("microsoft", "teams", "1.4.00.10000")]

        row = HOME_PRODUCTS[2]
        inventory = build_inventory(
            [{"Publisher": row["publisher"], "DisplayName": row["displayName"],
              "DisplayVersion": row["displayVersion"]}],
            unknown_products_path=self.root / "unknown.json",
        )
        client = OlderCatalog(NvdCache(self.root / "older.sqlite3"))
        summary = CveService(client=client, resolver=CpeResolver(client=client)).scan_inventory(
            inventory, raw_data={"OS": "Microsoft Windows 11"}
        )
        self.assertEqual(summary.evaluated_products, 1)
        self.assertEqual(summary.product_evaluations[0].discovery_trace["providerQueryMode"],
                         "FAMILY_RANGE")
        self.assertNotIn("cpeName", client.cve_queries[0])
        self.assertIn("virtualMatchString", client.cve_queries[0])

    def test_embedded_version_requires_same_installed_version(self) -> None:
        """A trailing version is stripped only when collector version corroborates it."""

        self.assertEqual(
            normalize_product("Notepad++ 7.8.8 (x86)", version="7.8.8.0").value,
            "Notepad++",
        )
        self.assertEqual(
            normalize_product("Notepad++ 7.8.8 (x86)", version="8.0").value,
            "Notepad++ 7.8.8",
        )

    def test_catalog_reuses_discovery_across_endpoint_runs(self) -> None:
        """A second endpoint should synchronize from local CPE intelligence."""

        client = CatalogClient(NvdCache(self.root / "nvd.sqlite3"))
        for _ in range(2):
            summary = CveService(client=client, resolver=CpeResolver(client=client)).scan_inventory(
                self._inventory(), raw_data={"OS": "Microsoft Windows 11"}
            )
        self.assertEqual(len(client.queries), 4)
        self.assertEqual(summary.evaluated_products, 4)
        self.assertTrue(all(row.discovery_trace["catalogHit"] for row in summary.product_evaluations))
        self.assertEqual(summary.telemetry["cpeCatalogHits"], 4)
        self.assertEqual(summary.telemetry["remoteCpeQueries"], 0)

    def test_invalid_catalog_entry_is_refetched(self) -> None:
        """A malformed persisted snapshot cannot become a trusted mapping."""

        cache = NvdCache(self.root / "corrupt.sqlite3")
        cache.set_cpe_catalog("family", [])
        connection = sqlite3.connect(cache.path)
        try:
            connection.execute(
                "UPDATE cpe_catalog SET products_json = ? WHERE identity = ?",
                ('{"cpeName": "not-a-list"}', "family"),
            )
            connection.commit()
        finally:
            connection.close()
        self.assertIsNone(cache.get_cpe_catalog("family"))

    def test_home_scale_cold_discovery_budget(self) -> None:
        """One cold family query per identity avoids 275-request search fan-out."""

        class FamilyClient(CatalogClient):
            def get_cpes(self, params):
                query = params["keywordSearch"]
                self.queries.append(query)
                return [_cpe("acme", query.casefold().replace(" ", "_"))]

        inventory = build_inventory(
            [{"Publisher": "Acme", "DisplayName": f"Product {index}",
              "DisplayVersion": "1.0"} for index in range(86)],
            unknown_products_path=self.root / "unknown.json",
        )
        client = FamilyClient(NvdCache(self.root / "fleet.sqlite3"))
        summary = CveService(client=client, resolver=CpeResolver(client=client)).scan_inventory(inventory)
        self.assertEqual(summary.evaluated_products, 86)
        self.assertEqual(len(client.queries), 86)
        self.assertEqual(len(client.cve_queries), 86)
        self.assertLess(len(client.queries) + len(client.cve_queries), 275)

    def test_unknown_identity_does_not_become_false_positive(self) -> None:
        """A nonmatching CPE must produce an auditable unmapped result."""

        class WrongClient(CatalogClient):
            def get_cpes(self, params):
                self.queries.append(params["keywordSearch"])
                return [_cpe("other", "unrelated_tool")]

        client = WrongClient(NvdCache(self.root / "wrong.sqlite3"))
        result = CveService(client=client, resolver=CpeResolver(client=client)).scan_inventory(
            self._inventory()
        )
        self.assertEqual(result.evaluated_products, 0)
        self.assertTrue(all(row.failure_stage == "PRODUCT_MAPPING" for row in result.product_evaluations))
        self.assertTrue(all(row.discovery_trace["topCandidates"] for row in result.product_evaluations))

    def test_platform_constraints_require_collector_evidence(self) -> None:
        """Never map a platform-only CPE from a product name alone."""

        class WindowsOnly(CatalogClient):
            def get_cpes(self, params):
                return [_cpe("nvidia", "gpu_display_driver", target_sw="windows")]

        product = self._inventory().products[-1]
        client = WindowsOnly(NvdCache(self.root / "platform.sqlite3"))
        resolver = CpeResolver(client=client)
        missing = resolver.resolve_with_trace(product, {})
        self.assertEqual(missing.status, "NO_RELIABLE_MAPPING")
        self.assertIn("collector OS", missing.reason)
        windows = resolver.resolve_with_trace(product, {"OS": "Microsoft Windows 11"})
        self.assertEqual(windows.status, "SUCCESS")
        self.assertIn(":windows:*:*", windows.candidate.cpe_name)

    def test_identification_follows_mapping_and_cannot_trail_evaluation(self) -> None:
        """Normalization confidence alone is not security product identification."""

        rows = [
            {"displayName": "Mapped", "displayVersion": "1.0", "normalizationConfidence": 0,
             "cvePipeline": {"productMappingStatus": "SUCCESS", "terminalStatus": "COMPLETED"}},
            {"displayName": "Normalized only", "displayVersion": "1.0", "normalizationConfidence": 100,
             "cvePipeline": {"productMappingStatus": "NO_RELIABLE_MAPPING", "terminalStatus": "NOT_EVALUATED"}},
        ]
        coverage = _software_intelligence_coverage(rows)
        self.assertEqual(coverage["normalizedConfidently"], 1)
        self.assertEqual(coverage["identifiedForSecurityAnalysis"], 1)
        self.assertEqual(coverage["cveEvaluated"], 1)
        fleet = _aggregate_software_intelligence([{"softwareResults": rows, "softwareIntelligence": {
            "normalizedConfidently": 0, "cveEvaluated": 2,
        }}])
        self.assertGreaterEqual(fleet["identifiedForSecurityAnalysis"], fleet["cveEvaluated"])

    def test_rate_limit_wait_can_be_cancelled(self) -> None:
        """An operator cancellation interrupts the limiter before network I/O."""

        event = threading.Event()
        event.set()
        limiter = SlidingWindowRateLimiter(requests=1, window_seconds=30)
        with self.assertRaises(CveScanCancelled):
            limiter.acquire(cancel_event=event)

    def test_provider_wait_publishes_state_and_stops_without_request(self) -> None:
        """The NVD client remains observable and interruptible during a wait."""

        class NoNetwork:
            def __init__(self):
                self.calls = 0

            def get(self, *_args, **_kwargs):
                self.calls += 1
                raise AssertionError("Provider request must not run after cancellation")

        limiter = SlidingWindowRateLimiter(requests=1, window_seconds=30)
        limiter.acquire()
        event = threading.Event()
        ready = threading.Event()
        progress: list[dict] = []
        errors: list[Exception] = []
        session = NoNetwork()
        client = NvdClient(
            cache=NvdCache(self.root / "waiting.sqlite3"), session=session,
            limiter=limiter, cancel_event=event,
            progress_callback=lambda details: (progress.append(details), ready.set()),
        )

        def run() -> None:
            try:
                client.get_cpes({"keywordSearch": "Notepad++"})
            except Exception as error:
                errors.append(error)

        worker = threading.Thread(target=run)
        worker.start()
        try:
            self.assertTrue(ready.wait(2))
            self.assertEqual(progress[0]["provider"], "NVD CPES")
            self.assertEqual(progress[0]["phase"], "RATE_LIMIT_WAIT")
        finally:
            event.set()
            worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(session.calls, 0)
        self.assertIsInstance(errors[0], CveScanCancelled)

    def test_client_semantics(self) -> None:
        """Do not duplicate versions or promote a generic CVE finding to action."""

        self.assertEqual(_product_label({"displayName": "NVIDIA Graphics Driver 466.11",
                                         "displayVersion": "466.11"}), "NVIDIA Graphics Driver")
        finding = {"ruleId": "CVE-001", "recommendation": "Generic CVE guidance",
                   "title": "Known vulnerability assessment", "severity": "HIGH",
                   "endpointReferences": ["HOME"]}
        self.assertEqual(_remediation_plan([], [finding]), [])
        software_finding = {**finding, "kind": "SOFTWARE_CVE",
                            "recommendation": "Update Notepad++ to a supported version"}
        self.assertEqual(len(_remediation_plan([], [software_finding])), 1)

        root = Path(__file__).resolve().parents[1]
        template = (root / "csa_lab" / "templates" / "unified.html").read_text(encoding="utf-8")
        knowledge = json.loads((root / "knowledge" / "knowledge.json").read_text(encoding="utf-8"))
        controls = json.loads((root / "knowledge" / "windows_security.json").read_text(encoding="utf-8"))
        self.assertNotIn("evaluated control results", template)
        self.assertIn("{{ software.productLabel }}", template)
        self.assertIn("identifiedForSecurityAnalysis", template)
        self.assertIn("vendor documentation", knowledge["entries"]["SW-001"]["recommendation"])
        self.assertEqual(knowledge["entries"]["SW-001"]["title"], "Software identity coverage")
        self.assertEqual(controls["entries"]["DEF-002"]["title"], "Defender real-time protection state")


if __name__ == "__main__":
    unittest.main()
