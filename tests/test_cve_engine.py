"""Tests for the CVE Intelligence Engine."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import gc

from cve.applicability import evaluate_applicability
from cve.cache import NvdCache
from cve.cpe_resolver import CpeResolver, build_cpe23
from cve.models import (
    ApplicabilityStatus,
    CpeCandidate,
    CpeMatchStatus,
    CveDataQuality,
    CveRecord,
    CveScanSummary,
)
from cve.parser import parse_cve_record
from cve.rate_limiter import SlidingWindowRateLimiter
from cve.service import CveService
from rules.cve import KnownVulnerabilitiesRule
from software.models import SoftwareInventory, SoftwareProduct


class CveEngineTests(unittest.TestCase):
    """Validate CVE engine safety-critical behavior."""

    def test_local_cpe_mapping_and_escaping(self) -> None:
        """Resolver should use local mappings and escape CPE values safely."""

        software = _software()
        resolver = CpeResolver(client=None)
        candidate = resolver.resolve(software)

        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate.match_status, CpeMatchStatus.EXACT)
        self.assertEqual(candidate.source, "LOCAL_MAPPING")
        self.assertIn("google:chrome", candidate.cpe_name)
        self.assertEqual(build_cpe23("a", "Vendor:Name", "Product Name"), "cpe:2.3:a:vendor\\:name:product_name:*:*:*:*:*:*:*:*")

    def test_ambiguous_nvd_candidates_are_not_confirmed(self) -> None:
        """Ambiguous CPE candidates should remain ambiguous."""

        class Client:
            def get_cpes(self, params):
                return [
                    {"cpe": {"cpeName": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", "titles": [{"lang": "en", "title": "Vendor Product"}]}},
                    {"cpe": {"cpeName": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", "titles": [{"lang": "en", "title": "Vendor Product Pro"}]}},
                ]

        software = SoftwareProduct(
            vendor="Vendor",
            product="Product",
            version="1.0",
            normalized_vendor="Vendor",
            normalized_product="Product",
            normalized_version="1.0",
            confidence=100,
        )
        resolver = CpeResolver(client=Client(), minimum_confidence=65, ambiguous_score_difference=5)
        candidate = resolver.resolve(software)

        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate.match_status, CpeMatchStatus.AMBIGUOUS)

    def test_applicability_version_range(self) -> None:
        """Applicability should confirm only matching vulnerable ranges."""

        status, reason, confidence, matched = evaluate_applicability(
            _software(version="144.0.7559.60"),
            _cpe(),
            _cve_record(
                configurations=[
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "144.0.0.0",
                                        "versionEndExcluding": "145.0.0.0",
                                    }
                                ],
                            }
                        ]
                    }
                ]
            ),
        )

        self.assertEqual(status, ApplicabilityStatus.AFFECTED)
        self.assertGreaterEqual(confidence, 90)
        self.assertTrue(matched)
        self.assertIn("vulnerable", reason)

    def test_applicability_missing_config_is_not_evaluated(self) -> None:
        """Missing NVD configuration must not become affected."""

        status, _, _, _ = evaluate_applicability(_software(), _cpe(), _cve_record(configurations=[]))
        self.assertEqual(status, ApplicabilityStatus.NOT_EVALUATED)

    def test_parser_handles_missing_cvss_as_partial(self) -> None:
        """Missing CVSS should not drop the CVE."""

        record = parse_cve_record(
            {
                "id": "CVE-2026-0002",
                "descriptions": [{"lang": "en", "value": "Description"}],
                "configurations": [{"nodes": []}],
                "weaknesses": [{"description": [{"value": "CWE-79"}]}],
                "references": {"referenceData": [{"url": "https://example.test"}]},
            }
        )

        self.assertEqual(record.cve_id, "CVE-2026-0002")
        self.assertIsNone(record.cvss_score)
        self.assertEqual(record.data_quality, CveDataQuality.PARTIAL)
        self.assertEqual(record.cwes, ["CWE-79"])

    def test_cache_set_get_and_expiry(self) -> None:
        """NVD cache should return fresh entries and clear expired ones."""

        with tempfile.TemporaryDirectory() as temp_dir:
            cache = NvdCache(Path(temp_dir) / "cache.sqlite3")
            key = cache.make_key("endpoint", {"b": 2, "a": 1})
            self.assertEqual(key, cache.make_key("endpoint", {"a": 1, "b": 2}))
            cache.set(key, "endpoint", {"a": 1}, {"ok": True}, ttl_hours=1)
            self.assertEqual(cache.get(key), {"ok": True})
            cache.clear_all()
            self.assertIsNone(cache.get(key))
            del cache
            gc.collect()

    def test_rate_limiter_waits_when_window_full(self) -> None:
        """Rate limiter should sleep when the rolling window is full."""

        now_values = iter([0.0, 0.0, 0.5, 1.1])
        sleeps: list[float] = []
        limiter = SlidingWindowRateLimiter(
            requests=1,
            window_seconds=1,
            sleep=sleeps.append,
            now=lambda: next(now_values),
        )
        limiter.acquire()
        limiter.acquire()
        self.assertTrue(sleeps)

    def test_service_deduplicates_and_continues(self) -> None:
        """Service should deduplicate products and produce assessments."""

        class Client:
            def get_cves(self, params):
                return [{"cve": _nvd_cve_payload()}]

        class Resolver:
            def resolve(self, software):
                return _cpe()

        inventory = SoftwareInventory(products=[_software(), _software()], product_count=2)
        summary = CveService(client=Client(), resolver=Resolver()).scan_inventory(inventory)
        self.assertEqual(summary.unique_products, 1)
        self.assertEqual(summary.confirmed_vulnerabilities, 1)

    def test_cve_rule_states(self) -> None:
        """CVE rule should represent not-run, clean, and affected summaries."""

        rule = KnownVulnerabilitiesRule()
        not_run = rule.check({}, None)[0]
        self.assertEqual(not_run.status.value, "INFO")

        clean = CveScanSummary(0, 0, 0, 0, 0, 0, 0, 0, 0, [], [], True)
        context = type("Context", (), {"cve_summary": clean})()
        clean_finding = rule.check({}, context)[0]
        self.assertEqual(clean_finding.status.value, "PASS")


def _software(version: str = "144.0.7559.60") -> SoftwareProduct:
    """Create Chrome software."""

    return SoftwareProduct(
        vendor="Google LLC",
        product="Google Chrome",
        version=version,
        normalized_vendor="Google",
        normalized_product="Google Chrome",
        normalized_version=version,
        confidence=100,
    )


def _cpe() -> CpeCandidate:
    """Create Chrome CPE."""

    return CpeCandidate(
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


def _cve_record(configurations) -> CveRecord:
    """Create a CVE record."""

    return CveRecord(
        cve_id="CVE-2026-0001",
        description="Description",
        published=None,
        last_modified=None,
        cvss_version="3.1",
        cvss_score=9.8,
        severity="CRITICAL",
        vector=None,
        cwes=[],
        references=[],
        configurations=configurations,
        source_identifier="nvd",
        vuln_status="Analyzed",
        data_quality=CveDataQuality.COMPLETE,
    )


def _nvd_cve_payload():
    """Create a minimal NVD CVE payload."""

    return {
        "id": "CVE-2026-0001",
        "descriptions": [{"lang": "en", "value": "Description"}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"},
                }
            ]
        },
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                                "versionEndExcluding": "145.0.0.0",
                            }
                        ],
                    }
                ]
            }
        ],
    }


if __name__ == "__main__":
    unittest.main()
