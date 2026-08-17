"""Tests for the CVE Intelligence Engine."""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import date, datetime, timezone
from pathlib import Path
import gc
import json
import sqlite3
import warnings

from analysis_context import AnalysisContext
from analyzer import _cve_analysis_metadata, _product_evaluation_dict
from csa_console.canonical import canonical_json
from csa_console.serde import model_to_dict
from cve.applicability import evaluate_applicability
from cve.cache import NvdCache
from cve.cpe_resolver import (
    CpeResolver,
    build_cpe23,
    parse_cpe23_components,
    replace_cpe23_version,
)
from cve.exceptions import NvdRequestError
from cve.models import (
    ApplicabilityStatus,
    CpeCandidate,
    CpeMatchStatus,
    CveAssessment,
    CveDataQuality,
    CveRecord,
    CveScanSummary,
)
from cve.parser import parse_cve_record
from cve.rate_limiter import SlidingWindowRateLimiter
from cve.service import CveService, empty_summary
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

    def test_edge_uses_validated_chromium_cpe_mapping(self) -> None:
        """Microsoft Edge should not depend on ambiguous remote discovery."""

        software = SoftwareProduct(
            vendor="Microsoft Corporation",
            product="Microsoft Edge",
            version="151.0.4129.78",
            normalized_vendor="Microsoft",
            normalized_product="Microsoft Edge",
            normalized_version="151.0.4129.78",
            confidence=100,
        )

        candidate = CpeResolver(client=None).resolve(software)

        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate.confidence, 100)
        self.assertIn("microsoft:edge_chromium", candidate.cpe_name)

    def test_cpe_version_replacement_preserves_environment_components(
        self,
    ) -> None:
        """Installed versions should narrow CPEs without losing environment."""

        cpe = "cpe:2.3:a:vendor:product:*:stable:pro:en_us:*:windows:x64:*"

        self.assertEqual(
            replace_cpe23_version(cpe, "25.01.0"),
            "cpe:2.3:a:vendor:product:25.01.0:stable:pro:en_us:*:windows:x64:*",
        )
        self.assertIsNone(replace_cpe23_version("invalid", "25.01.0"))

    def test_unvalidated_local_mapping_caps_confidence(self) -> None:
        """Unvalidated local mappings should not produce automatic 100 confidence."""

        software = _software()
        with tempfile.TemporaryDirectory() as temp_dir:
            mapping_path = Path(temp_dir) / "mappings.json"
            mapping_path.write_text(
                json.dumps(
                    {
                        "google|google chrome": {
                            "part": "a",
                            "vendor": "google",
                            "product": "chrome",
                            "confidence": 100,
                        }
                    }
                ),
                encoding="utf-8",
            )
            candidate = CpeResolver(client=None, mapping_path=mapping_path).resolve(software)

        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate.confidence, 85)
        self.assertEqual(candidate.match_status, CpeMatchStatus.ALIAS)

    def test_cpe23_parser_handles_escaped_components(self) -> None:
        """CPE parser should split only on unescaped colons and unescape values."""

        parsed = parse_cpe23_components("cpe:2.3:a:vendor\\:name:product\\\\name:1\\.0:*:*:*:*:*:*:*")
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed.vendor, "vendor:name")
        self.assertEqual(parsed.product, "product\\name")
        self.assertEqual(parsed.version, "1.0")

        wildcard = parse_cpe23_components("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*")
        self.assertIsNotNone(wildcard)
        assert wildcard is not None
        self.assertEqual(wildcard.version, "*")

        na_value = parse_cpe23_components("cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*")
        self.assertIsNotNone(na_value)
        assert na_value is not None
        self.assertEqual(na_value.version, "-")

    def test_cpe23_parser_rejects_invalid_field_counts(self) -> None:
        """Invalid CPE names should return None instead of crashing."""

        self.assertIsNone(parse_cpe23_components("not-cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"))
        self.assertIsNone(parse_cpe23_components("cpe:2.3:a:vendor:product:*"))
        self.assertIsNone(parse_cpe23_components("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*:extra"))
        self.assertIsNone(parse_cpe23_components("cpe:2.3:a:vendor:product:\\"))

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

    def test_wildcard_cpe_without_range_is_not_a_possible_vulnerability(
        self,
    ) -> None:
        """Historical wildcard records need an affected-version range."""

        status, reason, _, _ = evaluate_applicability(
            _software(version="151.0.7922.138"),
            _cpe(),
            _cve_record(
                configurations=[
                    _configuration_for_criteria(
                        "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"
                    )
                ]
            ),
        )

        self.assertEqual(status, ApplicabilityStatus.NOT_EVALUATED)
        self.assertIn("affected-version range", reason)

    def test_applicability_respects_configuration_or(self) -> None:
        """A configuration-level OR may match any reliable vulnerable branch."""

        status, _, _, _ = evaluate_applicability(
            _software(),
            _cpe(),
            _cve_record(
                configurations=[
                    {
                        "operator": "OR",
                        "nodes": [
                            {
                                "operator": "OR",
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:other:product:*:*:*:*:*:*:*:*",
                                    }
                                ],
                            },
                            {
                                "operator": "OR",
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:google:chrome:144.0.7559.60:*:*:*:*:*:*:*",
                                    }
                                ],
                            },
                        ],
                    }
                ]
            ),
        )

        self.assertEqual(status, ApplicabilityStatus.AFFECTED)

    def test_applicability_and_partial_match_is_not_evaluated(self) -> None:
        """AND must not confirm affected from only one vulnerable product branch."""

        status, reason, _, _ = evaluate_applicability(
            _software(),
            _cpe(),
            _cve_record(
                configurations=[
                    {
                        "nodes": [
                            {
                                "operator": "AND",
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:google:chrome:144.0.7559.60:*:*:*:*:*:*:*",
                                    },
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*",
                                    },
                                ],
                            }
                        ]
                    }
                ]
            ),
        )

        self.assertEqual(status, ApplicabilityStatus.NOT_EVALUATED)
        self.assertIn("AND", reason)

    def test_applicability_vulnerable_false_is_not_whole_cve_not_affected(self) -> None:
        """A vulnerable=false entry should not mark the whole CVE safe."""

        status, reason, _, _ = evaluate_applicability(
            _software(),
            _cpe(),
            _cve_record(
                configurations=[
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*",
                                    }
                                ],
                            }
                        ]
                    }
                ]
            ),
        )

        self.assertEqual(status, ApplicabilityStatus.NOT_EVALUATED)
        self.assertIn("cannot be confirmed", reason)

    def test_applicability_nested_children_preserve_operator_semantics(self) -> None:
        """Nested children should be evaluated with their own operators."""

        status, reason, _, _ = evaluate_applicability(
            _software(),
            _cpe(),
            _cve_record(
                configurations=[
                    {
                        "nodes": [
                            {
                                "operator": "AND",
                                "children": [
                                    {
                                        "operator": "OR",
                                        "cpeMatch": [
                                            {
                                                "vulnerable": True,
                                                "criteria": "cpe:2.3:a:google:chrome:144.0.7559.60:*:*:*:*:*:*:*",
                                            }
                                        ],
                                    },
                                    {
                                        "operator": "OR",
                                        "cpeMatch": [
                                            {
                                                "vulnerable": False,
                                                "criteria": "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*",
                                            }
                                        ],
                                    },
                                ],
                            }
                        ]
                    }
                ]
            ),
        )

        self.assertEqual(status, ApplicabilityStatus.NOT_EVALUATED)
        self.assertIn("AND", reason)

    def test_applicability_target_sw_wildcard_does_not_require_collector_os(self) -> None:
        """Wildcard target_sw should not restrict applicability."""

        status, _, _, _ = evaluate_applicability(
            _software(),
            _cpe(),
            _cve_record(configurations=[_configuration_for_criteria("cpe:2.3:a:google:chrome:144.0.7559.60:*:*:*:*:*:*:*")]),
        )

        self.assertEqual(status, ApplicabilityStatus.AFFECTED)

    def test_applicability_target_sw_matches_collector_windows(self) -> None:
        """Windows target_sw should match trusted Windows collector OS data."""

        status, _, _, _ = evaluate_applicability(
            _software(),
            _cpe(),
            _cve_record(configurations=[_configuration_for_criteria("cpe:2.3:a:google:chrome:144.0.7559.60:*:*:*:*:windows:*:*")]),
            {"OS": "Microsoft Windows 11 Pro"},
        )

        self.assertEqual(status, ApplicabilityStatus.AFFECTED)

    def test_applicability_target_sw_mismatch_is_not_affected(self) -> None:
        """Linux target_sw should not match trusted Windows collector OS data."""

        status, _, _, _ = evaluate_applicability(
            _software(),
            _cpe(),
            _cve_record(configurations=[_configuration_for_criteria("cpe:2.3:a:google:chrome:144.0.7559.60:*:*:*:*:linux:*:*")]),
            {"OS": "Microsoft Windows 11 Pro"},
        )

        self.assertEqual(status, ApplicabilityStatus.NOT_AFFECTED)

    def test_applicability_target_sw_missing_collector_info_is_not_evaluated(self) -> None:
        """Specific target_sw without collector OS data should remain unevaluated."""

        status, reason, _, _ = evaluate_applicability(
            _software(),
            _cpe(),
            _cve_record(configurations=[_configuration_for_criteria("cpe:2.3:a:google:chrome:144.0.7559.60:*:*:*:*:windows:*:*")]),
        )

        self.assertEqual(status, ApplicabilityStatus.NOT_EVALUATED)
        self.assertIn("target_sw", reason)

    def test_applicability_target_hw_missing_collector_info_is_not_evaluated(self) -> None:
        """Specific target_hw without architecture data should remain unevaluated."""

        status, reason, _, _ = evaluate_applicability(
            _software(),
            _cpe(),
            _cve_record(configurations=[_configuration_for_criteria("cpe:2.3:a:google:chrome:144.0.7559.60:*:*:*:*:*:x64:*")]),
            {"OS": "Microsoft Windows 11 Pro"},
        )

        self.assertEqual(status, ApplicabilityStatus.NOT_EVALUATED)
        self.assertIn("target_hw", reason)

    def test_applicability_edition_mismatch_is_not_affected(self) -> None:
        """Specific edition mismatch should prevent affected status."""

        status, reason, _, _ = evaluate_applicability(
            _software(),
            _cpe(),
            _cve_record(configurations=[_configuration_for_criteria("cpe:2.3:a:google:chrome:144.0.7559.60:*:enterprise:*:*:*:*:*")]),
            {"Edition": "Professional"},
        )

        self.assertEqual(status, ApplicabilityStatus.NOT_AFFECTED)
        self.assertIn("edition", reason)

    def test_applicability_na_environment_component_is_not_wildcard(self) -> None:
        """NA environment components should require confirmation, not act as wildcard."""

        status, reason, _, _ = evaluate_applicability(
            _software(),
            _cpe(),
            _cve_record(configurations=[_configuration_for_criteria("cpe:2.3:a:google:chrome:144.0.7559.60:-:*:*:*:*:*:*")]),
            {"OS": "Microsoft Windows 11 Pro"},
        )

        self.assertEqual(status, ApplicabilityStatus.NOT_EVALUATED)
        self.assertIn("update", reason)

    def test_applicability_all_environment_conditions_match(self) -> None:
        """Matching environment components should allow version evaluation to continue."""

        status, _, _, _ = evaluate_applicability(
            _software(),
            _cpe(),
            _cve_record(configurations=[_configuration_for_criteria("cpe:2.3:a:google:chrome:144.0.7559.60:stable:pro:en_us:desktop:windows_11:x64:*")]),
            {
                "Update": "stable",
                "Edition": "Pro",
                "Language": "en-US",
                "SoftwareEdition": "Desktop",
                "OS": "Microsoft Windows 11 Pro",
                "Architecture": "AMD64",
            },
        )

        self.assertEqual(status, ApplicabilityStatus.AFFECTED)

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

    def test_parser_prefers_primary_highest_cvss_family(self) -> None:
        """Parser should prefer CVSS 4.0 and primary metrics when available."""

        record = parse_cve_record(
            {
                "id": "CVE-2026-0003",
                "descriptions": [{"lang": "et", "value": "Kirjeldus"}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "type": "Primary",
                            "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"},
                        }
                    ],
                    "cvssMetricV40": [
                        {
                            "type": "Secondary",
                            "cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"},
                        },
                        {
                            "type": "Primary",
                            "cvssData": {"baseScore": 9.1, "baseSeverity": "CRITICAL"},
                        },
                    ],
                },
                "configurations": [{"nodes": []}],
                "weaknesses": [],
                "references": [],
            }
        )

        self.assertEqual(record.cvss_version, "4.0")
        self.assertEqual(record.cvss_score, 9.1)
        self.assertEqual(record.severity, "CRITICAL")
        self.assertEqual(record.description, "Kirjeldus")
        self.assertEqual(record.data_quality, CveDataQuality.PARTIAL)

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

    def test_cache_closes_connections_and_ignores_corrupt_json(self) -> None:
        """Cache operations should not leak SQLite connections."""

        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / "cache.sqlite3"
            with warnings.catch_warnings(record=True) as captured:
                warnings.simplefilter("always", ResourceWarning)
                cache = NvdCache(cache_path)
                key = cache.make_key("endpoint", {"a": 1})
                cache.set(key, "endpoint", {"a": 1}, {"ok": True}, ttl_hours=1)
                self.assertEqual(cache.get(key), {"ok": True})
                connection = sqlite3.connect(cache_path)
                try:
                    connection.execute(
                        "UPDATE nvd_cache SET response_json = ? WHERE cache_key = ?",
                        ("{broken", key),
                    )
                    connection.commit()
                finally:
                    connection.close()
                self.assertIsNone(cache.get(key))
                del cache
                gc.collect()

        self.assertFalse([warning for warning in captured if issubclass(warning.category, ResourceWarning)])

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
        self.assertEqual(summary.eligible_products, 1)
        self.assertEqual(summary.evaluated_products, 1)
        self.assertEqual(summary.coverage_percent, 100.0)
        self.assertEqual(summary.confirmed_vulnerabilities, 1)

    def test_service_queries_nvd_with_the_exact_installed_version(
        self,
    ) -> None:
        """A mapped product CPE should be narrowed to the installed version."""

        queries = []
        progress = []

        class Client:
            def get_cves(self, params):
                queries.append(params)
                return []

        class Resolver:
            def resolve(self, software):
                return _cpe()

        summary = CveService(
            client=Client(), resolver=Resolver()
        ).scan_inventory(
            SoftwareInventory(products=[_software()], product_count=1),
            progress_callback=progress.append,
        )

        self.assertEqual(
            queries,
            [
                {
                    "cpeName": (
                        "cpe:2.3:a:google:chrome:144.0.7559.60:"
                        "*:*:*:*:*:*:*"
                    )
                }
            ],
        )
        evaluation = summary.product_evaluations[0]
        self.assertEqual(evaluation.product_mapping_status, "SUCCESS")
        self.assertEqual(evaluation.provider_query_status, "SUCCESS")
        self.assertEqual(evaluation.version_evaluation_status, "SUCCESS")
        self.assertEqual(
            evaluation.cve_result_status,
            "NO_KNOWN_VULNERABILITIES",
        )
        self.assertIn(
            "QUERYING_PROVIDER",
            {item["phase"] for item in progress},
        )

    def test_console_serializers_support_cve_provider_dates(self) -> None:
        """KEV dates must remain JSON-safe when endpoint results are saved."""

        value = {
            "date": date(2026, 8, 14),
            "timestamp": datetime(2026, 8, 14, 10, 30, tzinfo=timezone.utc),
        }

        self.assertEqual(
            json.loads(canonical_json(value)),
            {
                "date": "2026-08-14",
                "timestamp": "2026-08-14T10:30:00+00:00",
            },
        )
        self.assertEqual(
            model_to_dict(value),
            {
                "date": "2026-08-14",
                "timestamp": "2026-08-14T10:30:00+00:00",
            },
        )

    def test_service_reports_incomplete_coverage(self) -> None:
        """Products without a usable CPE should reduce CVE coverage."""

        class Client:
            def get_cves(self, params):
                return []

        class Resolver:
            def resolve(self, software):
                return None

        inventory = SoftwareInventory(products=[_software()], product_count=1)
        summary = CveService(client=Client(), resolver=Resolver()).scan_inventory(inventory)
        self.assertEqual(summary.eligible_products, 1)
        self.assertEqual(summary.evaluated_products, 0)
        self.assertEqual(summary.coverage_percent, 0.0)
        self.assertFalse(summary.coverage_complete)
        evaluation = summary.product_evaluations[0]
        self.assertEqual(evaluation.provider, "NVD")
        self.assertEqual(evaluation.terminal_status, "NOT_EVALUATED")
        self.assertEqual(evaluation.failure_stage, "PRODUCT_MAPPING")
        self.assertFalse(evaluation.retryable)
        self.assertTrue(evaluation.failure_reason)
        serialized = _product_evaluation_dict(evaluation)
        self.assertEqual(serialized["provider"], "NVD")
        self.assertEqual(serialized["terminalStatus"], "NOT_EVALUATED")
        self.assertEqual(serialized["failureStage"], "PRODUCT_MAPPING")
        self.assertTrue(serialized["failureReason"])
        self.assertFalse(serialized["retryable"])

    def test_provider_failure_has_auditable_retryable_terminal_state(
        self,
    ) -> None:
        """Provider failures must preserve stage, safe reason, and retryability."""

        class Client:
            def get_cves(self, params):
                raise NvdRequestError(
                    "safe",
                    retryable=True,
                    status_code=429,
                    endpoint_label="CVES",
                )

        class Resolver:
            def resolve(self, software):
                return _cpe()

        summary = CveService(
            client=Client(), resolver=Resolver()
        ).scan_inventory(
            SoftwareInventory(products=[_software()], product_count=1)
        )
        evaluation = summary.product_evaluations[0]

        self.assertEqual(evaluation.provider, "NVD")
        self.assertEqual(evaluation.provider_query_status, "FAILED")
        self.assertEqual(evaluation.terminal_status, "FAILED")
        self.assertEqual(evaluation.failure_stage, "PROVIDER_QUERY")
        self.assertEqual(evaluation.failure_reason, "NVD CVES HTTP 429")
        self.assertTrue(evaluation.retryable)

    def test_vendor_only_normalization_is_not_cve_eligible(self) -> None:
        """Vendor-only confidence must not trigger unreliable CPE queries."""

        class Client:
            def get_cves(self, params):
                raise AssertionError("CVE provider must not be queried")

        software = _software()
        software.confidence = 60
        summary = CveService(client=Client()).scan_inventory(
            SoftwareInventory(products=[software], product_count=1)
        )

        self.assertEqual(summary.eligible_products, 0)
        evaluation = summary.product_evaluations[0]
        self.assertEqual(evaluation.eligibility_status, "NOT_ELIGIBLE")
        self.assertIn("confidence", evaluation.provider_reason.lower())

    def test_empty_summary_for_skipped_or_failed_scan_has_no_coverage(self) -> None:
        """Skipped or fatal CVE scans should not claim complete coverage."""

        skipped = empty_summary(scan_complete=False)
        failed = empty_summary(scan_complete=False, message="fatal")
        incomplete = empty_summary(scan_complete=False, message="interrupted")

        for summary in (skipped, failed, incomplete):
            self.assertEqual(summary.coverage_percent, 0.0)
            self.assertFalse(summary.coverage_complete)
            self.assertFalse(summary.scan_complete)

    def test_empty_successful_inventory_has_complete_coverage(self) -> None:
        """An empty inventory can be fully covered when the scan ran successfully."""

        class Client:
            def get_cves(self, params):
                return []

        class Resolver:
            def resolve(self, software):
                return None

        summary = CveService(client=Client(), resolver=Resolver()).scan_inventory(SoftwareInventory())

        self.assertEqual(summary.coverage_percent, 100.0)
        self.assertTrue(summary.coverage_complete)
        self.assertTrue(summary.scan_complete)

    def test_product_scan_error_marks_coverage_incomplete(self) -> None:
        """Product-level fatal scan errors should reduce coverage."""

        class Client:
            def get_cves(self, params):
                return []

        class Resolver:
            def resolve(self, software):
                raise RuntimeError("boom")

        summary = CveService(client=Client(), resolver=Resolver()).scan_inventory(
            SoftwareInventory(products=[_software()], product_count=1)
        )

        self.assertEqual(summary.coverage_percent, 0.0)
        self.assertFalse(summary.coverage_complete)
        self.assertFalse(summary.scan_complete)

    def test_report_metrics_exclude_not_affected_cves_from_risk_counts(
        self,
    ) -> None:
        """Risk counts should include only confirmed or possible CVEs."""

        base = _cve_record([])
        assessments = [
            CveAssessment(
                software=_software(),
                cpe=_cpe(),
                cve=replace(
                    base,
                    cve_id="CVE-2026-0001",
                    severity="HIGH",
                ),
                applicability=ApplicabilityStatus.AFFECTED,
                reason="affected",
                confidence=100,
            ),
            CveAssessment(
                software=_software(),
                cpe=_cpe(),
                cve=replace(
                    base,
                    cve_id="CVE-2026-0002",
                    severity="MEDIUM",
                ),
                applicability=ApplicabilityStatus.POSSIBLY_AFFECTED,
                reason="possible",
                confidence=70,
            ),
            CveAssessment(
                software=_software(),
                cpe=_cpe(),
                cve=replace(
                    base,
                    cve_id="CVE-2026-0003",
                    severity="CRITICAL",
                ),
                applicability=ApplicabilityStatus.NOT_AFFECTED,
                reason="not affected",
                confidence=100,
            ),
        ]
        summary = CveScanSummary(
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
            possible_vulnerabilities=1,
            not_evaluated=0,
            api_errors=0,
            assessments=assessments,
            errors=[],
            scan_complete=True,
        )
        context = AnalysisContext(
            raw_data={},
            software_inventory=SoftwareInventory(
                products=[_software()],
                product_count=1,
            ),
            cve_summary=summary,
        )

        metrics = _cve_analysis_metadata(context)

        self.assertEqual(metrics["uniqueCves"], 2)
        self.assertEqual(metrics["confirmedUniqueCves"], 1)
        self.assertEqual(metrics["possibleUniqueCves"], 1)
        self.assertEqual(metrics["criticalUniqueCves"], 0)
        self.assertEqual(metrics["highUniqueCves"], 1)
        self.assertEqual(metrics["providerCoverage"][0]["provider"], "NVD")
        self.assertEqual(
            metrics["providerCoverage"][0]["recordsLoaded"],
            3,
        )

    def test_cve_rule_states(self) -> None:
        """CVE rule should represent not-run, clean, and affected summaries."""

        rule = KnownVulnerabilitiesRule()
        not_run = rule.check({}, None)[0]
        self.assertEqual(not_run.status.value, "NOT_EVALUATED")
        self.assertEqual(
            not_run.evidence["analysis_status"], "NOT_PERFORMED"
        )

        clean = CveScanSummary(
            scanned_products=0,
            unique_products=0,
            eligible_products=0,
            evaluated_products=0,
            coverage_percent=100.0,
            coverage_complete=True,
            products_with_cpe=0,
            products_without_cpe=0,
            ambiguous_cpe_matches=0,
            confirmed_vulnerabilities=0,
            possible_vulnerabilities=0,
            not_evaluated=0,
            api_errors=0,
            assessments=[],
            errors=[],
            scan_complete=True,
        )
        context = type("Context", (), {"cve_summary": clean})()
        clean_finding = rule.check({}, context)[0]
        self.assertEqual(clean_finding.status.value, "PASS")

        incomplete = replace(
            clean,
            scanned_products=9,
            unique_products=9,
            eligible_products=9,
            evaluated_products=0,
            coverage_percent=0.0,
            coverage_complete=False,
            products_without_cpe=9,
            api_errors=1,
            scan_complete=False,
        )
        incomplete_context = type(
            "Context", (), {"cve_summary": incomplete}
        )()
        incomplete_finding = rule.check({}, incomplete_context)[0]
        self.assertEqual(
            incomplete_finding.status.value,
            "NOT_EVALUATED",
        )
        self.assertEqual(incomplete_finding.score, 0)


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


def _configuration_for_criteria(criteria: str) -> dict:
    """Create a simple OR configuration for one CPE criteria string."""

    return {
        "nodes": [
            {
                "operator": "OR",
                "cpeMatch": [
                    {
                        "vulnerable": True,
                        "criteria": criteria,
                    }
                ],
            }
        ]
    }


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
