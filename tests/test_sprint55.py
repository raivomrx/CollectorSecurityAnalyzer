"""Sprint 5.5 software identity and intelligence quality regressions."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from csa_lab.unified_report import (
    UnifiedReportGenerator,
    _aggregate_software_intelligence,
    _priority_actions,
    _reconcile_malware_inventory,
    _remediation_plan,
    _software_intelligence_coverage,
    _software_security_findings,
)
from csa_console.pipeline import ConsoleAnalysisPipeline
from csa_console.submission import SubmissionService
from cve.cache import CPE_CATALOG_SCHEMA_VERSION, NvdCache
from cve.models import CveTerminalReason
from cve.service import CveService
from software.models import SoftwareInventory, SoftwareProduct
from software.normalizer import normalize_product, normalize_software
from tests.test_console_sprint5 import Sprint5TestCase


def _product(name: str, version: str, vendor: str = "Example Vendor") -> SoftwareProduct:
    """Create a synthetic software product without writing a fixture."""

    return SoftwareProduct(
        vendor=vendor,
        product=name,
        version=version,
        normalized_vendor=vendor,
        normalized_product=name,
        normalized_version=version,
        confidence=60,
        normalization_status="PARTIAL",
        discovery_eligible=False,
    )


def _software_result(
    name: str,
    version: str,
    terminal: str,
    reason: str,
    *,
    eligible: bool = True,
) -> dict:
    """Create one synthetic report-facing product result."""

    return {
        "productKey": f"example|{name}|{version}",
        "displayName": name,
        "displayVersion": version,
        "publisher": "Example Vendor",
        "architecture": "x64",
        "normalizedVendor": "Example Vendor",
        "normalizedProduct": name,
        "normalizedVersion": version,
        "normalizationConfidence": 95,
        "cvePipeline": {
            "eligibilityStatus": "ELIGIBLE" if eligible else "NOT_ELIGIBLE",
            "productMappingStatus": "SUCCESS" if terminal == "COMPLETED" else "NO_RELIABLE_MAPPING",
            "terminalStatus": terminal,
            "terminalReasonCode": reason,
            "retryable": reason in {"PROVIDER_ERROR", "PROVIDER_RATE_LIMIT"},
        },
        "cveDetails": [],
        "confirmedCves": 0,
    }


class ProductIdentityTests(unittest.TestCase):
    """Keep materially different product identities separate."""

    def test_visual_cpp_generations_never_cross_normalize(self) -> None:
        generations = (
            ("2012", "11.0.61030"),
            ("2013", "12.0.40664"),
            ("2015", "14.0.24215"),
            ("2017", "14.16.27033"),
            ("2019", "14.29.30153"),
            ("2022", "14.40.33810"),
            ("2015-2022", "14.40.33810"),
        )
        identities = set()
        for generation, version in generations:
            for architecture in ("x86", "x64"):
                name = (
                    f"Microsoft Visual C++ {generation} {architecture} "
                    "Additional Runtime"
                )
                with self.subTest(name=name):
                    result = normalize_product(name, version=version)
                    self.assertEqual(
                        result.value,
                        f"Microsoft Visual C++ {generation} Redistributable",
                    )
                    self.assertGreaterEqual(result.confidence, 95)
                    self.assertFalse(result.trace["guardrailRejections"])
                    identities.add(result.value)
        self.assertEqual(len(identities), 7)

    def test_visual_cpp_version_mismatch_is_rejected_and_auditable(self) -> None:
        result = normalize_product(
            "Microsoft Visual C++ 2012 x64 Redistributable",
            version="14.40.33810",
        )
        self.assertEqual(result.confidence, 0)
        self.assertEqual(result.reason, "identity_guard_rejected")
        self.assertIn("expects version family 11.x", result.trace["guardrailRejections"][0])

    def test_component_roles_do_not_collapse_into_parent_products(self) -> None:
        edge = normalize_product("Microsoft Edge", version="140.0")
        webview = normalize_product("Microsoft Edge WebView2 Runtime", version="140.0")
        ccleaner = normalize_product("CCleaner", version="7.0")
        helper = normalize_product("CCleaner Update Helper", version="7.0")
        teams = normalize_product("Microsoft Teams", version="2.0")
        addin = normalize_product("Microsoft Teams Meeting Add-in", version="2.0")

        self.assertNotEqual(edge.value, webview.value)
        self.assertNotEqual(ccleaner.value, helper.value)
        self.assertNotEqual(teams.value, addin.value)
        self.assertEqual(helper.confidence, 0)
        self.assertEqual(addin.confidence, 0)
        self.assertTrue(helper.trace["guardrailRejections"])

    def test_malwarebytes_is_identified_without_inventing_cpe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            software = normalize_software(
                "Malwarebytes",
                "Malwarebytes version 5.7.0.328",
                "5.7.0.328",
                unknown_products_path=Path(temporary) / "unknown.json",
            )
        self.assertEqual(software.normalized_product, "Malwarebytes")
        self.assertGreaterEqual(software.confidence, 95)
        self.assertIsNone(software.cpe)


class CpeCatalogTests(unittest.TestCase):
    """Validate versioned local CPE intelligence lifecycle semantics."""

    def test_catalog_records_provenance_and_does_not_serve_stale_as_fresh(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache = NvdCache(Path(temporary) / "cache.sqlite3")
            identity = "example|product|query"
            cache.set_cpe_catalog(
                identity,
                [{"cpe": {"cpeName": "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*"}}],
                source="SYNTHETIC_TEST_CATALOG",
                source_version="2026.09",
            )
            record = cache.get_cpe_catalog_record(identity)
            self.assertEqual(record["schemaVersion"], CPE_CATALOG_SCHEMA_VERSION)
            self.assertEqual(record["state"], "FRESH")
            self.assertEqual(record["source"], "SYNTHETIC_TEST_CATALOG")
            self.assertFalse(record["negative"])

            expired = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
            with cache._connect() as connection:
                connection.execute(
                    "UPDATE cpe_catalog_v2 SET expires_at = ? WHERE identity = ?",
                    (expired, identity),
                )
            self.assertEqual(cache.get_cpe_catalog_record(identity)["state"], "STALE")
            self.assertIsNone(cache.get_cpe_catalog(identity))

    def test_negative_catalog_entry_has_bounded_ttl_and_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache = NvdCache(Path(temporary) / "negative.sqlite3")
            cache.set_cpe_catalog("example|unknown|query", [])
            record = cache.get_cpe_catalog_record("example|unknown|query")
            self.assertTrue(record["negative"])
            self.assertEqual(record["state"], "FRESH")
            created = datetime.fromisoformat(record["createdAt"])
            expires = datetime.fromisoformat(record["expiresAt"])
            self.assertLessEqual(expires - created, timedelta(hours=72, seconds=1))


class TerminalReasonAndCoverageTests(unittest.TestCase):
    """Expose deterministic final states and consistent counting units."""

    def test_unsupported_component_gets_terminal_reason(self) -> None:
        product = _product("Example Update Helper", "1.0")
        summary = CveService(client=object(), resolver=object()).scan_inventory(
            SoftwareInventory(products=[product])
        )
        evaluation = summary.product_evaluations[0]
        self.assertEqual(evaluation.terminal_status, "NOT_ELIGIBLE")
        self.assertEqual(
            evaluation.terminal_reason_code,
            CveTerminalReason.UNSUPPORTED_COMPONENT.value,
        )

    def test_coverage_denominators_and_fleet_worklist_are_consistent(self) -> None:
        products = [
            _software_result("Mapped Product", "1.0", "COMPLETED", "EVALUATION_COMPLETED"),
            _software_result("Ambiguous Product", "2.0", "NOT_EVALUATED", "AMBIGUOUS_IDENTITY"),
            _software_result("Provider Product", "3.0", "FAILED", "PROVIDER_RATE_LIMIT"),
            _software_result("Helper Component", "4.0", "NOT_ELIGIBLE", "UNSUPPORTED_COMPONENT", eligible=False),
        ]
        coverage = _software_intelligence_coverage(products)
        self.assertEqual(coverage["endpointProductInstances"], 4)
        self.assertEqual(coverage["cveEligible"], 3)
        self.assertEqual(coverage["cveEvaluated"], 1)
        self.assertEqual(coverage["cveEligibleNotEvaluated"], 1)
        self.assertEqual(coverage["cveEligibleFailed"], 1)
        self.assertEqual(coverage["nonEligibleOrUnsupported"], 1)
        self.assertLessEqual(
            coverage["cveEvaluated"],
            coverage["identifiedForSecurityAnalysis"],
        )

        endpoints = [
            {"displayName": "LAB-A", "softwareResults": products},
            {"displayName": "LAB-B", "softwareResults": products},
        ]
        aggregate = _aggregate_software_intelligence(endpoints)
        ambiguous = next(
            row for row in aggregate["terminalReasonWorklist"]
            if row["reasonCode"] == "AMBIGUOUS_IDENTITY"
        )
        self.assertEqual(ambiguous["endpointCount"], 2)

    def test_fully_evaluated_never_exceeds_reliably_identified(self) -> None:
        completed = _software_result(
            "Completed Product", "1.0", "COMPLETED", "EVALUATION_COMPLETED"
        )
        identified_only = _software_result(
            "Identified Product", "2.0", "NOT_EVALUATED",
            "APPLICABILITY_INCOMPLETE",
        )
        identified_only["cvePipeline"]["productMappingStatus"] = "SUCCESS"
        coverage = _software_intelligence_coverage(
            [completed, identified_only]
        )
        self.assertEqual(coverage["identifiedForSecurityAnalysis"], 2)
        self.assertEqual(coverage["cveEvaluated"], 1)
        self.assertLessEqual(
            coverage["cveEvaluated"],
            coverage["identifiedForSecurityAnalysis"],
        )


class KevAndAvReportingTests(unittest.TestCase):
    """Keep exploit priority and AV inventory semantics explicit."""

    def test_confirmed_kev_remediation_is_never_demoted_below_p1(self) -> None:
        endpoints = [{
            "submissionId": "SUB-SYNTHETIC-01",
            "displayName": "LAB-ENDPOINT",
            "anchorId": "endpoint-lab",
            "softwareResults": [{
                "productKey": "example|editor|1.0",
                "displayName": "Example Editor",
                "displayVersion": "1.0",
                "normalizedVendor": "Example Vendor",
                "normalizedProduct": "Example Editor",
                "cveDetails": [{
                    "cveId": "CVE-2099-0001",
                    "matchStatus": "AFFECTED",
                    "severity": "MEDIUM",
                    "cvssScore": 6.5,
                    "cisaKev": True,
                    "vendorAdvisoryUrls": ["https://example.invalid/advisory/1"],
                }],
            }],
        }]
        findings = _software_security_findings(endpoints)
        actions = _priority_actions(endpoints, findings)
        plan = _remediation_plan(actions, findings)
        self.assertEqual(plan[0]["priority"], "P1")
        self.assertIn("CISA KEV", plan[0]["priorityBasis"])
        self.assertEqual(plan[0]["riskReduction"], "Medium")

    def test_seven_distinct_kev_actions_remain_p1_in_complete_plan(self) -> None:
        endpoint = {
            "submissionId": "SUB-SYNTHETIC-KEV-SEVEN",
            "displayName": "LAB-ENDPOINT",
            "anchorId": "endpoint-lab",
            "softwareResults": [],
        }
        for index in range(1, 8):
            endpoint["softwareResults"].append({
                "productKey": f"example|product-{index}|1.0",
                "displayName": f"Example Product {index}",
                "displayVersion": "1.0",
                "normalizedVendor": "Example Vendor",
                "normalizedProduct": f"Example Product {index}",
                "cveDetails": [{
                    "cveId": f"CVE-2099-{index:04d}",
                    "matchStatus": "AFFECTED",
                    "severity": "HIGH",
                    "cvssScore": 8.0,
                    "cisaKev": True,
                }],
            })
        findings = _software_security_findings([endpoint])
        actions = _priority_actions([endpoint], findings)
        self.assertEqual(len(actions), 5)
        plan = _remediation_plan(actions, findings)
        self.assertEqual(len(plan), 7)
        self.assertTrue(all(item["priority"] == "P1" for item in plan))
        self.assertTrue(all(
            "CISA KEV" in item["priorityBasis"] for item in plan
        ))

    def test_installed_security_product_is_not_invented_as_active_av(self) -> None:
        posture = {
            "status": "PASS",
            "active_product": "Microsoft Defender Antivirus",
            "registered_products": [{
                "name": "Microsoft Defender Antivirus",
                "role": "PRIMARY",
                "protectionStatus": "ENABLED",
            }],
        }
        software = [
            {"normalizedProduct": "Microsoft Defender Antivirus", "displayVersion": "4.18", "publisher": "Microsoft"},
            {"normalizedProduct": "Malwarebytes", "displayVersion": "5.7.0.328", "publisher": "Malwarebytes"},
        ]
        result = _reconcile_malware_inventory(posture, software)
        installed = {item["name"]: item for item in result["installed_security_products"]}
        self.assertEqual(installed["Microsoft Defender Antivirus"]["correlationStatus"], "REGISTERED")
        self.assertEqual(installed["Malwarebytes"]["correlationStatus"], "INSTALLED_NOT_REGISTERED")
        self.assertEqual(installed["Malwarebytes"]["role"], "ROLE_UNKNOWN")
        self.assertEqual(installed["Malwarebytes"]["protectionState"], "NOT_EVALUATED")
        self.assertEqual(result["active_product"], "Microsoft Defender Antivirus")

    def test_browser_guard_does_not_inherit_malwarebytes_av_health(self) -> None:
        posture = {
            "status": "PASS",
            "active_product": "Malwarebytes Antivirus",
            "registered_products": [{
                "name": "Malwarebytes Antivirus",
                "role": "PRIMARY",
                "protectionStatus": "ENABLED",
            }],
        }
        result = _reconcile_malware_inventory(posture, [{
            "normalizedProduct": "Malwarebytes Browser Guard",
            "displayVersion": "3.0",
            "publisher": "Malwarebytes",
        }])
        installed = result["installed_security_products"][0]
        self.assertEqual(installed["correlationStatus"], "INSTALLED_NOT_REGISTERED")
        self.assertEqual(installed["role"], "ROLE_UNKNOWN")
        self.assertEqual(installed["protectionState"], "NOT_EVALUATED")
        self.assertEqual(
            result["registered_products"][0]["inventoryCorrelationStatus"],
            "REGISTERED_NOT_IN_INVENTORY",
        )

    def test_defender_for_endpoint_does_not_inherit_antivirus_health(self) -> None:
        posture = {
            "status": "PASS",
            "active_product": "Microsoft Defender Antivirus",
            "registered_products": [{
                "name": "Microsoft Defender Antivirus",
                "role": "PRIMARY",
                "protectionStatus": "ENABLED",
            }],
        }
        result = _reconcile_malware_inventory(posture, [{
            "normalizedProduct": "Microsoft Defender for Endpoint",
            "displayVersion": "10.0",
            "publisher": "Microsoft",
        }])
        installed = result["installed_security_products"][0]
        self.assertEqual(installed["correlationStatus"], "INSTALLED_NOT_REGISTERED")
        self.assertEqual(installed["role"], "ROLE_UNKNOWN")
        self.assertEqual(installed["protectionState"], "NOT_EVALUATED")


class UnifiedKevReportTests(Sprint5TestCase):
    """Carry confirmed KEV priority through persisted unified reporting."""

    def test_full_report_preserves_confirmed_kev_as_p1_work_item(self) -> None:
        service = SubmissionService(self.storage)
        submission_id = "SUB-55-KEV-SYNTHETIC"
        nonce = service.request_nonce(
            self.assessment.assessment_id,
            self.session.session_id,
            submission_id,
            self.token,
            "127.0.0.1",
        )
        _, package, _ = service.accept(
            assessment_id=self.assessment.assessment_id,
            session_id=self.session.session_id,
            submission_id=submission_id,
            enrollment_token=self.token,
            nonce=nonce,
            source_address="127.0.0.1",
            archive_bytes=self.package(submission_id, nonce).read_bytes(),
        )
        ConsoleAnalysisPipeline(self.storage).analyze(package)
        analysis = self.storage.read_json(
            self.assessment.assessment_id,
            "findings",
            f"{submission_id}.json",
        )
        analysis["cveAnalysisStatus"] = "COMPLETE"
        analysis["cveSummary"] = {
            "status": "COMPLETE",
            "installedSoftwareRecords": 1,
            "normalizedProducts": 1,
            "cveEligibleProducts": 1,
            "successfullyEvaluatedProducts": 1,
            "confirmedCveIds": ["CVE-2099-0001"],
            "possibleCveIds": [],
            "softwareResults": [{
                "productKey": "example|editor|1.0",
                "displayName": "Example Editor",
                "displayVersion": "1.0",
                "publisher": "Example Vendor",
                "normalizedVendor": "Example Vendor",
                "normalizedProduct": "Example Editor",
                "normalizedVersion": "1.0",
                "normalizationConfidence": 95,
                "cveEvaluationStatus": "CONFIRMED",
                "confirmedCves": 1,
                "possibleCves": 0,
                "lifecycleStatus": "SUPPORTED",
                "cvePipeline": {
                    "eligibilityStatus": "ELIGIBLE",
                    "productMappingStatus": "SUCCESS",
                    "terminalStatus": "COMPLETED",
                    "terminalReasonCode": "EVALUATION_COMPLETED",
                },
                "cveDetails": [{
                    "cveId": "CVE-2099-0001",
                    "matchStatus": "AFFECTED",
                    "severity": "MEDIUM",
                    "cvssScore": 6.5,
                    "cisaKev": True,
                    "vendorAdvisoryUrls": [
                        "https://example.invalid/advisory/1"
                    ],
                }],
            }],
        }
        self.storage.write_json(
            self.assessment.assessment_id,
            ("findings", f"{submission_id}.json"),
            analysis,
        )

        report = UnifiedReportGenerator(self.storage)
        model = report.build_model(self.assessment.assessment_id)
        kev_action = next(
            item for item in model["remediationPlan"]
            if "Example Editor" in item["action"]
        )
        self.assertEqual(kev_action["priority"], "P1")
        self.assertIn("CISA KEV", kev_action["priorityBasis"])
        html = report.generate(
            self.assessment.assessment_id
        ).read_text(encoding="utf-8")
        self.assertIn("Confirmed affected CVE is listed in CISA KEV", html)
        self.assertIn("Example Editor", html)


if __name__ == "__main__":
    unittest.main()
