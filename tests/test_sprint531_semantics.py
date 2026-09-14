"""Sprint 5.3.1 evidence-to-control-to-client regression fixtures."""

from __future__ import annotations

import copy
import unittest

from analysis_context import AnalysisContext
from collector_schema.compatibility import CollectorV1ToV2Adapter
from collector_schema.loader import _parse_setting
from csa_console.pipeline import ConsoleAnalysisPipeline
from csa_console.submission import SubmissionService
from csa_lab.unified_report import (
    UnifiedReportGenerator, _aggregate_cve, _bitlocker_detail,
    _executive_endpoint_metrics,
)
from evidence.bitlocker import resolve_bitlocker
from evidence.registry import WindowsEvidenceRegistry
from risk import Status
from rules.bitlocker import BitLockerRule
from software.models import SoftwareInventory
from tests.test_console_sprint5 import Sprint5TestCase


def bitlocker_setting(value: object, status: str = "SUCCESS") -> dict:
    return {
        "settingId": "BITLOCKER_OS_PROTECTION", "category": "Encryption",
        "configuredValue": value, "effectiveValue": value,
        "source": "RUNTIME_STATE", "collectionStatus": status,
        "confidence": 75, "collectedAt": "2026-09-14T08:00:00Z",
        "provider": "SHELL_VOLUME_BITLOCKER_PROPERTY",
        "metadata": {
            "volumeType": "OperatingSystem", "mountPoint": "C:",
            "protectionEnabled": value,
            "encryptionState": "FULLY_ENCRYPTED" if value is True else "FULLY_DECRYPTED" if value is False else "UNKNOWN",
            "rawEvidence": {"property": "System.Volume.BitLockerProtection", "value": 1 if value is True else 2 if value is False else None},
        },
    }


def build_semantics_fixture(case: Sprint5TestCase) -> UnifiedReportGenerator:
    """Accept and analyze three real package fixtures; add offline CVE results."""

    service = SubmissionService(case.storage)
    for label, value in (("ENABLED", True), ("DISABLED", False), ("UNKNOWN", None)):
        submission_id = f"SUB-531-{label}"
        evidence = case.evidence()
        evidence["device"]["hostname"] = f"DEMO-{label}"
        evidence["device"]["computerName"] = f"DEMO-{label}"
        evidence["security"]["settings"] = [
            item for item in evidence["security"]["settings"]
            if not item["settingId"].startswith("BITLOCKER_")
        ]
        if value is not None:
            evidence["security"]["settings"].append(bitlocker_setting(value))
        nonce = service.request_nonce(case.assessment.assessment_id, case.session.session_id, submission_id, case.token, "127.0.0.1")
        _, package, _ = service.accept(
            assessment_id=case.assessment.assessment_id, session_id=case.session.session_id,
            submission_id=submission_id, enrollment_token=case.token, nonce=nonce,
            source_address="127.0.0.1", archive_bytes=case.package(submission_id, nonce, evidence=evidence).read_bytes(),
        )
        ConsoleAnalysisPipeline(case.storage).analyze(package)
        analysis = case.storage.read_json(case.assessment.assessment_id, "findings", f"{submission_id}.json")
        products = []
        if label == "DISABLED":
            for index in range(85):
                products.append({
                    "productKey": f"demo|product-{index}|1.0", "displayName": f"Demo Software {index:02d}",
                    "displayVersion": "1.0", "publisher": "Demo", "normalizedVendor": "Demo",
                    "normalizedProduct": f"Demo Software {index:02d}", "normalizedVersion": "1.0",
                    "normalizationConfidence": 100, "lifecycleStatus": "SUPPORTED",
                    "cveEvaluationStatus": "NO_KNOWN_VULNERABILITIES" if index < 11 else "NOT_EVALUATED",
                    "cvePipeline": {"eligibilityStatus": "ELIGIBLE", "terminalStatus": "COMPLETED" if index < 11 else "NOT_EVALUATED"},
                    "cveDetails": [],
                })
        analysis["cveAnalysisStatus"] = "PARTIAL" if products else "COMPLETE"
        analysis["cveSummary"] = {
            "status": analysis["cveAnalysisStatus"], "softwareResults": products,
            "installedSoftwareRecords": len(products), "normalizedProducts": len(products),
            "cveEligibleProducts": len(products), "successfullyEvaluatedProducts": 11 if products else 0,
            "confirmedCveIds": [], "possibleCveIds": [],
        }
        case.storage.write_json(case.assessment.assessment_id, ("findings", f"{submission_id}.json"), analysis)
    return UnifiedReportGenerator(case.storage)


class BitLockerSemanticTests(unittest.TestCase):
    def test_typed_evidence_and_control_share_all_state_decisions(self):
        cases = [
            (True, "SUCCESS", "ENABLED", Status.PASS),
            (False, "SUCCESS", "NOT_ENABLED", Status.FAIL),
            (None, "SUCCESS", "NOT_EVALUATED", Status.NOT_EVALUATED),
            (False, "ACCESS_DENIED", "NOT_EVALUATED", Status.NOT_EVALUATED),
            (False, "PARTIAL", "NOT_EVALUATED", Status.NOT_EVALUATED),
            (None, "NOT_AVAILABLE", "NOT_EVALUATED", Status.NOT_EVALUATED),
            (None, "FAILED", "ERROR", Status.ERROR),
        ]
        cases += [(bad, "SUCCESS", "NOT_EVALUATED", Status.NOT_EVALUATED) for bad in (0, 1, "false", "true", [], {})]
        for value, collected, state, status in cases:
            with self.subTest(value=value, collection=collected):
                setting = bitlocker_setting(value, collected)
                original = copy.deepcopy(setting)
                conclusion = resolve_bitlocker(setting)
                context = AnalysisContext(raw_data={}, software_inventory=SoftwareInventory(), evidence_registry=WindowsEvidenceRegistry([_parse_setting(setting)]))
                finding = BitLockerRule().check({}, context)[0]
                detail = _bitlocker_detail({"diskEncryption": {"settings": [setting]}})
                self.assertEqual(conclusion["state"], state)
                self.assertEqual(finding.status, status)
                self.assertEqual(detail["status"], status.value)
                self.assertEqual(detail["displayLabel"], state.replace("_", " "))
                self.assertEqual(finding.score, 20 if status == Status.FAIL else 0)
                self.assertEqual(setting, original)

    def test_missing_or_non_system_volume_never_means_disabled(self):
        self.assertEqual(_bitlocker_detail({})["state"], "NOT_EVALUATED")
        setting = bitlocker_setting(False)
        setting["metadata"]["volumeType"] = "FixedData"
        self.assertEqual(resolve_bitlocker(setting)["state"], "NOT_EVALUATED")
        self.assertEqual(BitLockerRule().check({})[0].status, Status.NOT_EVALUATED)

    def test_structurally_unusable_evidence_remains_unknown(self):
        for section in (None, [], {"settings": None}, {"settings": [None, "bad", {}]}):
            self.assertEqual(_bitlocker_detail({"diskEncryption": section})["state"], "NOT_EVALUATED")

    def test_legacy_adapter_does_not_coerce_unknown_into_a_known_state(self):
        for value in (None, "false", 0, {}):
            doc = CollectorV1ToV2Adapter().convert({"Bitlocker-C": value})
            context = AnalysisContext(raw_data={}, software_inventory=SoftwareInventory(), evidence_registry=WindowsEvidenceRegistry(doc.security.settings))
            self.assertEqual(BitLockerRule().check({}, context)[0].status, Status.NOT_EVALUATED)

    def test_ten_endpoint_aggregation_keeps_unknown_and_errors_separate(self):
        endpoints = [{"bitLocker": {"status": status}} for status in ["PASS"] * 6 + ["FAIL"] * 2 + ["NOT_EVALUATED"] * 2]
        metrics = _executive_endpoint_metrics(endpoints)
        self.assertEqual(metrics["bitLockerEnabledEndpoints"], 6)
        self.assertEqual(metrics["bitLockerNotEnabledEndpoints"], 2)
        self.assertEqual(metrics["bitLockerNotEvaluatedEndpoints"], 2)
        endpoints.append({"bitLocker": {"status": "ERROR"}})
        self.assertEqual(_executive_endpoint_metrics(endpoints)["bitLockerErrorEndpoints"], 1)

    def test_confirmed_cves_remain_separate_from_partial_software_evaluation(self):
        cve = _aggregate_cve([{
            "displayName": "HOME", "cveAnalysisStatus": "PARTIAL",
            "softwareIntelligence": {"cveEligible": 85, "cveEvaluated": 11},
            "cveSummary": {"confirmedCveIds": [f"CVE-DEMO-{i}" for i in range(195)]},
        }])
        self.assertEqual(cve["confirmedUniqueCves"], 195)
        scope = cve["softwareVulnerabilityEvaluation"]
        self.assertEqual(scope["ratio"], "11 of 85 eligible software instances")
        self.assertEqual(scope["percent"], 12.9)
        self.assertEqual(scope["notFullyEvaluatedInstances"], 74)


class Sprint531ReportTests(Sprint5TestCase):
    def test_package_normalization_control_and_both_report_views(self):
        generator = build_semantics_fixture(self)
        model = generator.build_model(self.assessment.assessment_id)
        self.assertEqual(model["executiveEndpointMetrics"]["bitLockerEnabledEndpoints"], 1)
        self.assertEqual(model["executiveEndpointMetrics"]["bitLockerNotEnabledEndpoints"], 1)
        self.assertEqual(model["executiveEndpointMetrics"]["bitLockerNotEvaluatedEndpoints"], 1)
        html = generator.generate(self.assessment.assessment_id).read_text(encoding="utf-8")
        overview = html.split('id="comparison"', 1)[1].split('id="priority"', 1)[0]
        for endpoint in model["endpoints"]:
            label = endpoint["bitLocker"]["displayLabel"]
            status = endpoint["bitLocker"]["status"]
            normalized = self.storage.read_json(self.assessment.assessment_id, "normalized", endpoint["submissionId"] + ".json")
            self.assertEqual(normalized["diskEncryption"]["bitLocker"]["status"], status)
            findings = [item for item in endpoint["findings"] if item["finding"]["rule_id"] == "BIT-001"]
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["finding"]["status"], status)
            row = overview.split(f'data-endpoint="{endpoint["displayName"]}"', 1)[1].split('</tr>', 1)[0]
            self.assertIn(f'>{label}</span>', row)
            self.assertIn(f'class="status status-{status.lower()}" title="BitLocker: {label}"', row)
            details = html.split(f'id="{endpoint["anchorId"]}"', 1)[1].split('<h3>Assessment Limitations', 1)[0]
            self.assertIn(f'>{label}</span>', details)
        self.assertEqual(model["softwareVulnerabilityEvaluation"]["percent"], 12.9)
        self.assertIn("11 of 85 eligible software instances", html)
        self.assertIn("74 CVE-eligible software instances were not fully evaluated", html)
        self.assertIn("does not mean that those products are vulnerable", html)
        self.assertIn("does not represent the percentage of all CVEs discovered", html)
        self.assertIn('id="software-evaluation-help" tabindex="0"', html)
        self.assertIn('aria-describedby="software-evaluation-help"', html)
        self.assertNotIn("cve coverage", html.lower())


if __name__ == "__main__":
    unittest.main()
