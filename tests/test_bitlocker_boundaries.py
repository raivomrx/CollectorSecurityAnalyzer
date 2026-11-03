"""Synthetic OS-volume observations through the actual submission pipeline."""
from pathlib import Path
import unittest

from analysis_context import AnalysisContext
from compliance.enums import EvidenceResult
from compliance.evidence.finding_evidence import FindingEvidenceExtractor
from compliance.loader import load_framework
from csa_console.pipeline import ConsoleAnalysisPipeline
from csa_console.submission import SubmissionService
from csa_lab.unified_report import UnifiedReportGenerator
from evidence.bitlocker import resolve_bitlocker
from knowledge.repository import KnowledgeRepository
from risk import AuditFinding, Finding
from software.models import SoftwareInventory
from tests.test_console_sprint5 import Sprint5TestCase
from tests.test_sprint531_semantics import bitlocker_setting


def shell_setting(value, read_status="SUCCESS"):
    setting = bitlocker_setting(None, "PARTIAL")
    setting["provider"] = "SHELL_VOLUME_BITLOCKER_PROPERTY"
    setting["metadata"] = {
        "volumeType": "OperatingSystem",
        "mountPoint": "C:",
        "shellRawValue": value,
        "shellReadStatus": read_status,
        "observedAt": "2026-11-03T08:00:00Z",
    }
    return setting


class BitLockerBoundaryTests(unittest.TestCase):
    def test_old_shell_percent_is_not_measured_evidence(self):
        for raw, expected in ((0, "NOT_EVALUATED"), (1, "PROTECTION_ON_INDICATED"), (2, "PROTECTION_OFF_INDICATED")):
            setting = shell_setting(raw)
            del setting["metadata"]["shellReadStatus"]
            setting["metadata"].update(encryptionPercentage=100, encryptionState="FULLY_ENCRYPTED")
            result = resolve_bitlocker(setting)
            self.assertEqual(result["state"], expected)
            self.assertIsNone(result["encryptionPercentage"])
            self.assertEqual(result["encryptionState"], "UNKNOWN")

    def test_shell_heuristic_and_transitions_remain_indications(self):
        for value, read, state, interpretation in (
            (0, "SUCCESS", "PROTECTION_OFF_INDICATED", "FIELD_HEURISTIC"),
            (2, "SUCCESS", "PROTECTION_OFF_INDICATED", "SHELL_ENUM"),
            (3, "SUCCESS", "SHELL_TRANSITIONING", "SHELL_ENUM"),
            (4, "SUCCESS", "SHELL_TRANSITIONING", "SHELL_ENUM"),
            (5, "SUCCESS", "SHELL_SUSPENDED", "SHELL_ENUM"),
            (6, "SUCCESS", "SHELL_LOCKED", "SHELL_ENUM"),
            (7, "SUCCESS", "NOT_EVALUATED", None),
            (None, "UNAVAILABLE", "NOT_EVALUATED", None),
            ("0", "SUCCESS", "NOT_EVALUATED", None),
            (0, "ERROR", "NOT_EVALUATED", None),
        ):
            with self.subTest(value=value, read=read):
                result = resolve_bitlocker(shell_setting(value, read))
                self.assertEqual(result["state"], state)
                self.assertEqual(result["shellInterpretationMethod"], interpretation)
                self.assertIn(result["status"], {"PARTIAL", "NOT_EVALUATED"})
                self.assertIsNone(result["authoritativeProtectionStatus"])
                self.assertIsNone(result["encryptionPercentage"])

    def test_conflicting_shell_does_not_replace_authoritative_observation(self):
        for value, raw, verified in ((True, 0, "ON"), (False, 1, "OFF")):
            setting = bitlocker_setting(value)
            setting["metadata"]["fallbacksAttempted"] = [{
                "provider": "SHELL_VOLUME_BITLOCKER_PROPERTY", "status": "SUCCESS", "volume": "C:",
                "rawState": {"value": raw, "shellReadStatus": "SUCCESS"},
            }]
            result = resolve_bitlocker(setting)
            self.assertEqual(result["state"], "SOURCE_CONFLICT")
            self.assertEqual(result["status"], "PARTIAL")
            self.assertEqual(result["authoritativeProtectionStatus"], verified)
            self.assertEqual(result["shellRawValue"], raw)
            self.assertEqual(result["encryptionPercentage"], 100 if value else 0)

    def test_rounded_percentage_cannot_override_conversion(self):
        setting = bitlocker_setting(True)
        setting["metadata"]["encryptionState"] = "ENCRYPTION_IN_PROGRESS"
        self.assertEqual(resolve_bitlocker(setting)["status"], "PARTIAL")

    def test_locked_or_contradictory_volume_cannot_pass(self):
        setting = bitlocker_setting(True)
        setting["metadata"]["lockStatus"] = "Locked"
        self.assertEqual(resolve_bitlocker(setting)["state"], "LOCKED")
        setting["metadata"].update(lockStatus="Unlocked", protectionStatus="Off")
        self.assertEqual(resolve_bitlocker(setting)["state"], "SOURCE_CONFLICT")


class BitLockerReportBoundaryTests(Sprint5TestCase):
    def test_lab_home_indications_and_authoritative_results(self):
        suspended = bitlocker_setting(False)
        suspended["metadata"].update(encryptionState="FULLY_ENCRYPTED", encryptionPercentage=100)
        used_space = bitlocker_setting(True)
        used_space["metadata"].update(encryptionState="USED_SPACE_ONLY_ENCRYPTED", encryptionMethod="XtsAes128")
        cases = (
            ("LAB-SHELL", shell_setting(1), "PARTIAL", "PROTECTION_ON_INDICATED"),
            ("LAB-AUTH", used_space, "PASS", "ENABLED"),
            ("HOME-SHELL", shell_setting(0), "PARTIAL", "PROTECTION_OFF_INDICATED"),
            ("HOME-AUTH", bitlocker_setting(False), "FAIL", "DISABLED_FULLY_DECRYPTED"),
            ("SUSPENDED", suspended, "FAIL", "PROTECTION_OFF_ENCRYPTED"),
            ("SHELL-SUSPENDED", shell_setting(5), "PARTIAL", "SHELL_SUSPENDED"),
        )
        service = SubmissionService(self.storage)
        assessment = self.assessment.assessment_id
        generator = UnifiedReportGenerator(self.storage)
        baseline = load_framework(Path(__file__).resolve().parents[1] / "compliance/frameworks/microsoft_baseline/framework.json")
        requirement = next(req for control in baseline.controls for req in control.evidence_requirements if req.source_reference == "BIT-001")
        context = AnalysisContext(raw_data={}, software_inventory=SoftwareInventory())
        for label, setting, status, state in cases:
            submission = f"SUB-{label}"
            evidence = self.evidence()
            settings = evidence["security"]["settings"]
            evidence["security"]["settings"] = [row for row in settings if not row["settingId"].startswith("BITLOCKER_")] + [setting]
            nonce = service.request_nonce(assessment, self.session.session_id, submission, self.token, "127.0.0.1")
            _, package, _ = service.accept(
                assessment_id=assessment, session_id=self.session.session_id, submission_id=submission,
                enrollment_token=self.token, nonce=nonce, source_address="127.0.0.1",
                archive_bytes=self.package(submission, nonce, evidence=evidence).read_bytes(),
            )
            result = ConsoleAnalysisPipeline(self.storage).analyze(package)
            finding = next(row["finding"] for row in result.findings if row["finding"]["rule_id"] == "BIT-001")
            self.assertEqual(finding["status"], status, label)
            baseline_record = FindingEvidenceExtractor().extract(requirement, context, [
                AuditFinding(Finding.from_dict(finding), KnowledgeRepository().get("BIT-001")),
            ])
            self.assertEqual(baseline_record.result, {"PARTIAL": EvidenceResult.INCONCLUSIVE, "PASS": EvidenceResult.SUPPORTS, "FAIL": EvidenceResult.CONTRADICTS}[status])
            normalized = self.storage.read_json(assessment, "normalized", submission + ".json")
            self.assertEqual(normalized["diskEncryption"]["bitLocker"]["state"], state, label)
            if label == "LAB-SHELL":
                single = generator.generate(assessment).read_text(encoding="utf-8")
                self.assertIn("BitLocker Shell indication: ON — Shell indication", single)
        model = generator.build_model(assessment)
        by_id = {row["submissionId"]: row["bitLocker"] for row in model["endpoints"]}
        for label, _, status, state in cases:
            self.assertEqual(by_id[f"SUB-{label}"]["status"], status)
            self.assertEqual(by_id[f"SUB-{label}"]["state"], state)
        html = generator.generate(assessment).read_text(encoding="utf-8")
        self.assertIn("ON — Shell indication", html)
        self.assertIn("OFF — Shell field heuristic; verify", html)
        self.assertIn("BitLocker Shell indication: 1 ON / 1 OFF", html)
        self.assertIn("XtsAes128", html)
        self.assertEqual(model["executiveEndpointMetrics"]["bitLockerNotEnabledEndpoints"], 2)
        self.assertEqual(model["executiveEndpointMetrics"]["bitLockerAttentionEndpoints"], 3)
        self.assertIn("fully decrypted", html)
        self.assertIn("Investigate suspension and resume BitLocker protection", html)
        self.assertNotIn("Unknown% encrypted", html)
