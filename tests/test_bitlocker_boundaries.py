"""Synthetic OS-volume observations through the actual submission pipeline."""
import unittest

from csa_console.pipeline import ConsoleAnalysisPipeline
from csa_console.submission import SubmissionService
from csa_lab.unified_report import UnifiedReportGenerator
from evidence.bitlocker import resolve_bitlocker
from tests.test_console_sprint5 import Sprint5TestCase
from tests.test_sprint531_semantics import bitlocker_setting


def shell_setting(value):
    setting = bitlocker_setting(None, "PARTIAL")
    setting["provider"] = "SHELL_VOLUME_BITLOCKER_PROPERTY"
    setting["metadata"] = {
        "volumeType": "OperatingSystem",
        "mountPoint": "C:",
        "shellRawValue": value,
        "observedAt": "2026-11-03T08:00:00Z",
    }
    return setting


class BitLockerBoundaryTests(unittest.TestCase):
    def test_old_shell_percent_is_not_measured_evidence(self):
        for raw, expected in ((0, "NOT_EVALUATED"), (1, "PROTECTION_ON_INDICATED"), (2, "PROTECTION_OFF_INDICATED")):
            setting = shell_setting(raw)
            setting["metadata"].update(encryptionPercentage=100, encryptionState="FULLY_ENCRYPTED")
            result = resolve_bitlocker(setting)
            self.assertEqual(result["state"], expected)
            self.assertIsNone(result["encryptionPercentage"])
            self.assertEqual(result["encryptionState"], "UNKNOWN")

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
        cases = (
            ("LAB-SHELL", shell_setting(1), "PARTIAL", "PROTECTION_ON_INDICATED"),
            ("LAB-AUTH", bitlocker_setting(True), "PASS", "ENABLED"),
            ("HOME-SHELL", shell_setting(0), "NOT_EVALUATED", "NOT_EVALUATED"),
            ("HOME-AUTH", bitlocker_setting(False), "FAIL", "DISABLED_FULLY_DECRYPTED"),
            ("SUSPENDED", suspended, "FAIL", "PROTECTION_OFF_ENCRYPTED"),
        )
        service = SubmissionService(self.storage)
        assessment = self.assessment.assessment_id
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
            normalized = self.storage.read_json(assessment, "normalized", submission + ".json")
            self.assertEqual(normalized["diskEncryption"]["bitLocker"]["state"], state, label)
        generator = UnifiedReportGenerator(self.storage)
        model = generator.build_model(assessment)
        by_id = {row["submissionId"]: row["bitLocker"] for row in model["endpoints"]}
        for label, _, status, state in cases:
            self.assertEqual(by_id[f"SUB-{label}"]["status"], status)
            self.assertEqual(by_id[f"SUB-{label}"]["state"], state)
        html = generator.generate(assessment).read_text(encoding="utf-8")
        self.assertIn("PROTECTION ON INDICATED", html)
        self.assertIn("fully decrypted", html)
        self.assertIn("Investigate suspension and resume BitLocker protection", html)
        self.assertNotIn("Unknown% encrypted", html)
