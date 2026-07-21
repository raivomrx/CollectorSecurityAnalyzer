"""Tests for Collector Schema v2 and Windows evidence rules."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from analysis_context import AnalysisContext
from collector_schema.compatibility import CollectorV1ToV2Adapter
from collector_schema.enums import CollectionStatus, ConfigurationSource, PrivacyMode
from collector_schema.loader import load_collector_document
from collector_schema.validation import CollectorSchemaError, validate_v2_document
from evidence.normalization import normalize_windows_evidence
from evidence.provenance import pseudonymize_hostname, redact_value
from evidence.registry import WindowsEvidenceRegistry
from evidence.windows_models import SecuritySettingEvidence
from policies.loader import load_policy_profile
from analyzer import analyze_file
from report import generate_html_report
from risk import Severity, Status
from rules.windows.defender_rules import Def002Rule, Def003Rule
from rules.windows.firewall_rules import Fw002Rule
from rules.windows.remote_access_rules import Remote006Rule
from software.inventory import build_inventory


class CollectorSchemaTests(unittest.TestCase):
    """Validate Collector Schema v2 behavior."""

    def test_valid_v2_document_loads(self) -> None:
        """A valid v2 document should load and normalize."""

        document = load_collector_document(_v2_document(), validate=True)
        registry = normalize_windows_evidence(document)

        self.assertEqual(document.schema_version, "2.0")
        self.assertIsNotNone(registry.get("DEFENDER_REALTIME_PROTECTION_ENABLED"))
        self.assertEqual(document.collection_summary.module_invocation_coverage_percent, 100.0)
        self.assertEqual(document.collection_summary.successful_module_percent, 50.0)
        self.assertEqual(document.collection_summary.evidence_unit_coverage_percent, 50.0)
        self.assertEqual(document.collection_summary.mandatory_evidence_coverage_percent, 50.0)

    def test_invalid_schema_values_are_rejected(self) -> None:
        """Validation should reject invalid enum, confidence, timestamps, and duplicates."""

        invalid = _v2_document()
        invalid["security"]["settings"][0]["confidence"] = 101
        with self.assertRaises(CollectorSchemaError):
            validate_v2_document(invalid)

        invalid = _v2_document()
        invalid["security"]["settings"][0]["collectionStatus"] = "NOPE"
        with self.assertRaises(CollectorSchemaError):
            validate_v2_document(invalid)

        invalid = _v2_document()
        invalid["security"]["settings"].append(dict(invalid["security"]["settings"][0]))
        with self.assertRaises(CollectorSchemaError):
            validate_v2_document(invalid)

        invalid = _v2_document()
        invalid["collectionCompletedAt"] = "2026-07-20T09:00:00Z"
        with self.assertRaises(CollectorSchemaError):
            validate_v2_document(invalid)

    def test_unsupported_major_schema_version_is_rejected(self) -> None:
        """Unknown major versions should fail clearly."""

        invalid = _v2_document()
        invalid["schemaVersion"] = "9.0"

        with self.assertRaises(CollectorSchemaError):
            load_collector_document(invalid, validate=True)

    def test_forward_compatible_minor_version_is_allowed(self) -> None:
        """A newer v2 minor version should be accepted conservatively."""

        data = _v2_document()
        data["schemaVersion"] = "2.1"

        self.assertEqual(load_collector_document(data, validate=True).schema_version, "2.1")

    def test_atomic_incomplete_file_is_rejected_when_validating(self) -> None:
        """A temporary collector output should not be treated as final JSON."""

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "evidence.tmp"
            path.write_text("{}", encoding="utf-8")
            with self.assertRaises(ValueError):
                analyze_file(path, output_dir=Path(temp_dir) / "out", validate_input=True)


class V1CompatibilityTests(unittest.TestCase):
    """Validate v1 compatibility conversion."""

    def test_v1_conversion_does_not_invent_missing_evidence(self) -> None:
        """The adapter should convert known fields without inventing TPM or method evidence."""

        source = {
            "ComputerName": "EE-D3147",
            "Bitlocker-C": True,
            "Windows Defender": {"ProductState": "On"},
            "Firewall": {"Domain": {"Enabled": True}},
            "All_local_admins": ["Administrator", "Helpdesk"],
            "Updates_lastInstallationSuccessDate": "2026-07-01",
        }

        document = CollectorV1ToV2Adapter().convert(source)
        registry = normalize_windows_evidence(document)

        self.assertEqual(registry.get("BITLOCKER_OS_PROTECTION").effective_value, True)
        self.assertIsNone(registry.get("TPM_READY"))
        self.assertEqual(registry.get("BITLOCKER_OS_PROTECTION").source, ConfigurationSource.UNKNOWN)
        self.assertEqual(registry.get("BITLOCKER_OS_PROTECTION").confidence, 70)
        self.assertEqual(registry.get("BITLOCKER_OS_PROTECTION").metadata["adapter"], "v1_to_v2")


class EvidenceRegistryTests(unittest.TestCase):
    """Validate evidence registry behavior."""

    def test_registry_lookup_duplicate_and_collection_error(self) -> None:
        """Registry should preserve lookup semantics and collection failure states."""

        failed = _setting(
            "TPM_READY",
            "Device Security",
            None,
            CollectionStatus.ACCESS_DENIED,
            error_code="CSA-COLLECT-ACCESS-DENIED",
        )
        registry = WindowsEvidenceRegistry([_setting("A", "Defender", True), _setting("A", "Defender", False), failed])

        self.assertEqual(registry.get("A").effective_value, True)
        self.assertEqual(registry.duplicates, ["A"])
        self.assertEqual(registry.find_by_category("defender")[0].setting_id, "A")
        self.assertEqual(registry.missing_or_problematic()[0].collection_status, CollectionStatus.ACCESS_DENIED)


class WindowsEvidenceRuleTests(unittest.TestCase):
    """Validate conservative Windows evidence rule semantics."""

    def test_rule_pass_fail_missing_access_denied_and_not_supported(self) -> None:
        """Rules should not confuse disabled, missing, access denied, and unsupported evidence."""

        self.assertEqual(Def002Rule().check({}, _context([_setting("DEFENDER_REALTIME_PROTECTION_ENABLED", "Defender", True)]))[0].status, Status.PASS)
        self.assertEqual(Def002Rule().check({}, _context([_setting("DEFENDER_REALTIME_PROTECTION_ENABLED", "Defender", False)]))[0].status, Status.FAIL)
        self.assertEqual(Def002Rule().check({}, _context([]))[0].status, Status.NOT_EVALUATED)
        self.assertEqual(
            Def002Rule().check({}, _context([_setting("DEFENDER_REALTIME_PROTECTION_ENABLED", "Defender", None, CollectionStatus.ACCESS_DENIED)]))[0].status,
            Status.NOT_EVALUATED,
        )
        self.assertEqual(
            Def002Rule().check({}, _context([_setting("DEFENDER_REALTIME_PROTECTION_ENABLED", "Defender", None, CollectionStatus.NOT_SUPPORTED)]))[0].status,
            Status.NOT_APPLICABLE,
        )

    def test_policy_threshold_and_approved_remote_access(self) -> None:
        """Rules should use policy thresholds and approved remote products."""

        policy = load_policy_profile()
        stale = Def003Rule().check({}, _context([_setting("DEFENDER_SIGNATURE_AGE_DAYS", "Defender", 7)], policy=policy))[0]
        approved = Remote006Rule().check({}, _context([_setting("REMOTE_ACCESS_PRODUCTS", "Remote Access", [])], policy=policy))[0]
        unapproved = Remote006Rule().check({}, _context([_setting("REMOTE_ACCESS_PRODUCTS", "Remote Access", ["AnyDesk"])], policy=policy))[0]

        self.assertEqual(stale.status, Status.FAIL)
        self.assertEqual(approved.status, Status.PASS)
        self.assertEqual(unapproved.status, Status.FAIL)

    def test_skip_category_and_prerequisite(self) -> None:
        """Skipped categories and inactive prerequisites should not create failures."""

        skipped = Fw002Rule().check({}, _context([], skipped=["Firewall"]))[0]

        self.assertEqual(skipped.status, Status.NOT_EVALUATED)


class PrivacyAndReportTests(unittest.TestCase):
    """Validate privacy helpers and report sections."""

    def test_privacy_redaction_is_deterministic(self) -> None:
        """Strict privacy should redact personal paths and pseudonymize hostnames."""

        self.assertEqual(redact_value(r"C:\Users\John\Desktop\file.txt"), r"C:\Users\<USER>\Desktop\file.txt")
        self.assertEqual(redact_value("10.1.2.3", PrivacyMode.STRICT), "10.1.2.xxx")
        self.assertEqual(pseudonymize_hostname("LAPTOP-1", PrivacyMode.STRICT), pseudonymize_hostname("LAPTOP-1", PrivacyMode.STRICT))

    def test_report_contains_collection_quality_policy_and_missing_evidence(self) -> None:
        """HTML report should show collection quality, policy, settings, and missing evidence."""

        document = load_collector_document(_v2_document(), validate=True)
        registry = normalize_windows_evidence(document)
        policy = load_policy_profile()
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "report.html"
            report_path = generate_html_report(
                data={"ComputerName": "EE-D3147"},
                audit_findings=[],
                score=100,
                software_inventory=build_inventory([]),
                rule_metadata={},
                cve_summary=None,
                output_path=path,
                collector_document=document,
                evidence_registry=registry,
                policy_profile=policy,
                privacy_mode=PrivacyMode.STRICT,
            )
            html = report_path.read_text(encoding="utf-8")

        self.assertIn("Collection Quality", html)
        self.assertIn("Windows Security Configuration", html)
        self.assertIn("Missing Evidence", html)
        self.assertIn("WINDOWS_ENDPOINT_DEFAULT", html)
        self.assertIn("DEFENDER_REALTIME_PROTECTION_ENABLED", html)
        self.assertIn("TPM_READY", html)


def _context(settings: list[SecuritySettingEvidence], policy=None, skipped=None) -> AnalysisContext:
    """Create an analysis context with normalized evidence."""

    return AnalysisContext(
        raw_data={},
        software_inventory=build_inventory([]),
        evidence_registry=WindowsEvidenceRegistry(settings),
        policy_profile=policy or load_policy_profile(),
        skipped_categories=skipped or [],
    )


def _setting(
    setting_id: str,
    category: str,
    value,
    status: CollectionStatus = CollectionStatus.SUCCESS,
    error_code: str | None = None,
) -> SecuritySettingEvidence:
    """Create test security setting evidence."""

    return SecuritySettingEvidence(
        setting_id=setting_id,
        category=category,
        configured_value=value,
        effective_value=value,
        source=ConfigurationSource.RUNTIME_STATE,
        collection_status=status,
        confidence=90 if status == CollectionStatus.SUCCESS else 0,
        collected_at=datetime.now(timezone.utc),
        provider="test",
        source_path=setting_id,
        error_code=error_code,
        error_message="collection problem" if error_code else None,
    )


def _v2_document() -> dict:
    """Return a minimal valid Schema v2 document."""

    return {
        "schemaVersion": "2.0",
        "collectorVersion": "test",
        "collectionId": "test-1",
        "collectionStartedAt": "2026-07-20T10:00:00Z",
        "collectionCompletedAt": "2026-07-20T10:01:00Z",
        "device": {"hostname": "EE-D3147", "elevated": True},
        "operatingSystem": {"name": "Windows 11", "version": "25H2"},
        "security": {
            "settings": [
                {
                    "settingId": "DEFENDER_REALTIME_PROTECTION_ENABLED",
                    "category": "Defender",
                    "configuredValue": True,
                    "effectiveValue": True,
                    "source": "SECURITY_PRODUCT",
                    "collectionStatus": "SUCCESS",
                    "confidence": 90,
                    "collectedAt": "2026-07-20T10:00:30Z",
                    "provider": "Get-MpComputerStatus",
                    "sourcePath": "RealTimeProtectionEnabled",
                },
                {
                    "settingId": "TPM_READY",
                    "category": "Device Security",
                    "configuredValue": None,
                    "effectiveValue": None,
                    "source": "UNKNOWN",
                    "collectionStatus": "ACCESS_DENIED",
                    "confidence": 0,
                    "collectedAt": "2026-07-20T10:00:30Z",
                    "provider": "Get-Tpm",
                    "sourcePath": "TpmReady",
                    "errorCode": "CSA-COLLECT-ACCESS-DENIED",
                    "errorMessage": "Administrator privileges are required.",
                },
            ]
        },
        "updates": {"settings": []},
        "software": {"items": []},
        "services": {"services": [], "scheduledTasks": []},
        "collectionSummary": {
            "totalCollectors": 2,
            "successfulCollectors": 1,
            "partialCollectors": 0,
            "failedCollectors": 0,
            "unsupportedCollectors": 0,
            "accessDeniedCollectors": 1,
            "evidenceItems": 2,
            "moduleInvocationCoveragePercent": 100.0,
            "successfulModulePercent": 50.0,
            "evidenceUnitCoveragePercent": 50.0,
            "mandatoryEvidenceCoveragePercent": 50.0,
            "collectionCoveragePercent": 50.0,
            "mandatoryCollectionCoveragePercent": 50.0,
            "elevated": True,
            "rebootPending": False,
            "warnings": [],
        },
        "errors": [],
    }


if __name__ == "__main__":
    unittest.main()
