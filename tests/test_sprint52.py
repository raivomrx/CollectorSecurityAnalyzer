"""Sprint 5.2 assessment intelligence correctness tests."""

from __future__ import annotations

import tempfile
import unittest
from datetime import date, datetime, timezone
from pathlib import Path

from analysis_context import AnalysisContext
from analyzer import _cve_analysis_metadata, _software_results
from csa_console.pipeline import _cve_audit_details
from csa_lab.service import _application_control_metadata
from csa_lab.unified_report import (
    _bitlocker_detail,
    _endpoint_display_name,
    _endpoint_users,
    _priority_actions,
)
from cve.models import (
    ApplicabilityStatus,
    CveAssessment,
    CveDataQuality,
    CveRecord,
)
from software.inventory import build_inventory
from software.lifecycle import LifecycleRepository
from software.models import LifecycleStatus, SoftwareInventory, SoftwareProduct


def _software(product: str = ".NET", version: str = "6.0.36") -> SoftwareProduct:
    return SoftwareProduct(
        vendor="Microsoft Corporation",
        product=product,
        version=version,
        normalized_vendor="Microsoft",
        normalized_product=product,
        normalized_version=version,
        architecture="x64",
        scope="MACHINE",
        source="HKLM_UNINSTALL",
        confidence=100,
        normalization_status="NORMALIZED",
    )


class Sprint52IntelligenceTests(unittest.TestCase):
    """Verify conservative endpoint and software intelligence semantics."""

    def test_endpoint_identity_uses_real_name_and_fallbacks(self) -> None:
        self.assertEqual(_endpoint_display_name({"computerName": "DELL-MINI"}), "DELL-MINI")
        self.assertEqual(_endpoint_display_name({"hostName": "LENOVO-T14"}), "LENOVO-T14")
        self.assertEqual(_endpoint_display_name({"computerName": "id-deadbeef", "fqdn": "pc.lab"}), "pc.lab")

    def test_user_inventories_deduplicate_by_sid(self) -> None:
        evidence = {
            "securityPolicies": {"settings": [
                {"settingId": "LOCAL_USERS", "effectiveValue": [
                    {"Name": "alice", "Sid": "S-1"},
                    {"Name": "ALICE", "Sid": "S-1"},
                ]},
                {"settingId": "LOCAL_ADMINISTRATORS", "effectiveValue": [
                    {"Name": "AzureAD\\alice", "Sid": "S-2", "Classification": "ENTRA"}
                ]},
            ]}
        }
        users = _endpoint_users(evidence, {"currentUser": "LAB\\alice"})
        self.assertEqual(len(users["localUsers"]), 1)
        self.assertEqual(users["localAdministrators"][0]["classification"], "ENTRA")

    def test_inventory_preserves_source_scope_and_collection_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            inventory = build_inventory(
                [{
                    "displayName": "Google Chrome",
                    "displayVersion": "144.0.1",
                    "publisher": "Google LLC",
                    "architecture": "x64",
                    "scope": "MACHINE",
                    "source": "HKLM_UNINSTALL",
                }],
                unknown_products_path=Path(directory) / "unknown.json",
                collection_status="ERROR",
                collection_errors=["CSA-COLLECT-SOFTWARE"],
            )
        self.assertEqual(inventory.products[0].source, "HKLM_UNINSTALL")
        self.assertEqual(inventory.products[0].scope, "MACHINE")
        self.assertEqual(inventory.collection_status, "ERROR")

    def test_empty_failed_inventory_is_not_reported_as_complete_cve_coverage(self) -> None:
        context = AnalysisContext(
            raw_data={},
            software_inventory=SoftwareInventory(collection_status="ERROR"),
        )
        metadata = _cve_analysis_metadata(context)
        self.assertEqual(metadata["status"], "NOT_EVALUATED")
        self.assertEqual(metadata["coveragePercent"], 0.0)

    def test_lifecycle_out_supported_nearing_and_unknown(self) -> None:
        repository = LifecycleRepository()
        old = repository.assess(_software(), assessed_on=date(2026, 8, 5))
        nearing = repository.assess(_software(version="8.0.20"), assessed_on=date(2026, 8, 5))
        unknown = repository.assess(_software("Internal Client", "1.0"), assessed_on=date(2026, 8, 5))
        self.assertEqual(old.status, LifecycleStatus.OUT_OF_SUPPORT)
        self.assertEqual(nearing.status, LifecycleStatus.NEARING_END_OF_SUPPORT)
        self.assertEqual(unknown.status, LifecycleStatus.NOT_EVALUATED)

    def test_confirmed_cve_is_bound_to_installed_version(self) -> None:
        software = _software()
        cve = CveRecord(
            cve_id="CVE-2026-0001",
            description="test",
            published=datetime(2026, 1, 1, tzinfo=timezone.utc),
            last_modified=datetime(2026, 1, 2, tzinfo=timezone.utc),
            cvss_version="3.1",
            cvss_score=9.8,
            severity="CRITICAL",
            vector=None,
            cwes=[],
            references=[],
            configurations=[],
            source_identifier="nvd",
            vuln_status="Analyzed",
            data_quality=CveDataQuality.COMPLETE,
        )
        assessment = CveAssessment(
            software=software,
            cpe=None,
            cve=cve,
            applicability=ApplicabilityStatus.AFFECTED,
            reason="Installed version is in affected range",
            confidence=95,
            matched_criteria=["< 6.0.40"],
        )
        lifecycle = LifecycleRepository().assess(software, assessed_on=date(2026, 8, 5))
        rows = _software_results(
            SoftwareInventory(products=[software], product_count=1),
            [assessment],
            [lifecycle],
            scan_status="COMPLETE",
            kev_ids={"CVE-2026-0001"},
        )
        self.assertEqual(rows[0]["cveEvaluationStatus"], "CONFIRMED")
        self.assertEqual(rows[0]["securityStatus"], "Both vulnerable and out of support")
        self.assertTrue(rows[0]["cveDetails"][0]["cisaKev"])

    def test_priority_actions_rank_and_deduplicate(self) -> None:
        endpoints = [{
            "displayName": "DELL-MINI",
            "cveSummary": {"cisaKevUniqueCves": 1, "criticalUniqueCves": 1},
            "unsupportedSoftwareCount": 1,
        }]
        findings = [{
            "ruleId": "BIT-001",
            "severity": "HIGH",
            "title": "BitLocker disabled",
            "endpointReferences": ["DELL-MINI"],
        }]
        actions = _priority_actions(endpoints, findings)
        self.assertEqual(actions[0]["action"], "Remediate CISA KEV vulnerabilities")
        self.assertLessEqual(len(actions), 5)
        self.assertEqual(len({item["action"] for item in actions}), len(actions))

    def test_missing_bitlocker_evidence_is_not_a_failure(self) -> None:
        self.assertEqual(_bitlocker_detail({})["status"], "NOT_EVALUATED")

    def test_cve_audit_details_are_aggregate_and_credential_safe(self) -> None:
        details = _cve_audit_details(
            "SUB-001",
            {
                "status": "COMPLETE",
                "coveragePercent": 75.0,
                "eligibleProducts": 4,
                "evaluatedProducts": 3,
                "cisaKevMatches": 1,
                "lifecycleDataVersion": "CSA-LIFECYCLE-2026.08",
                "softwareResults": [
                    {"confirmedCveCount": 2, "possibleCveCount": 1}
                ],
            },
        )
        self.assertEqual(details["confirmedMatches"], 2)
        self.assertEqual(details["possibleMatches"], 1)
        self.assertNotIn("softwareResults", details)

    def test_application_control_diagnostics_are_safe_summary(self) -> None:
        metadata = _application_control_metadata()
        self.assertIn("detectionStatus", metadata)
        self.assertNotIn("path", {key.casefold() for key in metadata})


if __name__ == "__main__":
    unittest.main()
