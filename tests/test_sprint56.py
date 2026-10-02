"""Sprint 5.6 evidence truth, scoped identity, and applicability regressions."""
import unittest
import tempfile
from pathlib import Path
from types import SimpleNamespace

from analyzer import _cve_analysis_metadata
from analysis_context import AnalysisContext
from cve.applicability import evaluate_applicability
from cve.cpe_resolver import CpeResolver
from cve.models import ApplicabilityStatus, CveProductEvaluation
from cve.service import empty_summary
from csa_lab.unified_report import _product_label, _executive_endpoint_metrics
from evidence.bitlocker import resolve_bitlocker
from evidence.identity_posture import identity_posture, mfa_posture, MfaPolicyObservation
from software.intelligence_worklist import intelligence_worklist
from software.models import SoftwareInventory
from software.models import SoftwareProduct
from cve.cache import NvdCache
from tests.test_sprint541 import CatalogClient, _cpe
from tests.test_cve_engine import _software, _cve_record, _configuration_for_criteria


class BitLockerStateTests(unittest.TestCase):
    def setting(self, state, protection, percentage, status="SUCCESS"):
        return {"settingId": "BITLOCKER_OS_PROTECTION", "effectiveValue": protection,
                "collectionStatus": status, "metadata": {"volumeType": "OperatingSystem",
                "encryptionState": state, "encryptionPercentage": percentage, "provider": "MANAGE_BDE"}}

    def test_decrypted_evidence_reaches_fail_and_executive_count(self):
        result = resolve_bitlocker(self.setting("FULLY_DECRYPTED", False, 0))
        self.assertEqual(result["state"], "DISABLED_FULLY_DECRYPTED")
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("fully decrypted", result["displayLabel"])
        self.assertEqual(_executive_endpoint_metrics([{"bitLocker": result}])["bitLockerNotEnabledEndpoints"], 1)

    def test_raw_zero_and_missing_never_disabled(self):
        for value in (None, 0, "", "false"):
            result = resolve_bitlocker(self.setting("UNKNOWN", value, None, "PARTIAL"))
            self.assertEqual(result["state"], "NOT_EVALUATED")
            self.assertIsNone(result["protectionEnabled"])

    def test_transitions_conflict_and_error_are_not_pass_or_disabled(self):
        for state in ("ENCRYPTION_IN_PROGRESS", "DECRYPTION_IN_PROGRESS", "SUSPENDED", "LOCKED", "SOURCE_CONFLICT"):
            result = resolve_bitlocker(self.setting(state, False, 50, "PARTIAL"))
            self.assertEqual(result["state"], state)
            self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(resolve_bitlocker(self.setting("UNKNOWN", None, None, "FAILED"))["state"], "ERROR")
        self.assertEqual(resolve_bitlocker(self.setting("FULLY_ENCRYPTED", True, 100))["state"], "ENABLED")


class IdentityPostureTests(unittest.TestCase):
    def evidence(self, domain=False):
        return {"identity": {"domainJoined": domain, "entraJoined": True, "windowsHelloProvisioned": True,
                             "mfaEnforced": True}, "accounts": {"settings": [
            {"settingId": "PASSWORD_POLICY_MIN_LENGTH", "effectiveValue": 0, "collectionStatus": "SUCCESS"},
            {"settingId": "PASSWORD_POLICY_HISTORY", "effectiveValue": 0, "collectionStatus": "SUCCESS"},
            {"settingId": "ACCOUNT_LOCKOUT_THRESHOLD", "effectiveValue": 0, "collectionStatus": "SUCCESS"},
        ]}}

    def test_weak_local_policy_and_endpoint_only_mfa(self):
        result = identity_posture(self.evidence(), [])
        self.assertEqual(result["passwordPolicy"]["state"], "FAIL")
        self.assertEqual(result["passwordPolicy"]["baselineMinimumLength"], 15)
        self.assertEqual(result["passwordPolicy"]["scope"], "LOCAL_POLICY")
        self.assertEqual(result["mfa"]["state"], "NOT_EVALUATED")
        self.assertNotIn("mfaEnforced", result["signals"])

    def test_domain_join_does_not_promote_local_account_policy(self):
        result = identity_posture(self.evidence(True), [])
        self.assertEqual(result["context"], "HYBRID_JOINED")
        self.assertEqual(result["passwordPolicy"]["domainEffectivePolicy"], "DOMAIN_POLICY_NOT_EVALUATED")
        self.assertEqual(result["mfa"]["state"], "NOT_EVALUATED")

    def test_configured_baseline_is_taken_from_control_result(self):
        result = identity_posture(self.evidence(), [{"finding": {"rule_id": "ACC-006", "evidence": {"required_minimum": 18}}}])
        self.assertEqual(result["passwordPolicy"]["baselineMinimumLength"], 18)

    def test_future_idp_provider_states_and_conflicts(self):
        def provider(state):
            return SimpleNamespace(evaluate=lambda: MfaPolicyObservation(state, "Synthetic IdP", "2026-09-30T00:00:00Z", "all assessed users", "fixture policy"))
        for state in ("ENFORCED", "NOT_ENFORCED", "PARTIAL", "SOURCE_CONFLICT"):
            self.assertEqual(mfa_posture((provider(state),))["state"], state)
        self.assertEqual(mfa_posture((provider("ENFORCED"), provider("NOT_ENFORCED")))["state"], "SOURCE_CONFLICT")
        self.assertEqual(mfa_posture((SimpleNamespace(evaluate=lambda: {"state":"ENFORCED"}),))["state"], "NOT_EVALUATED")


class ApplicabilityTruthTests(unittest.TestCase):
    def evaluate(self, criteria, version="150.0", **bounds):
        software = _software()
        software.version = version
        cpe = CpeResolver().resolve(software)
        configuration = _configuration_for_criteria(criteria)
        configuration["nodes"][0]["cpeMatch"][0].update(bounds)
        return evaluate_applicability(software, cpe, _cve_record([configuration]), {"OS": "Windows 11"})[0]

    def test_proven_version_mismatch_excludes_unknown_edition(self):
        criteria = "cpe:2.3:a:google:chrome:*:*:enterprise:*:*:*:*:*"
        self.assertEqual(self.evaluate(criteria, versionEndExcluding="140.0"), ApplicabilityStatus.NOT_AFFECTED)
        self.assertEqual(self.evaluate(criteria, version="130.0", versionEndExcluding="140.0"), ApplicabilityStatus.NOT_EVALUATED)

    def test_platform_mismatch_excludes_unknown_edition(self):
        criteria = "cpe:2.3:a:google:chrome:*:*:enterprise:*:*:android:*:*"
        self.assertEqual(self.evaluate(criteria, versionEndExcluding="160.0"), ApplicabilityStatus.NOT_AFFECTED)

    def test_bare_wildcard_and_na_remain_unknown(self):
        for version in ("*", "-"):
            self.assertEqual(self.evaluate(f"cpe:2.3:a:google:chrome:{version}:*:*:*:*:*:*:*"), ApplicabilityStatus.NOT_EVALUATED)


class ReportClarityTests(unittest.TestCase):
    def test_provider_health_is_independent_from_coverage(self):
        summary = empty_summary(scan_complete=True)
        summary.eligible_products = 97
        summary.evaluated_products = 22
        summary.product_evaluations = [CveProductEvaluation(
            product_key="synthetic", display_name="Synthetic", version="1.0",
            normalization_status="SUCCESS", normalization_confidence=95,
            eligibility_status="ELIGIBLE", provider_query_status="SUCCESS",
        )]
        context = AnalysisContext(raw_data={}, software_inventory=SoftwareInventory(), cve_summary=summary)
        provider = _cve_analysis_metadata(context)["providerCoverage"][0]
        self.assertEqual(provider["status"], "SUCCESS")
        self.assertEqual(provider["evaluationCoverageStatus"], "PARTIAL")
        self.assertEqual(provider["fullyEvaluatedInstances"], 22)
        summary.api_errors = 1
        summary.product_evaluations[0].provider_query_status = "FAILED"
        self.assertEqual(_cve_analysis_metadata(context)["providerCoverage"][0]["status"], "FAILED")

    def test_duplicate_display_versions_and_msi_builds(self):
        for name, version, expected in (
            ("Wireshark 4.4.7 x64", "4.4.7", "Wireshark x64"),
            ("Python 3.12.4 (64-bit)", "3.12.4150.0", "Python (64-bit)"),
            ("Office 2019", "16.0", "Office 2019"),
            ("Visual C++ 2012", "11.0", "Visual C++ 2012"),
        ):
            self.assertEqual(_product_label({"displayName": name, "displayVersion": version}), expected)

    def test_worklist_groups_versions_but_not_component_families(self):
        def product(name, version):
            return {"normalizedVendor": "Microsoft", "normalizedProduct": name, "displayName": name,
                    "displayVersion": version, "cvePipeline": {"eligibilityStatus": "ELIGIBLE", "terminalStatus": "PARTIAL", "terminalReasonCode": "APPLICABILITY_INCOMPLETE"}}
        endpoints = [{"softwareResults": [product("Teams", "1.0"), product("Teams", "1.0"), product("Teams Meeting Add-in", "2.0")]},
                     {"softwareResults": [product("Teams", "2.0")]}]
        rows = intelligence_worklist(endpoints)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["canonicalProduct"], "Teams")
        self.assertEqual(rows[0]["eligibleInstanceCount"], 2)
        self.assertEqual(rows[0]["versions"], ["1.0", "2.0"])
        self.assertNotIn("endpoints", rows[0])


class IdentityRuleCacheTests(unittest.TestCase):
    def test_validated_publisher_alias_is_reranked_after_rule_change(self):
        class UsbClient(CatalogClient):
            def get_cpes(self, params):
                self.queries.append(params["keywordSearch"])
                return [_cpe("usbpcap_project", "usbpcap", "1.5.4.0")]

        with tempfile.TemporaryDirectory() as directory:
            client = UsbClient(NvdCache(Path(directory) / "nvd.sqlite3"))
            resolver = CpeResolver(client=client)
            product = SoftwareProduct(vendor="Tomasz Mon", product="USBPcap 1.5.4.0", version="1.5.4.0",
                                      normalized_vendor="Tomasz Mon", normalized_product="USBPcap",
                                      normalized_version="1.5.4.0", confidence=60)
            first = resolver.resolve_with_trace(product)
            self.assertEqual(first.status, "SUCCESS")
            for _ in range(50):
                self.assertEqual(resolver.resolve_with_trace(product), first)
            self.assertEqual(len(client.queries), 1)
            self.assertEqual(resolver.metrics["resolutionMemoryHits"], 50)
            resolver.discovery_aliases.pop("tomasz mon|usbpcap")
            rejected = resolver.resolve_with_trace(product)
            self.assertIsNone(rejected.candidate)
            self.assertEqual(rejected.status, "NO_RELIABLE_MAPPING")
            # Cached raw catalog data may be reused, but the old identity
            # decision may not survive removal of its authoritative alias.
            self.assertEqual(len(client.queries), 1)
