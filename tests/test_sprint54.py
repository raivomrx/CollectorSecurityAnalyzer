"""Sprint 5.4: authoritative product identities, passive posture and secrets."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from analysis_context import AnalysisContext
from analyzer import _cve_analysis_metadata
from csa_lab.secrets import NvdSecretStore
from csa_lab.unified_report import _cve_security_order, _software_matrix
from cve.cache import NvdCache
from cve.client import NvdClient, NVD_CPE_ENDPOINT
from cve.cpe_resolver import CpeResolver
from cve.enrichment_service import VulnerabilityEnrichmentService
from cve.models import ApplicabilityStatus
from cve.providers.cve_program import CveProgramCache, CveProgramProvider
from evidence.credential_posture import credential_posture
from software.inventory import build_inventory
from tests.test_sprint523_software_intelligence import _cpe_product, _discovery_product
from tests.test_console_sprint5 import Sprint5TestCase

FIXTURES = Path(__file__).parent / "fixtures" / "sprint54"


def fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class PublicFixtureClient:
    def __init__(self):
        self.queries = []
        self.cve_queries = []

    def get_cpes(self, params):
        query = params["keywordSearch"].casefold()
        self.queries.append(query)
        for token in ("lightroom", "premiere", "libreoffice"):
            if token in query:
                return fixture(f"{token}-cpes.json")
        if query == "audacity":
            return [_cpe_product("audacity", "audacity", "2.4.2", "Audacity 2.4.2")]
        # A helper is deliberately offered its parent. Selection must reject it.
        if "ccleaner" in query:
            return [_cpe_product("piriform", "ccleaner", "6.0", "CCleaner")]
        if "webview" in query:
            return [_cpe_product("microsoft", "edge_chromium", "152.0", "Microsoft Edge")]
        return []

    def get_cves(self, params):
        self.cve_queries.append(params)
        identity = params.get("cpeName", params.get("virtualMatchString", ""))
        if ":lightroom:" in identity:
            assert ":classic:" in identity
            return fixture("CVE-2021-40776-nvd.json")
        if ":premiere_pro:" in identity:
            return fixture("CVE-2020-9653-nvd.json")
        return []


class Response:
    status_code = 200
    headers = {}
    text = ""

    def __init__(self, value):
        self.value = value

    def json(self):
        return self.value

    def raise_for_status(self):
        pass


class FakeSession:
    def __init__(self, value):
        self.value = value
        self.calls = 0

    def get(self, *args, **kwargs):
        self.calls += 1
        return Response(self.value)


class Sprint54IdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def inventory(self, rows):
        return build_inventory(rows, unknown_products_path=self.root / "unknown.json")

    def test_public_lightroom_record_through_normalization_discovery_applicability_and_trust(self):
        from cve.service import CveService
        inventory = self.inventory([{"Publisher": "Adobe", "DisplayName": "Adobe Lightroom Classic", "DisplayVersion": "8.4"}])
        client = PublicFixtureClient()
        summary = CveService(client=client, resolver=CpeResolver(client=client)).scan_inventory(
            inventory, raw_data={"OS": "Microsoft Windows 11", "Architecture": "x64"},
        )
        self.assertEqual(summary.product_evaluations[0].terminal_status, "COMPLETED")
        self.assertEqual(summary.assessments[0].applicability, ApplicabilityStatus.AFFECTED)
        session = FakeSession(fixture("CVE-2021-40776-cna.json"))
        provider = CveProgramProvider(session=session, cache=CveProgramCache(self.root / "cna.sqlite3"))
        enrichment = VulnerabilityEnrichmentService([provider]).enrich_summary(summary)
        detail = _cve_analysis_metadata(AnalysisContext(raw_data={}, software_inventory=inventory, cve_summary=summary, cve_enrichment=enrichment))["softwareResults"][0]["cveDetails"][0]
        self.assertEqual(detail["cveId"], "CVE-2021-40776")
        self.assertEqual(detail["sourceResolution"]["status"], "AUTHORITATIVE_CONFIRMED")
        self.assertIn("https://helpx.adobe.com/security/products/lightroom/apsb21-97.html", detail["vendorAdvisoryUrls"])
        trace = summary.product_evaluations[0].discovery_trace
        self.assertTrue(trace["queries"])
        self.assertIn(":classic:", trace["selectedCandidate"])

    def test_premiere_and_libreoffice_use_authoritative_families(self):
        from cve.service import CveService
        inventory = self.inventory([
            {"Publisher": "Adobe", "DisplayName": "Adobe Premiere Pro 2019", "DisplayVersion": "13.1.3"},
            {"Publisher": "The Document Foundation", "DisplayName": "LibreOffice", "DisplayVersion": "25.8.3.2"},
        ])
        client = PublicFixtureClient()
        summary = CveService(client=client, resolver=CpeResolver(client=client)).scan_inventory(inventory, raw_data={"OS": "Microsoft Windows 11"})
        self.assertTrue(all(row.terminal_status == "COMPLETED" for row in summary.product_evaluations))
        self.assertTrue(any(":adobe:premiere_pro:" in row.cpe for row in summary.product_evaluations))
        self.assertTrue(any(":libreoffice:libreoffice:" in row.cpe for row in summary.product_evaluations))
        self.assertEqual({item.cve.cve_id for item in summary.assessments}, {"CVE-2020-9653"})
        self.assertTrue(all(item.applicability == ApplicabilityStatus.AFFECTED for item in summary.assessments))

    def test_lightroom_requires_classic_edition_and_windows_prerequisite(self):
        from dataclasses import replace
        from cve.applicability import evaluate_applicability
        from cve.parser import parse_cve_items
        software = self.inventory([{"Publisher": "Adobe", "DisplayName": "Adobe Lightroom Classic", "DisplayVersion": "8.4"}]).products[0]
        candidate = CpeResolver(client=PublicFixtureClient()).resolve(software)
        record = parse_cve_items(fixture("CVE-2021-40776-nvd.json"))[0]
        windows = {"OS": "Microsoft Windows 11"}
        self.assertEqual(evaluate_applicability(software, candidate, record, windows)[0], ApplicabilityStatus.AFFECTED)
        unknown = replace(candidate, cpe_name=candidate.cpe_name.replace(":classic:", ":*:"))
        other = replace(candidate, cpe_name=candidate.cpe_name.replace(":classic:", ":mobile:"))
        self.assertEqual(evaluate_applicability(software, unknown, record, windows)[0], ApplicabilityStatus.NOT_EVALUATED)
        self.assertEqual(evaluate_applicability(software, other, record, windows)[0], ApplicabilityStatus.NOT_AFFECTED)
        self.assertEqual(evaluate_applicability(software, candidate, record, {})[0], ApplicabilityStatus.NOT_EVALUATED)

    def test_edge_webview_helper_and_audacity_coexist_without_conflation(self):
        from cve.service import CveService
        inventory = self.inventory([
            {"Publisher": "Microsoft Corporation", "DisplayName": "Microsoft Edge", "DisplayVersion": "153.0.4234.32"},
            {"Publisher": "Microsoft Corporation", "DisplayName": "Microsoft Edge WebView2 Runtime", "DisplayVersion": "152.0.4191.66"},
            {"Publisher": "Piriform", "DisplayName": "CCleaner Update Helper", "DisplayVersion": "1.0"},
            {"Publisher": "Audacity Team", "DisplayName": "Audacity 2.4.2", "DisplayVersion": "2.4.2"},
        ])
        client = PublicFixtureClient()
        summary = CveService(client=client, resolver=CpeResolver(client=client)).scan_inventory(inventory)
        rows = _cve_analysis_metadata(AnalysisContext(raw_data={}, software_inventory=inventory, cve_summary=summary))["softwareResults"]
        by_name = {row["normalizedProduct"]: row for row in rows}
        self.assertEqual(by_name["Microsoft Edge"]["displayVersion"], "153.0.4234.32")
        self.assertEqual(by_name["Microsoft Edge WebView2 Runtime"]["displayVersion"], "152.0.4191.66")
        self.assertEqual(by_name["Microsoft Edge WebView2 Runtime"]["cveEvaluationStatus"], "NOT_EVALUATED")
        self.assertEqual(by_name["CCleaner Update Helper"]["cveEvaluationStatus"], "NOT_EVALUATED")
        self.assertEqual(by_name["Audacity"]["cveEvaluationStatus"], "NO_KNOWN_VULNERABILITIES")
        self.assertEqual(len(_software_matrix([{"displayName": "HOME", "softwareResults": rows}])["rows"]), 4)

    def test_ambiguity_and_rejections_are_auditable(self):
        class Client:
            def get_cpes(self, params):
                return [_cpe_product("acme", product, "1.0", "Acme Tool") for product in ("acme_tool", "acme_tool_2026")]
        result = CpeResolver(client=Client()).resolve_with_trace(_discovery_product())
        self.assertEqual(result.status, "AMBIGUOUS")
        self.assertIsNone(result.trace["selectedCandidate"])
        self.assertIn("too close", result.trace["rejectionReason"])
        self.assertEqual(len(result.trace["topCandidates"]), 2)

    def test_positive_and_negative_nvd_cache_avoid_remote_calls_until_expiry(self):
        for products in ([], [_cpe_product("acme", "acme_tool", "1.0", "Acme Tool")]):
            with self.subTest(positive=bool(products)):
                cache = NvdCache(self.root / f"cache-{bool(products)}.sqlite3")
                session = FakeSession({"products": products, "totalResults": len(products)})
                params = {"keywordSearch": "Acme Tool"}
                cold = NvdClient(cache=cache, session=session)
                cold.get_cpes(params)
                warm = NvdClient(cache=cache, session=session)
                warm.get_cpes(params)
                self.assertEqual(session.calls, 1)
                self.assertEqual(cold.metrics["cpeCacheMisses"], 1)
                self.assertEqual(warm.metrics["cpeCacheHits"], 1)
                self.assertEqual(warm.metrics["nvdRequests"], 0)
                page = {**params, "startIndex": 0, "resultsPerPage": 2000}
                cache.set(NvdCache.make_key(NVD_CPE_ENDPOINT, page), NVD_CPE_ENDPOINT, page, session.value, -1)
                warm.get_cpes(params)
                self.assertEqual(session.calls, 2)

    def test_cve_program_persistent_cache_telemetry(self):
        session = FakeSession(fixture("CVE-2021-40776-cna.json"))
        cache = CveProgramCache(self.root / "program.sqlite3")
        cold = CveProgramProvider(cache=cache, session=session)
        warm = CveProgramProvider(cache=cache, session=session)
        cold.enrich("CVE-2021-40776")
        warm.enrich("CVE-2021-40776")
        self.assertEqual(cold.metrics["cveProgramRequests"], 1)
        self.assertEqual(warm.metrics["cveProgramRequests"], 0)
        self.assertEqual(warm.metrics["cveProgramCacheHits"], 1)


class Sprint54SecretTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows DPAPI")
    def test_lab_http_key_lifecycle_csrf_and_exports_never_return_key(self):
        import threading
        import zipfile
        import requests
        from csa_lab.service import LabApplicationService
        from csa_lab.web import LabAdminServer
        from csa_lab.firewall import NullFirewallManager
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"NVD_API_KEY": ""}):
            root = Path(directory)
            service = LabApplicationService(root / "assessments", firewall=NullFirewallManager())
            admin = LabAdminServer(service)
            thread = threading.Thread(target=admin.server.serve_forever, daemon=True)
            thread.start()
            key = "TEST-ONLY-HTTP-12345678-87654321"
            url = admin.url + "api/v1/nvd-settings"
            headers = {"X-CSA-Lab-CSRF": admin.csrf_token}
            try:
                denied = requests.post(url, json={"action": "save", "key": key}, timeout=5)
                self.assertEqual(denied.status_code, 403)
                saved = requests.post(url, headers=headers, json={"action": "save", "key": key}, timeout=5)
                self.assertEqual(saved.status_code, 200)
                self.assertTrue(saved.json()["savedKey"])
                self.assertNotIn(key, saved.text)
                status = requests.get(url, timeout=5)
                self.assertNotIn(key, status.text)
                with patch("cve.client.NvdClient._get_json", return_value={}) as probe:
                    checked = requests.post(url, headers=headers, json={"action": "test"}, timeout=5)
                    self.assertEqual(checked.status_code, 200)
                    probe.assert_called_once()
                    self.assertNotIn(key, checked.text)
                with patch("csa_lab.service._application_control_metadata", return_value={}), patch("csa_lab.service._authenticode_metadata", return_value={}):
                    (root / "logs").mkdir(exist_ok=True)
                    (root / "logs" / "csa-lab.log").write_text("NVD_API_KEY=" + key, encoding="utf-8")
                    bundle = service.export_diagnostic_bundle()
                with zipfile.ZipFile(bundle) as archive:
                    self.assertFalse(any("dpapi" in name or "config/" in name for name in archive.namelist()))
                    self.assertTrue(all(key.encode() not in archive.read(name) for name in archive.namelist()))
                self.assertTrue(all(key.encode() not in path.read_bytes() for path in root.rglob("*.jsonl")))
                removed = requests.post(url, headers=headers, json={"action": "remove"}, timeout=5)
                self.assertFalse(removed.json()["configured"])
            finally:
                admin.server.shutdown()
                thread.join(timeout=5)
                admin.server.server_close()
                service.shutdown()

    def test_http_provider_echo_cannot_expose_key(self):
        from cve.client import _http_error
        response = Response({})
        response.status_code = 403
        key = "NVD-PRIVATE-TEST-ONLY-123456"
        response.text = "Invalid apiKey: " + key
        error = _http_error(NVD_CPE_ENDPOINT, response, False, key)
        self.assertNotIn(key, str(error))
        self.assertIn("[REDACTED]", str(error))

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI")
    def test_dpapi_roundtrip_replace_remove_and_no_plaintext(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            store = NvdSecretStore(Path(directory))
            first = "TEST-ONLY-00000000-11111111-22222222"
            second = "TEST-ONLY-33333333-44444444-55555555"
            store.save(first)
            self.assertNotIn(first.encode(), store.path.read_bytes())
            self.assertNotIn(first, json.dumps(store.status()))
            self.assertEqual(store.load(), first)
            store.save(second)
            self.assertEqual(store.load(), second)
            store.remove()
            self.assertFalse(store.status()["configured"])
            self.assertIsNone(store.load())

    def test_invalid_keys_are_not_echoed_or_written(self):
        with tempfile.TemporaryDirectory() as directory:
            store = NvdSecretStore(Path(directory))
            for key in ("secret\r\nheader", "bad value", "x" * 200, None):
                with self.assertRaises(ValueError) as raised:
                    store.save(key)
                if key:
                    self.assertNotIn(key, str(raised.exception))
            self.assertFalse(store.path.exists())

    def test_environment_configuration_remains_supported(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"NVD_API_KEY": "test-environment-key"}):
            store = NvdSecretStore(Path(directory))
            self.assertEqual(store.status()["source"], "Environment variable")
            self.assertIsNone(store.load())
            client = NvdClient(cache=NvdCache(Path(directory) / "nvd.sqlite3"))
            self.addCleanup(client.session.close)
            self.assertEqual(client.api_key, "test-environment-key")
            self.assertEqual(client.limiter.requests, 50)


class Sprint54PostureTests(unittest.TestCase):
    def test_password_policy_control_pass_fail_and_unavailable_are_distinct(self):
        from collector_schema.loader import _parse_setting
        from evidence.registry import WindowsEvidenceRegistry
        from rules.windows.account_rules import Acc006Rule, Acc009Rule
        from software.models import SoftwareInventory
        for value, collection, expected in ((14, "SUCCESS", "PASS"), (0, "SUCCESS", "FAIL"), (None, "NOT_AVAILABLE", "NOT_EVALUATED"), (None, "ACCESS_DENIED", "NOT_EVALUATED")):
            with self.subTest(value=value, collection=collection):
                setting = _parse_setting({"settingId": "PASSWORD_POLICY_MIN_LENGTH", "category": "Accounts", "configuredValue": value, "effectiveValue": value, "source": "LOCAL_POLICY", "collectionStatus": collection, "confidence": 95, "provider": "NetUserModalsGet"})
                context = AnalysisContext(raw_data={}, software_inventory=SoftwareInventory(), evidence_registry=WindowsEvidenceRegistry([setting]))
                self.assertEqual(Acc006Rule().check({}, context)[0].status.value, expected)
        self.assertEqual(Acc006Rule.metadata.title, "Local password policy strength")
        self.assertEqual(Acc009Rule.metadata.title, "Password requirement for enabled local accounts")

    def test_one_weak_setting_is_not_proven_credential_exposure(self):
        result = credential_posture([{"settingId": "LLMNR_ENABLED", "effectiveValue": True, "collectionStatus": "SUCCESS"}])
        self.assertEqual(result["rating"], "NOT FULLY EVALUATED")
        self.assertFalse(result["correlatedPrerequisitesObserved"])
        self.assertIn("No credential capture", result["explanation"])

    def test_incomplete_smb_retains_independent_policy_results(self):
        rows = [{"settingId": name, "effectiveValue": value, "collectionStatus": "SUCCESS"} for name, value in (
            ("LLMNR_ENABLED", True), ("NTLM_RESTRICTION_LEVEL", 0), ("WPAD_RELEVANT_STATE", "ENABLED_OR_DEFAULT"), ("SMB_CLIENT_SIGNING_REQUIRED", False),
        )]
        rows.append({"settingId": "SMB_SERVER_SIGNING_REQUIRED", "effectiveValue": None, "collectionStatus": "ACCESS_DENIED"})
        result = credential_posture(rows)
        self.assertTrue(result["correlatedPrerequisitesObserved"])
        self.assertEqual(result["rating"], "NOT FULLY EVALUATED")
        self.assertTrue(any("ACCESS_DENIED" in reason for reason in result["limitations"]))

    def test_severity_then_confirmed_kev_then_applicability_then_cvss(self):
        rows = [
            {"cveId": "critical", "severity": "CRITICAL", "cvss": 9.1, "applicability": "POSSIBLE"},
            {"cveId": "high-score", "severity": "HIGH", "cvss": 8.9, "applicability": "CONFIRMED"},
            {"cveId": "high-kev", "severity": "HIGH", "cvss": 7.0, "knownExploited": True, "applicability": "CONFIRMED"},
            {"cveId": "high-possible", "severity": "HIGH", "cvss": 8.9, "knownExploited": True, "applicability": "POSSIBLE"},
            {"cveId": "medium", "severity": "MEDIUM", "cvss": 6.0},
            {"cveId": "low", "severity": "LOW", "cvss": 3.0},
            {"cveId": "unknown", "severity": "UNKNOWN"},
        ]
        self.assertEqual([row["cveId"] for row in sorted(reversed(rows), key=_cve_security_order)], ["critical", "high-kev", "high-score", "high-possible", "medium", "low", "unknown"])


class Sprint54ReportIntegrationTests(Sprint5TestCase):
    def test_accepted_protocol_evidence_reaches_credential_posture_and_html(self):
        from csa_console.submission import SubmissionService
        from csa_console.pipeline import ConsoleAnalysisPipeline
        from csa_lab.unified_report import UnifiedReportGenerator
        evidence = self.evidence()
        values = {"LLMNR_ENABLED": True, "NETBIOS_TCPIP_ENABLED": False,
                  "WPAD_RELEVANT_STATE": "DISABLED", "NTLM_RESTRICTION_LEVEL": 0,
                  "LAN_MANAGER_AUTHENTICATION_LEVEL": 5, "SMB_CLIENT_SIGNING_REQUIRED": False,
                  "SMB_SERVER_SIGNING_REQUIRED": True, "INSECURE_GUEST_LOGONS_ENABLED": False}
        evidence["security"]["settings"] = [item for item in evidence["security"]["settings"] if item["settingId"] not in values]
        for name, value in values.items():
            evidence["security"]["settings"].append({"settingId": name, "category": "Protocols", "configuredValue": value,
                "effectiveValue": value, "source": "RUNTIME_STATE", "collectionStatus": "SUCCESS", "confidence": 90,
                "provider": "Structured test provider", "collectedAt": evidence["collectionCompletedAt"]})
        aid, sid = self.assessment.assessment_id, "SUB-SPRINT54-REPORT"
        service = SubmissionService(self.storage)
        nonce = service.request_nonce(aid, self.session.session_id, sid, self.token, "127.0.0.1")
        _, package, _ = service.accept(assessment_id=aid, session_id=self.session.session_id, submission_id=sid,
            enrollment_token=self.token, nonce=nonce, source_address="127.0.0.1", archive_bytes=self.package(sid, nonce, evidence=evidence).read_bytes())
        ConsoleAnalysisPipeline(self.storage).analyze(package)
        generator = UnifiedReportGenerator(self.storage)
        posture = generator.build_model(aid)["endpoints"][0]["credentialPosture"]
        self.assertEqual(posture["rating"], "ELEVATED")
        self.assertTrue(posture["correlatedPrerequisitesObserved"])
        self.assertEqual(posture["limitations"], [])
        self.assertEqual(len(posture["components"]), 8)
        html = generator.generate(aid).read_text(encoding="utf-8")
        self.assertIn("Credential Exposure Posture", html)
        self.assertIn("not proven credential exploitability", html)
        self.assertIn("Allow outbound NTLM", html)


if __name__ == "__main__":
    unittest.main()
