"""Audit2 regression with synthetic NVD/CNA data and frozen endpoint fixtures."""

from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, mock

from csa_console.pipeline import ConsoleAnalysisPipeline
from csa_console.submission import SubmissionService
from csa_lab.unified_report import UnifiedReportGenerator
from cve.applicability import evaluate_applicability_result
from cve.cache import NvdCache
from cve.cna_applicability import evaluate_cna_applicability
from cve.cpe_resolver import build_cpe23
from cve.enrichment_models import SourceEnrichment, SourceType
from cve.enrichment_service import VulnerabilityEnrichmentService
from cve.models import ApplicabilityStatus, CpeCandidate, CpeMatchStatus
from cve.parser import parse_cve_items
from cve.providers.cve_program import parse_cna_affected
from cve.service import CveService
from cve.status import normalize_metadata
from software.inventory import build_inventory
from software.version import compare_applicability_versions, version_evidence
from tests.test_bitlocker_boundaries import shell_setting
from tests.test_console_sprint5 import Sprint5TestCase


FIXTURE = json.loads(Path(__file__).with_name("fixtures").joinpath("audit2-cve-frozen.json").read_text(encoding="utf-8"))
TEAMS_DESKTOP_CVES = ("CVE-2023-29328", "CVE-2023-29330")
TEAMS_SOFTWARE = {"publisher": "Microsoft Corporation", "displayName": "Microsoft Teams",
                  "displayVersion": "1.4.00.32771", "architecture": "AMD64"}


def teams_desktop_records():
    # Minimal public NVD configuration and Microsoft affected-data projection.
    matches = [
        {"vulnerable": True, "criteria": build_cpe23("a", "microsoft", "teams", target_sw=platform),
         "versionEndExcluding": bound}
        for platform, bound in (("android", "1.0.0.2023070204"), ("macos", "1.6.00.17554"),
                                ("-", "1.6.00.18681"), ("iphone_os", "5.12.1"))
    ]
    return [{
        "id": cve_id,
        "sourceIdentifier": "secure@microsoft.com",
        "affected": [{"source": "secure@microsoft.com", "affectedData": [{
            "vendor": "Microsoft", "product": "Microsoft Teams for Desktop",
            "versions": [{"version": "1.0.0", "lessThan": "1.6.00.18681", "versionType": "custom", "status": "affected"}],
        }]}],
        "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": matches}]}],
    } for cve_id in TEAMS_DESKTOP_CVES]


class FrozenResolver:
    """Hold product identity constant so the comparison measures applicability."""

    def resolve(self, software):
        entry = next((row for row in FIXTURE["products"].values() if software.product.startswith(row["namePrefix"])), None)
        if entry is None:
            return None
        return CpeCandidate(build_cpe23("a", entry["vendor"], entry["product"]), software.product,
                            entry["vendor"], entry["product"], None, False, 100, CpeMatchStatus.EXACT, "LOCAL_MAPPING")


class FrozenNvd:
    def __init__(self, **_kwargs):
        self.session = SimpleNamespace(close=lambda: None)

    def get_cves(self, params):
        query = params.get("cpeName") or params.get("virtualMatchString", "")
        entry = next(row for row in FIXTURE["products"].values() if f":{row['vendor']}:{row['product']}:" in query)
        if "id" not in entry:
            return []
        match = {"vulnerable": True, "criteria": build_cpe23("a", entry["vendor"], entry["product"], target_sw=entry.get("targetSw", "*"))}
        for key, bound in (("endExcluding", "versionEndExcluding"), ("endIncluding", "versionEndIncluding")):
            if key in entry:
                match[bound] = entry[key]
        return [{"cve": {"id": entry["id"], "descriptions": [{"lang": "en", "value": "Synthetic audit2 range"}],
                         "configurations": [{"nodes": [{"cpeMatch": [match]}]}]}}]


class FrozenCna:
    name = "Synthetic CNA"

    def enrich(self, cve_id):
        if cve_id != FIXTURE["products"]["python"]["id"]:
            return None
        affected = parse_cna_affected([{
            "vendor": "Python", "product": "Python 3.12.4 Core Interpreter", "platforms": ["Windows x64"],
            "versions": [{"version": "3.12.4", "lessThan": "3.12.5", "versionType": "pep440", "status": "affected"}],
        }])
        return SourceEnrichment(cve_id=cve_id, source=SourceType.CVE_PROGRAM, affected=affected, raw_available=True)


def fixture_inventory(rows, **kwargs):
    with mock.patch("software.normalizer.log_unknown_product"):
        inventory = build_inventory(rows, **kwargs)
    # The harness pins existing identity for comparison. Production aliases and
    # eligibility thresholds remain independent of this source fixture.
    for software in inventory.products:
        software.confidence = 100
    return inventory


class Audit2CveTests(TestCase):
    def test_teams_classic_windows_range_requires_microsoft_desktop_evidence(self):
        product = build_inventory([TEAMS_SOFTWARE]).products[0]
        cpe = CpeCandidate(build_cpe23("a", "microsoft", "teams"), "Microsoft Teams",
                           "microsoft", "teams", None, False, 95, CpeMatchStatus.EXACT, "NVD")
        windows = {"OS": "Microsoft Windows 11 Pro"}
        for record in parse_cve_items(teams_desktop_records()):
            with self.subTest(cve=record.cve_id):
                self.assertEqual(evaluate_applicability_result(product, cpe, record, windows).status, ApplicabilityStatus.AFFECTED)
                for candidate, source, environment in (
                    (product, replace(record, affected=[]), windows),
                    (product, replace(record, source_identifier="other"), windows),
                    (product, record, {"OS": "unknown"}),
                    (replace(product, product="Microsoft Teams Meeting Add-in"), record, windows),
                ):
                    result = evaluate_applicability_result(candidate, cpe, source, environment)
                    self.assertEqual((result.status, result.reason_code),
                                     (ApplicabilityStatus.NOT_EVALUATED, "PLATFORM_UNKNOWN"))
                new_teams = replace(product, version="25122.1207.3700.1444")
                self.assertEqual(evaluate_applicability_result(new_teams, cpe, record, windows),
                                 evaluate_applicability_result(new_teams, cpe, replace(record, affected=[]), windows))
                desktop_only = replace(record, configurations=[{"cpeMatch": [record.configurations[0]["nodes"][0]["cpeMatch"][2]]}])
                for version in ("1.6.00.18681", "1.6.00.18682"):
                    result = evaluate_applicability_result(replace(product, version=version), cpe, desktop_only, windows)
                    self.assertEqual((result.status, result.reason_code),
                                     (ApplicabilityStatus.NOT_AFFECTED, "VERSION_OUTSIDE_RANGE"))

    def test_nvd_na_version_bound_is_distinct_from_unsupported_scheme(self):
        product = build_inventory([TEAMS_SOFTWARE]).products[0]
        cpe_name = build_cpe23("a", "microsoft", "teams")
        cpe = CpeCandidate(cpe_name, "Teams", "microsoft", "teams", None, False, 95, CpeMatchStatus.EXACT, "NVD")
        for bound, reason in (("-", "CPE_VERSION_NA"), ("2020-10-29", "VERSION_SCHEME_UNSUPPORTED")):
            match = {"vulnerable": True, "criteria": cpe_name, "versionEndExcluding": bound}
            record = parse_cve_items([{"id": "CVE-2099-56611", "configurations": [{"cpeMatch": [match]}]}])[0]
            result = evaluate_applicability_result(product, cpe, record)
            self.assertEqual((result.status, result.reason_code), (ApplicabilityStatus.NOT_EVALUATED, reason))

    def test_verified_python_msi_and_title_agreement(self):
        vendor = "Python Software Foundation"
        for title, version, interpreted, reason in [
            ("Python 3.12.4 Core Interpreter (64-bit)", "3.12.4150.0", "3.12.4", None),
            ("Python 3.14.2 (64-bit)", "3.14.2150.0", "3.14.2", None),
            ("Python 3.12.4 (64-bit)", "3.12.4", "3.12.4", None),
            ("Python 3.12.5rc1 (64-bit)", "3.12.5121.0", "3.12.5rc1", None),
            ("Python 3.12.5 (64-bit)", "3.12.4150.0", None, "VERSION_SOURCE_CONFLICT"),
            ("Python 3.12.5 (64-bit)", "3.12.4", None, "VERSION_SOURCE_CONFLICT"),
            ("Python", "3.12.4150.0", None, "VERSION_SCHEME_UNSUPPORTED"),
            ("Python 3.12.4 (64-bit)", "", None, "VERSION_UNAVAILABLE"),
        ]:
            with self.subTest(title=title, version=version):
                evidence = version_evidence(vendor, title, version)
                self.assertEqual((evidence.interpreted, evidence.reason), (interpreted, reason))
                self.assertEqual(evidence.raw, version)
        unrelated = version_evidence("Fixture Vendor", "Fixture Tool", "3.12.4150.0")
        self.assertEqual((unrelated.interpreted, unrelated.source), ("3.12.4150.0", "DISPLAY_VERSION"))
        conflict = fixture_inventory([{"publisher": vendor, "displayName": "Python 3.12.5 (64-bit)", "displayVersion": "3.12.4150.0"}])
        scan = CveService(client=FrozenNvd(), resolver=FrozenResolver()).scan_inventory(conflict)
        self.assertEqual((scan.eligible_products, scan.evaluated_products), (1, 0))
        self.assertEqual(scan.product_evaluations[0].terminal_reason_code, "VERSION_SOURCE_CONFLICT")

    def test_version_schemes_and_nonzero_build_boundary(self):
        compare = compare_applicability_versions
        self.assertEqual(compare("1.1.1k", "1.1.1t", "openssl").order, -1)
        self.assertEqual(compare("2.4.0-rc1", "2.4.0", "semver").order, -1)
        self.assertEqual(compare("2.4.0-rc.2", "2.4.0-rc.10", "semver").order, -1)
        self.assertEqual(compare("3.12.5rc1", "3.12.5", "cpython").order, -1)
        self.assertEqual(compare("1.1.1k", "1.1.1t").reason, "VERSION_SCHEME_UNSUPPORTED")
        self.assertEqual(compare("vendor-2026u2", "2026.3").reason, "VERSION_SCHEME_UNSUPPORTED")
        self.assertEqual(compare("10.9.1.20006", "10.9.1").reason, "VERSION_INCOMPARABLE")
        self.assertEqual(compare("10.9.1.0", "10.9.1").order, 0)
        inventory = fixture_inventory([{"publisher": "OpenSSL", "displayName": "OpenSSL", "displayVersion": value}
                                       for value in ("1.1.1k", "1.1.1t")])
        self.assertEqual(inventory.product_count, 2)

    def test_frozen_results_keep_identity_and_eligibility_constant(self):
        home, lab = [CveService(client=FrozenNvd(), resolver=FrozenResolver()).scan_inventory(
            fixture_inventory(row["software"]), {"OS": row["os"]}) for row in FIXTURE["endpoints"]]
        self.assertEqual([home.eligible_products, lab.eligible_products], [3, 3])
        self.assertEqual([home.evaluated_products, lab.evaluated_products], [1, 2])
        self.assertEqual([home.confirmed_vulnerabilities, lab.confirmed_vulnerabilities], [1, 0])
        self.assertEqual([item.reason_code for item in home.assessments], ["VERSION_MATCH", "VERSION_INCOMPARABLE"])
        self.assertEqual([item.reason_code for item in lab.assessments], ["VERSION_OUTSIDE_RANGE", "PLATFORM_MISMATCH_CONFIRMED"])
        self.assertEqual(home.product_evaluations[-1].terminal_reason_code, "NO_CVE_ROWS")
        self.assertEqual(home.product_evaluations[-1].provider_query_status, "SUCCESS")

    def test_nvd_product_architecture_and_platform_need_positive_evidence(self):
        row = FIXTURE["endpoints"][1]
        product = fixture_inventory(row["software"]).products[1]
        cpe = FrozenResolver().resolve(product)
        nvd = FrozenNvd()
        record = parse_cve_items(nvd.get_cves({"virtualMatchString": cpe.cpe_name}))[0]
        result = evaluate_applicability_result(product, cpe, record, {"OS": "vendor windows-like appliance"})
        self.assertEqual((result.status, result.reason_code), (ApplicabilityStatus.NOT_EVALUATED, "PLATFORM_UNKNOWN"))
        criteria = build_cpe23("a", cpe.vendor, cpe.product, version="1.4.0", target_hw="amd64")
        record = replace(record, configurations=[{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": criteria}]}]}])
        for architecture, expected in (("x64", "VERSION_MATCH"), (None, "ARCH_UNKNOWN"), ("ARM64", "ARCH_MISMATCH_CONFIRMED")):
            with self.subTest(architecture=architecture):
                result = evaluate_applicability_result(replace(product, architecture=architecture), cpe, record, {"Architecture": "AMD64"})
                self.assertEqual(result.reason_code, expected)

    def test_cna_semver_scope_and_explicit_default(self):
        product = fixture_inventory([{"publisher": "Fixture Vendor", "displayName": "Fixture Tool",
                                      "displayVersion": "2.4.0-rc1", "architecture": "AMD64"}]).products[0]
        entry = {"vendor": product.normalized_vendor, "product": product.normalized_product, "platforms": ["Windows x64"],
                 "versions": [{"version": "2.3.0", "lessThan": "2.4.0", "versionType": "semver", "status": "affected"}]}
        cna = parse_cna_affected([entry])
        self.assertEqual(evaluate_cna_applicability(product, cna, "Windows 11")[0], ApplicabilityStatus.AFFECTED)
        self.assertEqual(evaluate_cna_applicability(product, cna, None)[0], ApplicabilityStatus.NOT_EVALUATED)
        self.assertEqual(evaluate_cna_applicability(product, cna, "Linux")[0], ApplicabilityStatus.NOT_AFFECTED)
        fixed = replace(product, version="2.4.0")
        self.assertEqual(evaluate_cna_applicability(fixed, cna, "Windows 11")[0], ApplicabilityStatus.NOT_EVALUATED)
        self.assertEqual(evaluate_cna_applicability(fixed, parse_cna_affected([{**entry, "defaultStatus": "unaffected"}]), "Windows 11")[0],
                         ApplicabilityStatus.NOT_AFFECTED)

    def test_rep1_provider_success_does_not_complete_40_of_200(self):
        result = normalize_metadata({"providerStatus": "SUCCESS", "softwareCollectionStatus": "SUCCESS", "scanCompleted": True,
                                     "cveEligibleProducts": 200, "successfullyEvaluatedProducts": 40})
        self.assertEqual((result["providerStatus"], result["status"], result["coveragePercent"]), ("SUCCESS", "PARTIAL", 20.0))


class Audit2ReportTests(Sprint5TestCase):
    def test_teams_confirmed_cves_remain_visible_in_partial_report(self):
        service = SubmissionService(self.storage)
        pipeline = ConsoleAnalysisPipeline(self.storage)
        assessment = self.assessment.assessment_id
        evidence = self.evidence()
        evidence["operatingSystem"]["name"] = "Microsoft Windows 11 Pro"
        evidence["software"].update(items=[TEAMS_SOFTWARE], recordsCollected=1, collectionStatus="SUCCESS")
        submission = "SUB-TEAMS-SYNTHETIC"
        nonce = service.request_nonce(assessment, self.session.session_id, submission, self.token, "127.0.0.1")
        _, package, _ = service.accept(assessment_id=assessment, session_id=self.session.session_id,
            submission_id=submission, enrollment_token=self.token, nonce=nonce, source_address="127.0.0.1",
            archive_bytes=self.package(submission, nonce, evidence=evidence).read_bytes())
        pipeline.analyze(package)
        client = FrozenNvd()
        cpe_name = build_cpe23("a", "microsoft", "teams")
        unsupported = {"id": "CVE-2099-56611", "configurations": [{"cpeMatch": [
            {"vulnerable": True, "criteria": cpe_name, "versionEndExcluding": "2020-10-29"}]}]}
        client.get_cves = lambda _params: [*teams_desktop_records(), unsupported]
        cpe = CpeCandidate(cpe_name, "Microsoft Teams", "microsoft", "teams", None, False, 95, CpeMatchStatus.EXACT, "NVD")
        cve_service = CveService(client=client, resolver=SimpleNamespace(resolve=lambda _product: cpe))
        with mock.patch("analyzer.NvdClient", FrozenNvd), mock.patch("analyzer.NvdCache", side_effect=lambda: NvdCache(self.storage.root / "teams.sqlite3")), \
                mock.patch("analyzer.CveService", return_value=cve_service), mock.patch("analyzer._run_cve_enrichment"):
            result = pipeline.retry_analysis(assessment, submission, run_cve=True)
        self.assertEqual(result.cve_summary["status"], "PARTIAL")
        self.assertEqual(result.cve_summary["providerStatus"], "SUCCESS")
        self.assertEqual(result.cve_summary["confirmedCveIds"], list(TEAMS_DESKTOP_CVES))
        team = result.cve_summary["softwareResults"][0]
        self.assertEqual(team["cveEvaluationStatus"], "CONFIRMED")
        self.assertEqual(team["cvePipeline"]["terminalReasonCode"], "VERSION_SCHEME_UNSUPPORTED")
        html = UnifiedReportGenerator(self.storage).generate(assessment).read_text(encoding="utf-8")
        for cve_id in TEAMS_DESKTOP_CVES:
            self.assertIn(f"https://nvd.nist.gov/vuln/detail/{cve_id}", html)
        self.assertIn("Microsoft&#39;s affected Windows desktop range", html)

    def test_frozen_nvd_cna_evidence_to_unified_report(self):
        service = SubmissionService(self.storage)
        pipeline = ConsoleAnalysisPipeline(self.storage)
        assessment = self.assessment.assessment_id
        cve_service = CveService(client=FrozenNvd(), resolver=FrozenResolver())
        def offline_enrichment(context, *_args, **_kwargs):
            context.cve_enrichment = VulnerabilityEnrichmentService([FrozenCna()]).enrich_summary(context.cve_summary)

        for endpoint in FIXTURE["endpoints"]:
            evidence = self.evidence()
            evidence["software"].update(items=endpoint["software"], recordsCollected=len(endpoint["software"]), collectionStatus="SUCCESS")
            evidence["operatingSystem"]["name"] = endpoint["os"]
            settings = [row for row in evidence["security"]["settings"] if row["settingId"] != "BITLOCKER_OS_PROTECTION"]
            evidence["security"]["settings"] = settings + [shell_setting(endpoint["shell"])]
            submission = "SUB-" + endpoint["label"]
            nonce = service.request_nonce(assessment, self.session.session_id, submission, self.token, "127.0.0.1")
            _, package, _ = service.accept(assessment_id=assessment, session_id=self.session.session_id,
                submission_id=submission, enrollment_token=self.token, nonce=nonce, source_address="127.0.0.1",
                archive_bytes=self.package(submission, nonce, evidence=evidence).read_bytes())
            pipeline.analyze(package)
            # Use real normalization, NVD applicability, CNA enrichment and report
            # rendering. Only provider data and the fixture identities are pinned.
            with mock.patch("analyzer.NvdClient", FrozenNvd), mock.patch("analyzer.NvdCache", side_effect=lambda: NvdCache(self.storage.root / "audit2.sqlite3")), \
                    mock.patch("analyzer.CveService", return_value=cve_service), mock.patch("analyzer._run_cve_enrichment", side_effect=offline_enrichment), \
                    mock.patch("analyzer.build_inventory", side_effect=fixture_inventory):
                result = pipeline.retry_analysis(assessment, submission, run_cve=True)
            self.assertEqual(result.cve_summary["status"], "PARTIAL", result.cve_summary.get("assessmentReasonCode"))
            self.assertEqual(result.cve_summary["providerStatus"], "SUCCESS")

        generator = UnifiedReportGenerator(self.storage)
        model = generator.build_model(assessment)
        self.assertEqual(model["cve"]["status"], "PARTIAL")
        html = generator.generate(assessment).read_text(encoding="utf-8")
        self.assertIn("Interpreted version 3.12.4 (CPYTHON WINDOWS MSI)", html)
        self.assertIn("VERSION INCOMPARABLE", html)
        self.assertIn("NO CVE ROWS", html)
        self.assertIn("ON — Shell indication", html)
        self.assertIn("OFF — Shell field heuristic; verify", html)
        home = next(row for row in model["endpoints"] if row["submissionId"] == "SUB-HOME-SYNTHETIC")
        python = next(row for row in home["softwareResults"] if row["displayVersion"] == "3.12.4150.0")
        self.assertEqual(python["cveEvaluationStatus"], "CONFIRMED")
        self.assertEqual(python["cveDetails"][0]["sourceResolution"]["status"], "CORROBORATED")
