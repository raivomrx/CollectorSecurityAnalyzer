"""Synthetic report regressions for counting units and evidence limitations."""
import copy
import hashlib
import json
import re
import time
from html.parser import HTMLParser
from unittest import TestCase
from unittest import mock

from csa_console.pipeline import ConsoleAnalysisPipeline
from csa_console.submission import SubmissionService
from csa_lab.bitlocker_presentation import bitlocker_presentation
from csa_lab.unified_report import UnifiedReportGenerator, _finding_observations, _software_security_findings
from evidence.bitlocker import resolve_bitlocker
from knowledge.repository import KnowledgeRepository
from risk import AuditFinding, Finding, Severity, Status
from tests.test_bitlocker_boundaries import shell_setting
from tests.test_console_sprint5 import Sprint5TestCase
from tests.test_sprint531_exposure import analyzed_product
from tests.test_sprint531_semantics import bitlocker_setting
from tests.test_effective_admin_membership import membership_settings


def clarity_software(endpoint):
    """Build 219 source rows, 200 eligible instances and 231 CVE relationships."""
    rows = []
    full = 15 if endpoint == 0 else 14
    count = 110 if endpoint == 0 else 109
    for index in range(count):
        identity = index if endpoint == 0 or index < 63 else index + 47
        terminal = "NOT_ELIGIBLE" if index >= 100 else (
            "COMPLETED" if index < full else "PARTIAL" if index < full + 21 else "NOT_EVALUATED"
        )
        ids = [f"CVE-2099-{70000 + number % 206}" for number in range(index, 231, 20)] if endpoint == 0 and index < 20 else []
        matches = tuple(["AFFECTED"] * len(ids) + (["NOT_EVALUATED"] if terminal == "PARTIAL" else []))
        row = analyzed_product(f"Fixture Product {identity:03}", terminal=terminal, matches=matches)
        row["lifecycleStatus"] = "NOT_EVALUATED"
        for detail, cve_id in zip(row["cveDetails"], ids):
            detail["cveId"] = cve_id
            detail["cisaKev"] = cve_id == "CVE-2099-70000"
        rows.append(row)
    return rows


def prepare_clarity_report(case):
    """Exercise acceptance and rendering using only synthetic endpoint inputs."""
    assessment = case.assessment.assessment_id
    service = SubmissionService(case.storage)
    for index, raw in enumerate((0, 1)):
        submission = f"SUB-CLARITY-{index}"
        evidence = case.evidence()
        rows = clarity_software(index)
        evidence["software"].update(
            collectionStatus="SUCCESS", recordsCollected=len(rows),
            items=[{"displayName": row["displayName"], "publisher": row["publisher"],
                    "displayVersion": row["displayVersion"]} for row in rows],
        )
        evidence["device"]["hostname"] = f"id-{'1' if index == 0 else '2'}" + "0" * 11
        evidence["device"]["windowsHelloProvisioned"] = True
        evidence["device"]["domainJoined"] = False
        evidence["privilegeContext"]["isLocalAdministratorMember"] = True
        membership = membership_settings("INHERITED", sid=f"id-{index + 1:012d}", classification="LOCAL")
        membership_ids = {row["settingId"] for row in membership}
        for section in evidence.values():
            if isinstance(section, dict) and isinstance(section.get("settings"), list):
                section["settings"] = [row for row in section["settings"] if row.get("settingId") not in membership_ids]
                for row in section["settings"]:
                    if row.get("settingId") == "PASSWORD_POLICY_MIN_LENGTH":
                        row.update(effectiveValue=0, configuredValue=0)
        settings = evidence["security"]["settings"]
        bitlocker = shell_setting(raw)
        bitlocker["metadata"]["fallbacksAttempted"] = [{
            "provider": "Get-BitLockerVolume", "status": "ERROR", "errorCategory": "ACCESS_DENIED",
            "observedAt": "2026-11-05T07:00:00Z", "volume": "C:",
        }]
        evidence["security"]["settings"] = [row for row in settings if not row["settingId"].startswith("BITLOCKER_")] + [bitlocker] + membership
        for capability in evidence["capabilityResults"]:
            if capability["capabilityId"] == "COL-BITLOCKER-STATUS-001":
                capability.update(status="NOT_COLLECTED_ERROR", evidenceCount=0, limitationCode="PROVIDER_ERROR")
        nonce = service.request_nonce(assessment, case.session.session_id, submission, case.token, "127.0.0.1")
        with mock.patch.object(case, "capability_results", return_value=evidence["capabilityResults"]):
            archive = case.package(submission, nonce, evidence=evidence).read_bytes()
        _, package, _ = service.accept(assessment_id=assessment, session_id=case.session.session_id,
            submission_id=submission, enrollment_token=case.token, nonce=nonce, source_address="127.0.0.1",
            archive_bytes=archive)
        with mock.patch("software.normalizer.log_unknown_product"):
            ConsoleAnalysisPipeline(case.storage).analyze(package)
        findings = case.storage.read_json(assessment, "findings", submission + ".json")
        # A report fixture supplies a known assessment outcome independently
        # of the CVE provider outcome, without re-evaluating controls here.
        findings["coverage"]["overallCoveragePercent"] = 71.7
        findings["cveAnalysisStatus"] = "PARTIAL"
        confirmed = sorted({detail["cveId"] for row in rows for detail in row["cveDetails"] if detail["matchStatus"] == "AFFECTED"})
        full = 15 if index == 0 else 14
        findings["cveSummary"].update({
            "status": "PARTIAL", "providerStatus": "SUCCESS", "scanCompleted": True,
            "softwareCollectionStatus": "SUCCESS", "cveEligibleProducts": 100,
            "successfullyEvaluatedProducts": full, "notEvaluatedProducts": 100 - full,
            "coveragePercent": float(full), "coverageComplete": False,
            "confirmedCveIds": confirmed, "confirmedUniqueCves": len(confirmed),
            "confirmedProductCveRelationships": sum(row["confirmedCves"] for row in rows),
            "softwareResults": rows, "productEvaluations": [row["cvePipeline"] for row in rows],
        })
        for row in findings["findings"]:
            if row["finding"]["rule_id"] == "SW-001":
                row["finding"].update(status="NOT_EVALUATED", evidence={
                    "reason": "Synthetic provider identities are supplied by the report fixture.",
                })
            if row["finding"]["rule_id"] == "AV-001":
                row["finding"].update(status="PARTIAL", evidence={
                    "active_product": "Microsoft Defender", "active_protection_confirmed": True,
                    "freshness_status": "SOURCE_CONFLICT", "freshness_conflict": True,
                    "reason": "Synthetic signature freshness providers disagree.",
                })
        for rule_id, recommendation, observed in (
            ("ACC-011", "Review the synthetic execution account's administrator-group assignments.", {"isLocalAdministratorMember": True, "isElevated": False}),
            ("DEF-004", "Review cloud-delivered protection using the approved policy.", {"cloud_protection": False}),
            ("DEF-005", "Configure potentially unwanted application protection using the approved policy.", {"pua_protection": False}),
        ):
            row = AuditFinding(Finding(rule_id, Severity.HIGH, Status.FAIL, evidence=observed),
                               KnowledgeRepository().get(rule_id)).to_dict()
            if rule_id == "ACC-011":
                row = next(item for item in findings["findings"] if item["finding"]["rule_id"] == rule_id)
            row["knowledge"]["recommendation"] = recommendation
            findings["findings"] = [item for item in findings["findings"] if item["finding"]["rule_id"] != rule_id] + [row]
        case.storage.write_json(assessment, ("findings", submission + ".json"), findings)
    case.storage.write_json(assessment, ("lab-state.json",), {
        "organization": "Synthetic report review",
        "description": "Synthetic õäöü report. Release HOLD. No live customer evidence.",
    })
    return UnifiedReportGenerator(case.storage)


class LinkIndex(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.links = []

    def handle_starttag(self, tag, attrs):
        data = dict(attrs)
        if "id" in data:
            self.ids.append(data["id"])
        if data.get("href", "").startswith("#"):
            self.links.append(data["href"][1:])


class BitLockerPresentationTests(TestCase):
    def test_fleet_cve_group_keeps_each_endpoint_observation_count(self):
        rows = [
            {"displayName": "Fixture A", "submissionId": "SUB-A", "anchorId": "endpoint-a", "softwareResults": [analyzed_product("Shared fixture", matches=("AFFECTED", "AFFECTED"))]},
            {"displayName": "Fixture B", "submissionId": "SUB-B", "anchorId": "endpoint-b", "softwareResults": [analyzed_product("Shared fixture", matches=("AFFECTED",))]},
        ]
        finding = _software_security_findings(rows)[0]
        observations = _finding_observations(finding, rows)
        self.assertEqual(len(observations[0]["evidence"]["confirmedCveIds"]), 2)
        self.assertEqual(len(observations[1]["evidence"]["confirmedCveIds"]), 1)

    def test_shared_adapter_retains_verified_states_and_indications(self):
        encrypted_off = bitlocker_setting(False)
        encrypted_off["metadata"].update(encryptionState="FULLY_ENCRYPTED", encryptionPercentage=100)
        converting = bitlocker_setting(True)
        converting["metadata"].update(encryptionState="ENCRYPTION_IN_PROGRESS", encryptionPercentage=48)
        conflict = bitlocker_setting(True)
        conflict["metadata"]["encryptionState"] = "SOURCE_CONFLICT"
        for setting, reported, confirmed, unresolved in (
            (shell_setting(1), True, False, True), (shell_setting(0), False, False, True),
            (bitlocker_setting(True), True, True, False), (bitlocker_setting(False), False, False, False),
            (encrypted_off, False, False, False), (converting, True, False, True),
            (conflict, False, False, True), (None, False, False, True),
        ):
            result = resolve_bitlocker(setting)
            view = bitlocker_presentation(result)
            self.assertEqual((view["reportedOn"], view["confirmedProtected"], view["unresolved"]),
                             (reported, confirmed, unresolved))
            if unresolved:
                self.assertNotIn("Enable BitLocker", view["recommendation"])


class ReportClarityTests(Sprint5TestCase):
    def test_two_endpoint_counts_report_and_integrity(self):
        generator = prepare_clarity_report(self)
        model = generator.build_model(self.assessment.assessment_id)
        metrics = model["executiveEndpointMetrics"]
        self.assertEqual((metrics["bitLockerReportedOnEndpoints"], metrics["bitLockerEnabledEndpoints"],
                          metrics["bitLockerUnresolvedEndpoints"]), (1, 0, 2))
        intelligence = model["softwareIntelligence"]
        for key, count in (("softwareRecordsDiscovered", 219), ("cveEligible", 200), ("cveEvaluated", 29),
                           ("cveEligiblePartial", 42), ("cveEligibleNotEvaluated", 129),
                           ("nonEligibleOrUnsupported", 19), ("allSoftwareNotCompleted", 190),
                           ("cveEligibleFailed", 0), ("lifecycleEvaluated", 0),
                           ("confirmedVulnerableProducts", 20)):
            self.assertEqual(intelligence[key], count, key)
        self.assertEqual(model["cve"]["confirmedUniqueCves"], 206)
        self.assertEqual(model["cve"]["status"], "PARTIAL")
        self.assertEqual(model["coverage"]["corePassiveCoverage"], 71.7)
        self.assertEqual(model["cve"]["confirmedProductCveRelationships"], 231)
        self.assertEqual(len(model["findings"]), 35)
        self.assertEqual(len(model["remediationPlan"]), 30)
        self.assertEqual(model["controlResults"]["total"], 134)
        self.assertEqual(model["softwareVulnerabilityEvaluation"]["percent"], 14.5)
        self.assertEqual(len(model["softwareMatrix"]["rows"]), 156)
        self.assertEqual(model["malwareProtection"]["activeCoverageEndpoints"], 2)
        self.assertEqual(model["malwareProtection"]["healthyPostureEndpoints"], 0)
        self.assertEqual(model["malwareProtection"]["statusCounts"].get("PARTIAL"), 2)
        self.assertEqual(model["administrativePrivileges"]["affectedEndpoints"], 2)
        self.assertEqual(model["administrativePrivileges"]["elevatedCollectorProcesses"], 0)
        for endpoint in model["endpoints"]:
            limitation = next(row for row in endpoint["coverageLimitations"] if row["capabilityId"] == "COL-BITLOCKER-STATUS-001")
            self.assertEqual(limitation["reason"], "PROVIDER_ERROR")
            self.assertEqual(endpoint["bitLocker"]["providerAttempts"][0]["errorCategory"], "ACCESS_DENIED")
            self.assertEqual(endpoint["administrativePrivileges"]["tokenState"], "UAC_FILTERED_DENY_ONLY")
            self.assertEqual(endpoint["identityPosture"]["mfa"]["state"], "NOT_EVALUATED")
            self.assertEqual(endpoint["identityPosture"]["passwordPolicy"]["minimumLength"], 0)
            self.assertEqual(endpoint["identityPosture"]["passwordPolicy"]["scope"], "LOCAL_POLICY")
        kev_actions = [row for row in model["remediationPlan"] if "CVE-2099-70000" in row["relatedFindings"]]
        self.assertTrue(kev_actions)
        self.assertTrue(all(row["priority"] == "P1" for row in kev_actions))
        report = generator.generate(self.assessment.assessment_id)
        html = report.read_text(encoding="utf-8")
        self.assertIn("<strong>1 / 2</strong>", html)
        self.assertIn("0 confirmed protected / 2 unresolved", html)
        self.assertIn("Software lifecycle NOT EVALUATED", html)
        self.assertIn("171/200 eligible instances incomplete", html)
        self.assertIn("231 affected software-version/CVE relationships", html)
        self.assertIn("No capture or relay was performed", html)
        self.assertIn("õäöü", html)
        index = LinkIndex()
        index.feed(html)
        self.assertEqual(len(index.ids), len(set(index.ids)))
        self.assertFalse(set(index.links) - set(index.ids), set(index.links) - set(index.ids))
        sidecar = json.loads(report.with_suffix(".integrity.json").read_text(encoding="utf-8"))
        self.assertEqual("sha256:" + hashlib.sha256(report.read_bytes()).hexdigest(), sidecar["reportDigest"])
        self.assertNotEqual("sha256:" + hashlib.sha256(report.read_bytes() + b"changed").hexdigest(), sidecar["reportDigest"])
        self.assertTrue(all(row["relatedFindingLinks"] for row in model["remediationPlan"]))

    def test_scaled_offline_report_keeps_unique_ids_and_escapes_values(self):
        generator = prepare_clarity_report(self)
        original = generator.build_model(self.assessment.assessment_id)
        for count in (1, 2, 10, 50, 100):
            model = copy.deepcopy(original)
            model["endpoints"] = [copy.deepcopy(original["endpoints"][0]) for _ in range(count)]
            for number, endpoint in enumerate(model["endpoints"]):
                endpoint["anchorId"] = f"scale-endpoint-{number}"
                endpoint["displayName"] = f"õäöü <script>scale-{number}</script>"
                endpoint["softwareResults"] = []
                endpoint["securityFindings"] = []
                endpoint["softwareSecurityFindings"] = []
            started = time.perf_counter()
            html = generator.environment.get_template("unified.html").render(model=model, inline_style="", inline_script="")
            self.assertLess(time.perf_counter() - started, 15)
            self.assertIn("BitLocker protection reported ON (not necessarily verified)", html)
            self.assertIn("Recollect the required evidence and reevaluate", html)
            self.assertIn("Verification per accepted submission", html)
            for number in range(count):
                self.assertNotIn(f"<script>scale-{number}</script>", html)
            ids = LinkIndex()
            ids.feed(html)
            self.assertEqual(len(ids.ids), len(set(ids.ids)), count)
            self.assertEqual(len(re.findall(r'<tr[^>]+data-kind="endpoint"', html)), count)
