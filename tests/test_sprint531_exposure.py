"""Software Exposure acceptance: real per-product analyzer decisions to HTML."""

from __future__ import annotations

import re
import unittest
from html import unescape

from analyzer import _cve_product_key, _software_results
from csa_console.pipeline import ConsoleAnalysisPipeline
from csa_console.submission import SubmissionService
from csa_lab.unified_report import UnifiedReportGenerator, _software_matrix
from cve.models import (
    ApplicabilityStatus, CveAssessment, CveDataQuality, CveProductEvaluation,
    CveRecord,
)
from cve.service import _complete_evaluation
from software.models import (
    LifecycleResult, LifecycleStatus, SoftwareInventory, SoftwareProduct,
)
from tests.test_console_sprint5 import Sprint5TestCase


def analyzed_product(
    name: str,
    *,
    terminal: str = "COMPLETED",
    matches: tuple[str, ...] = (),
    scan_status: str = "PARTIAL",
    include_pipeline: bool = True,
) -> dict:
    """Supply typed pipeline evidence, never prefill cveEvaluationStatus."""

    eligible = terminal != "NOT_ELIGIBLE"
    product = SoftwareProduct(
        vendor="Fixture", product=name, version="2.4.2",
        normalized_vendor="fixture", normalized_product=name,
        normalized_version="2.4.2", confidence=100 if eligible else 40,
        normalization_status="NORMALIZED", discovery_eligible=eligible,
    )
    assessments = [
        CveAssessment(
            software=product, cpe=None,
            cve=CveRecord(
                cve_id=f"CVE-2026-{10000 + index}", description="Offline fixture",
                published=None, last_modified=None, cvss_version="3.1",
                cvss_score=7.5, severity="HIGH", vector=None, cwes=[],
                references=[], configurations=[], source_identifier=None,
                vuln_status="Analyzed", data_quality=CveDataQuality.COMPLETE,
            ),
            applicability=ApplicabilityStatus(match), reason="Offline fixture",
            confidence=100,
        )
        for index, match in enumerate(matches)
    ]
    pipeline = CveProductEvaluation(
        product_key=_cve_product_key(product), display_name=name, version="2.4.2",
        normalization_status=product.normalization_status,
        normalization_confidence=product.confidence,
        eligibility_status="ELIGIBLE" if eligible else "NOT_ELIGIBLE",
        terminal_status=terminal,
    )
    if terminal in {"COMPLETED", "PARTIAL"}:
        pipeline.product_mapping_status = "SUCCESS"
        pipeline.provider_query_status = "SUCCESS"
        # The production service derives version, result and terminal stages.
        _complete_evaluation(pipeline, assessments)
        assert pipeline.terminal_status == terminal
    elif terminal == "FAILED":
        pipeline.product_mapping_status = "SUCCESS"
        pipeline.provider_query_status = "FAILED"
        pipeline.failure_stage = "PROVIDER_QUERY"
    elif eligible:
        pipeline.product_mapping_status = "NO_RELIABLE_MAPPING"
        pipeline.failure_stage = "PRODUCT_MAPPING"
    lifecycle = LifecycleResult(
        vendor=product.vendor, product=name, installed_version="2.4.2",
        status=LifecycleStatus.SUPPORTED, end_of_support_date=None,
        source="Fixture", data_version="fixture", confidence=100,
        rationale="Offline lifecycle fixture",
    )
    return _software_results(
        SoftwareInventory(products=[product], product_count=1), assessments,
        [lifecycle], scan_status=scan_status, kev_ids=set(),
        product_evaluations=[pipeline] if include_pipeline else [],
    )[0]


def build_exposure_fixture(
    case: Sprint5TestCase, *, mixed: bool = True,
) -> UnifiedReportGenerator:
    """Persist genuine analyzer results alongside accepted endpoint evidence."""

    products = [
        analyzed_product("Unknown App", terminal="NOT_EVALUATED"),
        analyzed_product("Ineligible App", terminal="NOT_ELIGIBLE"),
        analyzed_product("Provider Failure", terminal="FAILED"),
        analyzed_product("Audacity"),
        analyzed_product("Vulnerable App", matches=("AFFECTED",)),
        analyzed_product("Possible App", matches=("POSSIBLY_AFFECTED",)),
        analyzed_product("Partial App", terminal="PARTIAL", matches=("NOT_EVALUATED",)),
        analyzed_product("Mixed Clean"),
        analyzed_product("Mixed Vulnerable", matches=("AFFECTED",)),
    ]
    endpoint_products = [products]
    if mixed:
        endpoint_products.append([
            analyzed_product("Mixed Clean", terminal="NOT_EVALUATED"),
            analyzed_product("Mixed Vulnerable", terminal="NOT_EVALUATED"),
        ])
    service = SubmissionService(case.storage)
    for index, rows in enumerate(endpoint_products, start=1):
        submission_id = f"SUB-EXPOSURE-{index}"
        evidence = case.evidence()
        evidence["device"]["hostname"] = f"EXPOSURE-{index}"
        evidence["device"]["computerName"] = f"EXPOSURE-{index}"
        nonce = service.request_nonce(
            case.assessment.assessment_id, case.session.session_id,
            submission_id, case.token, "127.0.0.1",
        )
        _, package, _ = service.accept(
            assessment_id=case.assessment.assessment_id,
            session_id=case.session.session_id, submission_id=submission_id,
            enrollment_token=case.token, nonce=nonce, source_address="127.0.0.1",
            archive_bytes=case.package(submission_id, nonce, evidence=evidence).read_bytes(),
        )
        ConsoleAnalysisPipeline(case.storage).analyze(package)
        findings = case.storage.read_json(
            case.assessment.assessment_id, "findings", f"{submission_id}.json",
        )
        findings["cveAnalysisStatus"] = "PARTIAL"
        findings["cveSummary"] = {
            "status": "PARTIAL", "softwareResults": rows,
            "installedSoftwareRecords": len(rows), "normalizedProducts": len(rows),
            "confirmedCveIds": ["CVE-2026-10000"] if index == 1 else [],
            "possibleCveIds": ["CVE-2026-10000"] if index == 1 else [],
        }
        case.storage.write_json(
            case.assessment.assessment_id, ("findings", f"{submission_id}.json"),
            findings,
        )
    return UnifiedReportGenerator(case.storage)


class ProductEvaluationTests(unittest.TestCase):
    def test_unknown_ineligible_and_failed_products_never_mean_clean(self):
        for terminal in ("NOT_EVALUATED", "NOT_ELIGIBLE", "FAILED"):
            for scan_status in ("COMPLETE", "PARTIAL"):
                with self.subTest(terminal=terminal, scan_status=scan_status):
                    product = analyzed_product("Unknown", terminal=terminal, scan_status=scan_status)
                    self.assertEqual(product["cveEvaluationStatus"], "NOT_EVALUATED")
                    row = _software_matrix([{"displayName": "HOME", "softwareResults": [product]}])["rows"][0]
                    self.assertEqual(row["cveStatus"], "Not evaluated")
                    self.assertIn("CVE not evaluated", row["risk"])
                    if terminal != "FAILED":
                        self.assertIn("Product not recognized", row["risk"])

    def test_completed_zero_is_clean_even_when_assessment_is_partial(self):
        product = analyzed_product("Audacity")
        self.assertEqual(product["cveEvaluationStatus"], "NO_KNOWN_VULNERABILITIES")
        self.assertEqual(product["securityStatus"], "None identified")

    def test_missing_pipeline_cannot_claim_clean_from_global_complete(self):
        product = analyzed_product("Missing pipeline", scan_status="COMPLETE", include_pipeline=False)
        self.assertEqual(product["cveEvaluationStatus"], "NOT_EVALUATED")

    def test_partial_assessment_preserves_confirmed_and_possible_findings(self):
        for match, expected in (("AFFECTED", "CONFIRMED"), ("POSSIBLY_AFFECTED", "POSSIBLE")):
            with self.subTest(match=match):
                product = analyzed_product("Known App", matches=(match,))
                self.assertEqual(product["cveEvaluationStatus"], expected)
                self.assertEqual(len(product["cveDetails"]), 1)
                self.assertEqual(product["cveDetails"][0]["matchStatus"], match)

    def test_unresolved_versions_remain_partial_and_preserve_confirmed_findings(self):
        for matches, status in ((("NOT_EVALUATED",), "Partially evaluated"), (("AFFECTED", "NOT_EVALUATED"), "1 confirmed · Partially evaluated")):
            with self.subTest(matches=matches):
                product = analyzed_product("Partial", terminal="PARTIAL", matches=matches)
                self.assertNotEqual(product["cveEvaluationStatus"], "NO_KNOWN_VULNERABILITIES")
                row = _software_matrix([{"displayName": "HOME", "softwareResults": [product]}])["rows"][0]
                self.assertEqual(row["cveStatus"], status)

    def test_mixed_endpoint_evaluation_is_explicit_in_both_input_orders(self):
        for matches, status in (((), "Partially evaluated"), (("AFFECTED",), "1 confirmed · Partially evaluated")):
            endpoints = [
                {"displayName": "A", "softwareResults": [analyzed_product("Same Product", matches=matches)]},
                {"displayName": "B", "softwareResults": [analyzed_product("Same Product", terminal="NOT_EVALUATED")]},
            ]
            for ordered in (endpoints, list(reversed(endpoints))):
                with self.subTest(matches=matches, first=ordered[0]["displayName"]):
                    row = _software_matrix(ordered)["rows"][0]
                    self.assertEqual(row["cveStatus"], status)
                    self.assertEqual(row["installedCount"], 2)


class ExposureHtmlTests(Sprint5TestCase):
    def test_generated_html_distinguishes_all_product_states(self):
        generator = build_exposure_fixture(self)
        html = generator.generate(self.assessment.assessment_id).read_text(encoding="utf-8")
        table = html.split('id="software-matrix"', 1)[1].split('</table>', 1)[0]
        rows = {
            unescape(name): unescape(status)
            for name, status in re.findall(
                r'<td data-label="Software"><strong>(.*?)</strong>.*?<td data-label="CVE status">(.*?)</td>',
                table,
            )
        }
        self.assertEqual(rows, {
            "Unknown App": "Not evaluated", "Ineligible App": "Not evaluated",
            "Provider Failure": "Not evaluated", "Audacity": "No known vulnerabilities found",
            "Vulnerable App": "1 confirmed", "Possible App": "1 possible",
            "Partial App": "Partially evaluated", "Mixed Clean": "Partially evaluated",
            "Mixed Vulnerable": "1 confirmed · Partially evaluated",
        })
        self.assertIn("9 software product/version entries across 2 endpoints", table)
        self.assertNotIn("normalized products", table)

    def test_single_endpoint_summary_uses_singular(self):
        generator = build_exposure_fixture(self, mixed=False)
        html = generator.generate(self.assessment.assessment_id).read_text(encoding="utf-8")
        self.assertIn("9 software product/version entries across 1 endpoint</span>", html)


if __name__ == "__main__":
    unittest.main()
