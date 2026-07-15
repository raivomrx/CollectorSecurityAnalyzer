"""Tests for Sprint 2.8 CVE enrichment."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import requests

from cve.cna_applicability import evaluate_cna_applicability
from cve.enrichment_models import (
    AffectedVersionRange,
    ExploitationStatus,
    RansomwareUse,
    SourceEnrichment,
    SourceType,
)
from cve.enrichment_service import VulnerabilityEnrichmentService
from cve.models import ApplicabilityStatus, CpeCandidate, CpeMatchStatus, CveAssessment, CveDataQuality, CveRecord, CveScanSummary
from cve.prioritization import PriorityLevel, calculate_priority
from cve.providers.cisa_kev import CisaKevProvider
from cve.providers.cve_program import cve_record_relative_path, parse_cna_affected, parse_cve_program_record
from cve.provenance import ConflictType
from report import generate_html_report
from risk import AuditFinding, Finding, Severity, Status
from knowledge.models import Knowledge
from rules.categories import RuleCategory
from rules.metadata import RuleMetadata
from software.models import SoftwareInventory, SoftwareProduct


class CisaKevProviderTests(unittest.TestCase):
    """Validate CISA KEV provider behavior."""

    def test_kev_match_non_match_optional_fields_and_ransomware(self) -> None:
        """Provider should parse KEV records and distinguish missing entries."""

        provider = CisaKevProvider(
            session=_Session([_Response(_kev_payload())]),
            cache_path=_temp_path("kev-cache.json"),
        )

        match = provider.enrich("CVE-2026-0001")
        missing = provider.enrich("CVE-2026-9999")

        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.kev.known_ransomware_campaign_use, RansomwareUse.KNOWN)
        self.assertEqual(provider.exploitation_status("CVE-2026-0001"), ExploitationStatus.KNOWN_EXPLOITED)
        self.assertIsNotNone(missing)
        assert missing is not None
        self.assertIsNone(missing.kev)
        self.assertEqual(provider.exploitation_status("CVE-2026-9999"), ExploitationStatus.NO_KEV_EVIDENCE)

    def test_kev_feed_error_and_stale_cache_fallback(self) -> None:
        """Provider should use stale cache when feed fails and stale is allowed."""

        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / "kev.json"
            cache_path.write_text(
                json.dumps(
                    {
                        "cached_at": "2020-01-01T00:00:00+00:00",
                        "data": _kev_payload(),
                    }
                ),
                encoding="utf-8",
            )
            provider = CisaKevProvider(
                session=_Session([requests.ConnectionError("offline")]),
                cache_path=cache_path,
                allow_stale_cache=True,
            )
            enrichment = provider.enrich("CVE-2026-0001")

        self.assertIsNotNone(enrichment)
        self.assertTrue(provider.status().used_stale_cache)

    def test_kev_malformed_json_is_unavailable(self) -> None:
        """Malformed feed without cache should fail open."""

        provider = CisaKevProvider(
            session=_Session([_Response(ValueError("bad json"))]),
            cache_path=_temp_path("missing-kev-cache.json"),
        )

        self.assertIsNone(provider.enrich("CVE-2026-0001"))
        self.assertFalse(provider.status().succeeded)


class CveProgramProviderTests(unittest.TestCase):
    """Validate CVE Program parsing."""

    def test_cvelist_path_builder(self) -> None:
        """Path builder should follow cvelistV5 bucket layout."""

        self.assertEqual(
            cve_record_relative_path("CVE-2021-44228").as_posix(),
            "2021/44xxx/CVE-2021-44228.json",
        )

    def test_parse_record_versions_containers_and_references(self) -> None:
        """Parser should tolerate supported 5.x variants and merge containers."""

        for version in ("5.0", "5.1", "5.1.1", "5.2", "5.2.0"):
            with self.subTest(version=version):
                enrichment = parse_cve_program_record(_cve_program_record(version))
                self.assertEqual(enrichment.cve_id, "CVE-2026-0001")
                self.assertEqual(enrichment.provider_short_name, "Vendor CNA")
                self.assertTrue(enrichment.affected)
                self.assertEqual(enrichment.affected[0].package_url, "pkg:generic/google/chrome")
                self.assertEqual(len(enrichment.references), 2)
                self.assertIsNotNone(enrichment.ssvc)

    def test_unknown_future_minor_and_unsupported_major(self) -> None:
        """Unknown 5.x should parse with warnings; unsupported major is unknown quality."""

        future = parse_cve_program_record(_cve_program_record("5.9"))
        unsupported = parse_cve_program_record(_cve_program_record("6.0"))

        self.assertTrue(future.warnings)
        self.assertEqual(unsupported.data_quality, CveDataQuality.UNKNOWN)

    def test_parse_cna_affected_missing_optional_fields(self) -> None:
        """Affected parser should tolerate missing optional fields."""

        affected = parse_cna_affected([{"product": "Google Chrome", "versions": [{"version": "1.0", "status": "affected"}]}])
        self.assertEqual(len(affected), 1)
        self.assertIsNone(affected[0].vendor)


class CnaApplicabilityTests(unittest.TestCase):
    """Validate CNA affected-version applicability."""

    def test_exact_less_than_less_than_equal_and_changes(self) -> None:
        """CNA evaluator should handle common version forms."""

        software = _software(version="2.0")
        exact = [_affected(version="2.0")]
        less_than = [_affected(version="1.0", less_than="3.0")]
        less_equal = [_affected(version="1.0", less_than_or_equal="2.0")]
        changed = [_affected(version="1.0", less_than="3.0", changes=[{"at": "2.0", "status": "unaffected"}])]

        self.assertEqual(evaluate_cna_applicability(software, exact)[0], ApplicabilityStatus.AFFECTED)
        self.assertEqual(evaluate_cna_applicability(software, less_than)[0], ApplicabilityStatus.AFFECTED)
        self.assertEqual(evaluate_cna_applicability(software, less_equal)[0], ApplicabilityStatus.AFFECTED)
        self.assertEqual(evaluate_cna_applicability(software, changed)[0], ApplicabilityStatus.NOT_AFFECTED)

    def test_unaffected_mismatch_platform_and_unparsable(self) -> None:
        """CNA evaluator should stay conservative on mismatches and bad versions."""

        self.assertEqual(evaluate_cna_applicability(_software(), [_affected(status="unaffected")])[0], ApplicabilityStatus.NOT_AFFECTED)
        self.assertEqual(evaluate_cna_applicability(_software(), [_affected(vendor="Other")])[0], ApplicabilityStatus.NOT_AFFECTED)
        self.assertEqual(evaluate_cna_applicability(_software(), [_affected(product="Other")])[0], ApplicabilityStatus.NOT_AFFECTED)
        self.assertEqual(evaluate_cna_applicability(_software(architecture="x64"), [_affected(platforms=["arm64"])])[0], ApplicabilityStatus.NOT_AFFECTED)
        self.assertEqual(evaluate_cna_applicability(_software(version="unknown"), [_affected()])[0], ApplicabilityStatus.NOT_EVALUATED)


class EnrichmentServiceTests(unittest.TestCase):
    """Validate enrichment orchestration and priority."""

    def test_enriches_one_cve_once_and_retains_conflict(self) -> None:
        """One CVE should be loaded once and source conflicts should remain visible."""

        provider = _Provider(
            SourceEnrichment(
                cve_id="CVE-2026-0001",
                source=SourceType.CVE_PROGRAM,
                affected=[_affected(status="unaffected")],
                raw_available=True,
            )
        )
        summary = _summary([_assessment(), _assessment(product="Google Chrome Beta")])
        enriched = VulnerabilityEnrichmentService([provider], enrich_not_affected=True).enrich_summary(summary)

        self.assertEqual(provider.calls, 1)
        self.assertEqual(enriched.conflict_count, 2)
        self.assertEqual(enriched.assessments[0].conflicts[0].conflict_type, ConflictType.AFFECTED_VERSION_DISAGREEMENT)
        self.assertTrue(enriched.assessments[0].provenance)

    def test_provider_failures_do_not_block_other_providers(self) -> None:
        """Provider errors should be isolated."""

        good = _Provider(SourceEnrichment(cve_id="CVE-2026-0001", source=SourceType.CISA_KEV, kev=_kev_record(), raw_available=True))
        enriched = VulnerabilityEnrichmentService([_FailingProvider(), good]).enrich_summary(_summary([_assessment()]))

        self.assertEqual(enriched.known_exploited_count, 1)

    def test_priority_model(self) -> None:
        """Priority model should remain separate from CVSS."""

        priority = calculate_priority(
            assessment=_assessment(cvss_score=9.8),
            exploitation_status=ExploitationStatus.KNOWN_EXPLOITED,
            ransomware_use=RansomwareUse.KNOWN,
            cna_applicability=ApplicabilityStatus.AFFECTED,
            conflicts=[],
        )

        self.assertEqual(priority.level, PriorityLevel.P1_IMMEDIATE)
        self.assertEqual(_assessment(cvss_score=9.8).cve.cvss_score, 9.8)


class EnrichedHtmlTests(unittest.TestCase):
    """Validate enriched report rendering."""

    def test_html_contains_priority_kev_conflict_and_provider_status(self) -> None:
        """Report should display enriched CVE information."""

        summary = _summary([_assessment()])
        enriched = VulnerabilityEnrichmentService(
            [_Provider(SourceEnrichment(cve_id="CVE-2026-0001", source=SourceType.CISA_KEV, kev=_kev_record(), raw_available=True))]
        ).enrich_summary(summary)
        with tempfile.TemporaryDirectory() as temp_dir:
            path = generate_html_report(
                data={"ComputerName": "EE-D3147"},
                audit_findings=[_audit_finding()],
                score=80,
                software_inventory=SoftwareInventory(),
                rule_metadata={"CVE-001": _rule_metadata()},
                cve_summary=summary,
                cve_enrichment=enriched,
                output_path=Path(temp_dir) / "report.html",
            )
            html = path.read_text(encoding="utf-8")

        self.assertIn("KNOWN EXPLOITED", html)
        self.assertIn("P1_IMMEDIATE", html)
        self.assertIn("Provider Status", html)
        self.assertIn("required action", html)


def _software(version: str = "2.0", architecture: str | None = None) -> SoftwareProduct:
    """Create test software."""

    return SoftwareProduct(
        vendor="Google LLC",
        product="Google Chrome",
        version=version,
        normalized_vendor="Google",
        normalized_product="Google Chrome",
        normalized_version=version,
        architecture=architecture,
        confidence=100,
    )


def _affected(
    vendor: str | None = "Google",
    product: str | None = "Google Chrome",
    version: str | None = "2.0",
    status: str | None = "affected",
    less_than: str | None = None,
    less_than_or_equal: str | None = None,
    changes: list[dict[str, str]] | None = None,
    platforms: list[str] | None = None,
) -> AffectedVersionRange:
    """Create an affected range."""

    return AffectedVersionRange(
        vendor=vendor,
        product=product,
        package_name=None,
        package_url=None,
        version=version,
        status=status,
        version_type="semver",
        less_than=less_than,
        less_than_or_equal=less_than_or_equal,
        changes=changes or [],
        platforms=platforms or [],
        modules=[],
        source=SourceType.CNA,
    )


def _assessment(product: str = "Google Chrome", cvss_score: float = 9.8) -> CveAssessment:
    """Create an affected assessment."""

    software = _software()
    software.product = product
    return CveAssessment(
        software=software,
        cpe=CpeCandidate("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", "Chrome", "google", "chrome", None, False, 100, CpeMatchStatus.EXACT, "LOCAL"),
        cve=CveRecord(
            cve_id="CVE-2026-0001",
            description="Example",
            published=None,
            last_modified=None,
            cvss_version="3.1",
            cvss_score=cvss_score,
            severity="CRITICAL",
            vector=None,
            cwes=[],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2026-0001"],
            configurations=[],
            source_identifier="nvd",
            vuln_status="Analyzed",
            data_quality=CveDataQuality.COMPLETE,
        ),
        applicability=ApplicabilityStatus.AFFECTED,
        reason="affected",
        confidence=95,
    )


def _summary(assessments: list[CveAssessment]) -> CveScanSummary:
    """Create a CVE summary."""

    return CveScanSummary(
        scanned_products=len(assessments),
        unique_products=len(assessments),
        eligible_products=len(assessments),
        evaluated_products=len(assessments),
        coverage_percent=100.0,
        coverage_complete=True,
        products_with_cpe=len(assessments),
        products_without_cpe=0,
        ambiguous_cpe_matches=0,
        confirmed_vulnerabilities=len(assessments),
        possible_vulnerabilities=0,
        not_evaluated=0,
        api_errors=0,
        assessments=assessments,
        errors=[],
        scan_complete=True,
    )


def _kev_record():
    """Create a KEV record."""

    from cve.enrichment_models import KevRecord

    return KevRecord(
        cve_id="CVE-2026-0001",
        vendor_project="Google",
        product="Chrome",
        vulnerability_name="Chrome issue",
        date_added=None,
        short_description="Exploited",
        required_action="required action",
        due_date=None,
        known_ransomware_campaign_use=RansomwareUse.KNOWN,
        notes=None,
        cwes=[],
    )


def _kev_payload() -> dict:
    """Create KEV feed payload."""

    return {
        "catalogVersion": "2026.1",
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-0001",
                "vendorProject": "Google",
                "product": "Chrome",
                "vulnerabilityName": "Chrome issue",
                "dateAdded": "2026-01-01",
                "shortDescription": "Exploited",
                "requiredAction": "required action",
                "knownRansomwareCampaignUse": "Known",
                "cwes": ["CWE-79"],
            },
            {"cveID": "CVE-2026-0001", "vulnerabilityName": "Duplicate"},
            {"cveID": "CVE-2026-0002", "knownRansomwareCampaignUse": "FutureValue"},
        ],
    }


def _cve_program_record(version: str) -> dict:
    """Create CVE Program fixture payload."""

    return {
        "dataVersion": version,
        "cveMetadata": {
            "cveId": "CVE-2026-0001",
            "dateUpdated": "2026-01-01T00:00:00Z",
        },
        "containers": {
            "cna": {
                "providerMetadata": {"shortName": "Vendor CNA"},
                "title": "Example CVE",
                "descriptions": [{"lang": "en", "value": "Description"}],
                "affected": [
                    {
                        "vendor": "Google",
                        "product": "Google Chrome",
                        "packageURL": "pkg:generic/google/chrome",
                        "versions": [{"version": "1.0", "status": "affected", "lessThan": "3.0"}],
                    }
                ],
                "problemTypes": [{"descriptions": [{"cweId": "CWE-79"}]}],
                "metrics": [{"cvssV3_1": {"baseScore": 9.8}}],
                "references": [{"url": "https://vendor.example/advisory", "tags": ["vendor-advisory"]}],
            },
            "cveProgram": {
                "references": [{"url": "https://vendor.example/advisory"}],
            },
            "adp": [
                {
                    "providerMetadata": {"shortName": "CISA ADP"},
                    "metrics": [
                        {
                            "other": {
                                "content": {
                                    "ssvc": {
                                        "decision": "Act",
                                        "timestamp": "2026-01-01T00:00:00Z",
                                        "options": {
                                            "exploitation": "active",
                                            "automatable": "yes",
                                            "technicalImpact": "total",
                                        },
                                    }
                                }
                            }
                        }
                    ],
                    "references": [{"url": "https://cisa.example/kev"}],
                }
            ],
        },
    }


def _audit_finding() -> AuditFinding:
    """Create a test audit finding."""

    return AuditFinding(
            finding=Finding(
                rule_id="CVE-001",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                score=30,
                evidence={},
            ),
        knowledge=Knowledge(
            id="CVE-001",
            title="Known vulnerabilities",
            description="desc",
            risk="risk",
            recommendation="fix",
            frameworks={},
            references=[],
            knowledge_version="test",
        ),
    )


def _rule_metadata() -> RuleMetadata:
    """Create test rule metadata."""

    return RuleMetadata("CVE-001", "Known Vulnerabilities", "1.0", "CSA", RuleCategory.SOFTWARE, Severity.HIGH, True, "desc")


class _Provider:
    """Test provider."""

    name = "Provider"

    def __init__(self, enrichment: SourceEnrichment) -> None:
        self.enrichment = enrichment
        self.calls = 0

    def enrich(self, cve_id: str):
        self.calls += 1
        return self.enrichment

    def status(self):
        from cve.enrichment_models import ProviderStatus

        return ProviderStatus(self.name, True, True, False, self.calls, None)


class _FailingProvider:
    """Provider that fails."""

    name = "Failing"

    def enrich(self, cve_id: str):
        raise RuntimeError("failed")

    def status(self):
        from cve.enrichment_models import ProviderStatus

        return ProviderStatus(self.name, True, False, False, 0, "failed")


class _Session:
    """Fake HTTP session."""

    def __init__(self, responses: list[object]) -> None:
        self.responses = responses

    def get(self, *args, **kwargs):
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class _Response:
    """Fake HTTP response."""

    def __init__(self, payload, status_code: int = 200) -> None:
        self.payload = payload
        self.status_code = status_code

    def json(self):
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))


def _temp_path(name: str) -> Path:
    """Return a temp path that does not need to exist yet."""

    return Path(tempfile.gettempdir()) / f"csa-{datetime.now(timezone.utc).timestamp()}-{name}"


if __name__ == "__main__":
    unittest.main()
