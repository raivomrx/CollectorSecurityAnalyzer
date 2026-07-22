"""Tests for versioned framework content packs and evaluation."""

from __future__ import annotations

import csv
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from frameworks.comparison import compare_packs
from frameworks.coverage import calculate_coverage
from frameworks.enums import (
    AutomationCapability,
    FrameworkControlLevel,
    FrameworkControlStatus,
    MappingStatus,
    MappingStrength,
    PackStatus,
    ReviewMethod,
    ReviewPendingReason,
)
from frameworks.evaluator import FrameworkEvaluator
from frameworks.exceptions import FrameworkPackError
from frameworks.import_cis_mapping import import_cis_mapping
from frameworks.loader import load_json_document, load_pack
from frameworks.models import (
    AssessmentPolicy,
    FrameworkControl,
    FrameworkPack,
    FrameworkSource,
    RuleMapping,
)
from frameworks.registry import FrameworkPackRegistry
from frameworks.serialization import write_analysis_json
from frameworks.validation import FrameworkPackValidator
from knowledge.models import Knowledge
from report import generate_html_report
from risk import AuditFinding, Finding, Severity, Status
from rules.loader import load_registry
from software.models import SoftwareInventory

ROOT = Path(__file__).resolve().parents[1]


class FrameworkPackLoadingTests(unittest.TestCase):
    """Validate bundled pack loading and registry behavior."""

    def test_all_bundled_packs_load_with_valid_digests(self) -> None:
        """Every registered pack should pass digest and semantic validation."""

        registry = FrameworkPackRegistry()
        validator = FrameworkPackValidator(load_registry(log_startup=False))
        packs = [
            registry.resolve(entry.framework_id, entry.version)
            for entry in registry.list(include_archived=True)
        ]

        self.assertEqual(len(packs), 4)
        self.assertEqual([error for pack in packs for error in validator.validate(pack)], [])

    def test_registry_requires_exact_version_when_no_active_pack_exists(self) -> None:
        """Latest must not select review-required or draft content."""

        registry = FrameworkPackRegistry()

        self.assertEqual(registry.resolve("EITS", "2026").status, PackStatus.REVIEW_REQUIRED)
        self.assertEqual(
            registry.resolve("CIS_WINDOWS_11_ENTERPRISE", "5.0.1").status,
            PackStatus.DRAFT,
        )
        with self.assertRaises(FrameworkPackError):
            registry.resolve("CIS_WINDOWS_11_ENTERPRISE")
        with self.assertRaises(FrameworkPackError):
            registry.resolve("EITS")

    def test_duplicate_json_keys_are_rejected(self) -> None:
        """Duplicate JSON keys must not silently override security metadata."""

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "duplicate.json"
            path.write_text('{"frameworkId":"A","frameworkId":"B"}', encoding="utf-8")
            with self.assertRaises(FrameworkPackError):
                load_json_document(path)

    def test_modified_pack_fails_digest_verification(self) -> None:
        """A content change without rehashing should be detected."""

        source = ROOT / "frameworks" / "eits" / "2026" / "pack.json"
        document = json.loads(source.read_text(encoding="utf-8"))
        document["name"] = "Tampered"
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "pack.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(FrameworkPackError):
                load_pack(path)

    def test_release_validation_rejects_provisional_mappings(self) -> None:
        """The review gate must fail pending mappings."""

        pack = FrameworkPackRegistry().resolve("EITS", "2026")
        errors = FrameworkPackValidator(load_registry(log_startup=False)).validate(
            pack,
            require_reviewed=True,
        )

        self.assertTrue(any("not reviewed" in error for error in errors))

    def test_validated_mapping_requires_provenance(self) -> None:
        """Validated status without review provenance should be invalid."""

        mapping = replace(
            _mapping(),
            status=MappingStatus.VALIDATED,
            reviewer=None,
            reviewed_at=None,
            source_reference=None,
        )
        pack = _pack(_control(mappings=(mapping,)))

        errors = FrameworkPackValidator().validate(pack)

        self.assertTrue(any("lacks a reviewer" in error for error in errors))
        self.assertTrue(any("lacks a review date" in error for error in errors))
        self.assertTrue(any("lacks a source reference" in error for error in errors))

    def test_unknown_rule_id_is_rejected(self) -> None:
        """Mappings may only reference known CSA rules."""

        pack = _pack(_control(mappings=(replace(_mapping(), rule_id="NO-SUCH-RULE"),)))
        errors = FrameworkPackValidator(load_registry(log_startup=False)).validate(pack)

        self.assertIn("Unknown rule ID: NO-SUCH-RULE", errors)

    def test_schema_documents_are_valid_json(self) -> None:
        """All published schemas should be parseable draft 2020-12 documents."""

        paths = sorted((ROOT / "frameworks" / "schema").glob("*.schema.json"))
        documents = [json.loads(path.read_text(encoding="utf-8")) for path in paths]

        self.assertEqual(len(documents), 3)
        self.assertTrue(all(item["$schema"].endswith("2020-12/schema") for item in documents))


class FrameworkEvaluatorTests(unittest.TestCase):
    """Validate conservative control evaluation semantics."""

    def test_direct_pass_satisfies_technical_control(self) -> None:
        """All validated direct mappings passing should satisfy a technical control."""

        result = _evaluate(Status.PASS).results[0]

        self.assertEqual(result.status, FrameworkControlStatus.SATISFIED)
        self.assertEqual(result.passed_rule_ids, ("BIT-001",))

    def test_direct_fail_does_not_satisfy_control(self) -> None:
        """A failing direct mapping should make the control not satisfied."""

        result = _evaluate(Status.FAIL).results[0]

        self.assertEqual(result.status, FrameworkControlStatus.NOT_SATISFIED)
        self.assertEqual(result.failed_rule_ids, ("BIT-001",))

    def test_missing_direct_evidence_is_not_assessable(self) -> None:
        """Missing findings must never be interpreted as passing evidence."""

        pack = _pack(_control())
        result = FrameworkEvaluator().evaluate(pack, []).results[0]

        self.assertEqual(result.status, FrameworkControlStatus.NOT_ASSESSABLE)
        self.assertEqual(result.unavailable_rule_ids, ("BIT-001",))

    def test_supporting_evidence_alone_never_satisfies(self) -> None:
        """Supporting evidence cannot produce SATISFIED."""

        mapping = replace(_mapping(), strength=MappingStrength.SUPPORTING)
        pack = _pack(_control(mappings=(mapping,)))
        result = FrameworkEvaluator().evaluate(pack, [_finding(Status.PASS)]).results[0]

        self.assertEqual(result.status, FrameworkControlStatus.PARTIALLY_SATISFIED)

    def test_contextual_mapping_does_not_affect_result(self) -> None:
        """Contextual evidence should remain outside formal assessment."""

        mapping = replace(_mapping(), strength=MappingStrength.CONTEXTUAL)
        pack = _pack(_control(mappings=(mapping,)))
        result = FrameworkEvaluator().evaluate(pack, [_finding(Status.FAIL)]).results[0]

        self.assertEqual(result.status, FrameworkControlStatus.NOT_EVALUATED)
        self.assertEqual(result.failed_rule_ids, ())

    def test_nontechnical_control_cannot_be_fully_satisfied(self) -> None:
        """Endpoint evidence should only partially satisfy mixed scope."""

        control = replace(_control(), level=FrameworkControlLevel.MIXED)
        result = FrameworkEvaluator().evaluate(_pack(control), [_finding(Status.PASS)]).results[0]

        self.assertEqual(result.status, FrameworkControlStatus.PARTIALLY_SATISFIED)

    def test_provisional_mapping_is_excluded(self) -> None:
        """Pending mappings should be traceable but not formally evaluated."""

        mapping = replace(
            _mapping(),
            status=MappingStatus.PROVISIONAL,
            reviewer=None,
            reviewed_at=None,
            review_method=ReviewMethod.MIGRATED_UNREVIEWED,
            review_pending_reason=ReviewPendingReason.REQUIRES_DOMAIN_EXPERT_REVIEW,
        )
        result = FrameworkEvaluator().evaluate(
            replace(
                _pack(_control(mappings=(mapping,))),
                status=PackStatus.REVIEW_REQUIRED,
            ),
            [_finding(Status.PASS)],
            allow_unreviewed=True,
        ).results[0]

        self.assertEqual(result.status, FrameworkControlStatus.NOT_EVALUATED)
        self.assertEqual(result.provisional_rule_ids, ("BIT-001",))

    def test_not_applicable_requires_explicit_policy_decision(self) -> None:
        """An explicit applicability decision should be preserved."""

        evaluation = FrameworkEvaluator().evaluate(
            _pack(_control()),
            [_finding(Status.PASS)],
            AssessmentPolicy(not_applicable_controls=frozenset({"TEST-1"})),
        )

        self.assertEqual(evaluation.results[0].status, FrameworkControlStatus.NOT_APPLICABLE)

    def test_coverage_denominators_and_zero_case(self) -> None:
        """Coverage metrics should use named denominators and safe zero values."""

        evaluation = _evaluate(Status.PASS)
        empty = calculate_coverage(replace(evaluation.pack, controls=()), ())

        self.assertEqual(evaluation.coverage.mapping_coverage_percent, 100.0)
        self.assertEqual(evaluation.coverage.assessment_coverage_percent, 100.0)
        self.assertEqual(empty.mapping_coverage_percent, 0.0)
        self.assertEqual(empty.technical_automation_coverage_percent, 0.0)


class FrameworkToolsTests(unittest.TestCase):
    """Validate comparison, import, JSON, and report surfaces."""

    def test_pack_comparison_detects_semantic_changes(self) -> None:
        """Comparison should report added controls and changed automation."""

        old = _pack(_control(), version="1.0")
        changed = replace(_control(), automation=AutomationCapability.PARTIAL)
        added = replace(_control(), control_id="TEST-2")
        new = replace(old, version="2.0", controls=(changed, added))

        comparison = compare_packs(old, new)

        self.assertEqual(comparison.added_controls, ("TEST-2",))
        self.assertEqual(comparison.changed_automation, ("TEST-1",))

    def test_cis_csv_import_creates_hashed_draft(self) -> None:
        """A whitelisted licensed mapping row should create a draft pack."""

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "licensed.csv"
            output = root / "pack.json"
            with source.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=["controlId", "title", "profile", "ruleIds"],
                )
                writer.writeheader()
                writer.writerow(
                    {"controlId": "1.1.1", "title": "CSA short title", "profile": "L1", "ruleIds": "BIT-001"}
                )
            path = import_cis_mapping(
                source,
                output,
                "CIS_WINDOWS_11_ENTERPRISE",
                "5.0.1-test",
            )

            pack = load_pack(path)

        self.assertEqual(pack.status, PackStatus.DRAFT)
        self.assertEqual(pack.controls[0].profile, ("Level 1",))
        self.assertEqual(pack.controls[0].mappings[0].status, MappingStatus.PROVISIONAL)

    def test_cis_import_rejects_unknown_rule_and_unexpected_field(self) -> None:
        """Importer should fail closed for unknown IDs and extra fields."""

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "bad.json"
            output = root / "pack.json"
            source.write_text(
                json.dumps({"controls": [{"controlId": "1", "title": "T", "ruleIds": ["NOPE"], "html": "bad"}]}),
                encoding="utf-8",
            )
            with self.assertRaises(FrameworkPackError):
                import_cis_mapping(source, output, "CIS", "1")

    def test_json_sidecar_and_html_include_traceability(self) -> None:
        """Framework results should reach both machine and client-facing output."""

        evaluation = _evaluate(Status.PASS)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            json_path = write_analysis_json([evaluation], root / "report.analysis.json")
            html_path = generate_html_report(
                data={"ComputerName": "TEST-PC"},
                audit_findings=[_finding(Status.PASS)],
                score=100,
                software_inventory=SoftwareInventory(),
                rule_metadata={},
                cve_summary=None,
                framework_evaluations=[evaluation],
                output_path=root / "report.html",
            )
            document = json.loads(json_path.read_text(encoding="utf-8"))
            html = html_path.read_text(encoding="utf-8")

        self.assertEqual(document["frameworkEvaluations"][0]["pack"]["version"], "1.0")
        self.assertEqual(
            document["frameworkEvaluations"][0]["coverage"]["frameworkControlCount"],
            1,
        )
        self.assertIn(
            "contentHashSha256",
            document["frameworkEvaluations"][0]["pack"],
        )
        self.assertIn("Framework Coverage &amp; Traceability", html)
        self.assertIn("TEST-1", html)
        self.assertIn(evaluation.pack.content_hash_sha256, html)
        self.assertIn("not a certification", html)


def _mapping() -> RuleMapping:
    """Create a reviewed direct mapping."""

    return RuleMapping(
        rule_id="BIT-001",
        strength=MappingStrength.DIRECT,
        status=MappingStatus.VALIDATED,
        rationale="Direct technical setting check.",
        evidence_limitations=("Point-in-time evidence.",),
        reviewer="Test Reviewer",
        reviewed_at="2026-07-22",
        source_reference="https://example.invalid/control",
        source_release="1.0",
        review_method=ReviewMethod.MANUAL_SOURCE_REVIEW,
    )


def _control(mappings: tuple[RuleMapping, ...] | None = None) -> FrameworkControl:
    """Create a technical test control."""

    return FrameworkControl(
        control_id="TEST-1",
        title="Test control",
        section="Testing",
        profile=("Test",),
        level=FrameworkControlLevel.TECHNICAL,
        automation=AutomationCapability.AUTOMATED,
        mappings=(_mapping(),) if mappings is None else mappings,
    )


def _pack(*controls: FrameworkControl, version: str = "1.0") -> FrameworkPack:
    """Create a test framework pack."""

    return FrameworkPack(
        schema_version="1.0",
        framework_id="TEST_FRAMEWORK",
        name="Test Framework",
        version=version,
        status=PackStatus.ACTIVE,
        source=FrameworkSource(
            publisher="Test",
            release=version,
            published_at="2026-07-22",
            retrieved_at="2026-07-22",
            reference="https://example.invalid/framework",
        ),
        scope=("test",),
        license_notice="Test data",
        created_at="2026-07-22",
        updated_at="2026-07-22",
        maintainer="CSA",
        minimum_csa_version="3.2",
        deprecated=False,
        supersedes=None,
        superseded_by=None,
        controls=controls,
        content_hash_sha256="0" * 64,
    )


def _finding(status: Status) -> AuditFinding:
    """Create one technical audit finding."""

    return AuditFinding(
        finding=Finding("BIT-001", Severity.HIGH, status=status, evidence={}),
        knowledge=Knowledge(
            id="BIT-001",
            title="BitLocker",
            description="Test",
            risk="Test",
            recommendation="Test",
            frameworks={},
            references=[],
        ),
    )


def _evaluate(status: Status):
    """Evaluate one test control."""

    return FrameworkEvaluator().evaluate(_pack(_control()), [_finding(status)])


if __name__ == "__main__":
    unittest.main()
