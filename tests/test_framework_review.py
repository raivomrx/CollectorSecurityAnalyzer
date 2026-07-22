"""Hardening tests for framework source normalization and human review."""

from __future__ import annotations

import csv
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from frameworks.digest import pack_content_digest
from frameworks.enums import (
    AssessmentMode,
    EvaluationMode,
    MappingStatus,
    MappingStrength,
    PackStatus,
    ReviewMethod,
    ReviewPendingReason,
)
from frameworks.evaluator import FrameworkEvaluator
from frameworks.exceptions import FrameworkPackError
from frameworks.import_cis_mapping import import_cis_mapping
from frameworks.loader import load_pack
from frameworks.registry import FrameworkPackRegistry
from frameworks.review import apply_review, review_candidates
from frameworks.validation import FrameworkPackValidator
from report import generate_html_report
from software.models import SoftwareInventory

ROOT = Path(__file__).resolve().parents[1]


class FrameworkReleaseGateTests(unittest.TestCase):
    """Verify conservative pack lifecycle rules."""

    def test_active_pack_rejects_provisional_mapping(self) -> None:
        pack = _model_pack(PackStatus.ACTIVE, _provisional_mapping())
        errors = FrameworkPackValidator().validate(pack)
        self.assertIn("ACTIVE pack contains provisional mappings", errors)

    def test_active_pack_requires_reviewer_and_date(self) -> None:
        mapping = replace(
            _validated_mapping(),
            reviewer=None,
            reviewed_at=None,
        )
        errors = FrameworkPackValidator().validate(_model_pack(PackStatus.ACTIVE, mapping))
        self.assertTrue(any("lacks a reviewer" in item for item in errors))
        self.assertTrue(any("lacks a review date" in item for item in errors))

    def test_active_pack_requires_concrete_source_release(self) -> None:
        pack = replace(_model_pack(PackStatus.ACTIVE, _validated_mapping()), source=replace(
            _model_pack(PackStatus.ACTIVE, _validated_mapping()).source,
            release=None,
        ))
        self.assertIn(
            "ACTIVE pack requires a concrete source release",
            FrameworkPackValidator().validate(pack),
        )

    def test_review_required_provisional_pack_is_valid(self) -> None:
        errors = FrameworkPackValidator().validate(
            _model_pack(PackStatus.REVIEW_REQUIRED, _provisional_mapping())
        )
        self.assertEqual(errors, [])

    def test_empty_draft_pack_is_valid(self) -> None:
        pack = replace(_model_pack(PackStatus.DRAFT, _provisional_mapping()), controls=())
        self.assertEqual(FrameworkPackValidator().validate(pack), [])

    def test_bundled_registry_has_no_active_defaults(self) -> None:
        registry = FrameworkPackRegistry()
        self.assertEqual(registry.load_defaults(), [])
        self.assertTrue(all(not entry.default for entry in registry.entries))


class FrameworkSourceTests(unittest.TestCase):
    """Verify normalized bundled pack identity and provenance."""

    def test_microsoft_pack_is_csa_guidance_not_official_baseline(self) -> None:
        pack = FrameworkPackRegistry().resolve(
            "CSA_WINDOWS_11_MICROSOFT_GUIDANCE",
            "CSA-WIN11-2026.1",
        )
        self.assertEqual(pack.status, PackStatus.REVIEW_REQUIRED)
        self.assertIsNone(pack.source.release)
        self.assertIn("not an official Microsoft Security Baseline", pack.disclaimer_en or "")
        self.assertTrue(
            all(control.control_id.startswith("CSA-MSG-") for control in pack.controls)
        )

    def test_eits_utf8_and_strict_sources_are_preserved(self) -> None:
        pack = FrameworkPackRegistry().resolve("EITS", "2026")
        self.assertEqual(pack.source.publisher, "Riigi Infosüsteemi Amet")
        self.assertEqual(
            FrameworkPackValidator().validate(pack, strict_sources=True),
            [],
        )

    def test_eits_m6_has_exact_reference_and_explicit_limitation(self) -> None:
        pack = FrameworkPackRegistry().resolve("EITS", "2026")
        control = next(item for item in pack.controls if item.control_id == "OPS.1.1.4.M6")
        for mapping in control.mappings:
            self.assertIn("OPS.1.1.4.M6", mapping.source_reference or "")
            self.assertTrue(
                any("requires confirmation" in value for value in mapping.evidence_limitations)
            )

    def test_framework_sources_contain_no_mojibake_or_replacement_character(self) -> None:
        markers = ("\u00c3", "\u00c2", "\u00e2\u20ac", "\ufffd")
        paths = [
            *ROOT.joinpath("frameworks").rglob("*.json"),
            *ROOT.joinpath("docs").rglob("*.md"),
            ROOT / "templates" / "report.html",
        ]
        offenders = [
            str(path.relative_to(ROOT))
            for path in paths
            if any(marker in path.read_text(encoding="utf-8") for marker in markers)
        ]
        self.assertEqual(offenders, [])

    def test_nis2_is_traceability_only(self) -> None:
        pack = FrameworkPackRegistry().resolve(
            "NIS2_TECHNICAL_TRACEABILITY",
            "EU-2022-2555",
        )
        self.assertEqual(pack.assessment_mode, AssessmentMode.TRACEABILITY_ONLY)
        self.assertIn("not a determination of legal compliance", pack.disclaimer_en or "")
        self.assertTrue(
            all(
                mapping.strength in {MappingStrength.SUPPORTING, MappingStrength.CONTEXTUAL}
                for control in pack.controls
                for mapping in control.mappings
            )
        )

    def test_pack_digest_is_independent_of_key_order_and_formatting(self) -> None:
        document = _pack_document()
        reordered = dict(reversed(list(document.items())))
        self.assertEqual(pack_content_digest(document), pack_content_digest(reordered))
        self.assertEqual(
            pack_content_digest(json.loads(json.dumps(document, separators=(",", ":")))),
            pack_content_digest(json.loads(json.dumps(document, indent=4))),
        )


class CisImportPrivacyTests(unittest.TestCase):
    """Verify licensed import provenance does not disclose local paths."""

    def test_import_omits_parent_paths_and_preserves_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "Test User" / "Secret Client"
            root.mkdir(parents=True)
            source = _write_cis_csv(root / "licensed-cis-mapping.csv")
            output = Path(temp_dir) / "pack.json"
            import_cis_mapping(source, output, "CIS_TEST", "1.0")
            text = output.read_text(encoding="utf-8")
            document = json.loads(text)
        self.assertNotIn(str(root), text)
        self.assertNotIn("Test User", text)
        self.assertNotIn("Secret Client", text)
        self.assertEqual(document["source"]["sourceFileName"], source.name)
        self.assertEqual(len(document["source"]["sourceDigestSha256"]), 64)
        self.assertEqual(document["source"]["recordCount"], 1)

    def test_strict_privacy_redacts_filename(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = _write_cis_csv(Path(temp_dir) / "private-client.csv")
            output = Path(temp_dir) / "pack.json"
            import_cis_mapping(source, output, "CIS_TEST", "1.0", strict_privacy=True)
            document = json.loads(output.read_text(encoding="utf-8"))
        self.assertIsNone(document["source"]["sourceFileName"])
        self.assertEqual(len(document["source"]["sourceDigestSha256"]), 64)

    def test_imported_mapping_is_never_validated(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "mapping.csv"
            with source.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=[
                        "controlId",
                        "title",
                        "profile",
                        "ruleIds",
                        "mappingStatus",
                        "reviewer",
                        "reviewedAt",
                        "reviewMethod",
                    ],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "controlId": "1.1",
                        "title": "Test",
                        "profile": "L1",
                        "ruleIds": "BIT-001",
                        "mappingStatus": "VALIDATED",
                        "reviewer": "Untrusted Import",
                        "reviewedAt": "2026-07-22",
                        "reviewMethod": "MANUAL_SOURCE_REVIEW",
                    }
                )
            output = Path(temp_dir) / "pack.json"
            import_cis_mapping(source, output, "CIS_TEST", "1.0")
            mapping = load_pack(output).controls[0].mappings[0]
        self.assertEqual(mapping.status, MappingStatus.PROVISIONAL)
        self.assertIsNone(mapping.reviewer)
        self.assertEqual(mapping.review_method, ReviewMethod.IMPORTED_UNREVIEWED)

    def test_invalid_import_does_not_create_partial_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "bad.csv"
            output = Path(temp_dir) / "pack.json"
            source.write_text(
                "controlId,title,profile,ruleIds\n1,Title,L1,NOPE\n",
                encoding="utf-8",
            )
            with self.assertRaises(FrameworkPackError):
                import_cis_mapping(source, output, "CIS_TEST", "1.0")
            self.assertFalse(output.exists())


class HumanReviewWorkflowTests(unittest.TestCase):
    """Verify candidate export and transactional review application."""

    def test_candidate_export_filters_status_and_strength(self) -> None:
        pack = _model_pack(PackStatus.REVIEW_REQUIRED, _provisional_mapping())
        rows = review_candidates(
            [pack],
            status=MappingStatus.PROVISIONAL,
            strength=MappingStrength.DIRECT,
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["review_pending_reason"], "SOURCE_VERSION_UNCONFIRMED")

    def test_validate_decision_rehashes_pack_and_writes_path_safe_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            registry = _write_test_registry(Path(temp_dir))
            review_path = _write_review_csv(Path(temp_dir) / "Secret Client" / "review.csv")
            result = apply_review(review_path, "TEST", "1.0", registry)
            pack = registry.resolve("TEST", "1.0")
            audit_text = result.audit_path.read_text(encoding="utf-8")
        self.assertNotEqual(result.previous_digest, result.new_digest)
        self.assertEqual(pack.controls[0].mappings[0].status, MappingStatus.VALIDATED)
        self.assertNotIn(str(review_path), audit_text)
        self.assertNotIn("Secret Client", audit_text)

    def test_validate_requires_reviewer_date_and_human_method(self) -> None:
        for field, value in (
            ("reviewer", ""),
            ("reviewed_at", "not-a-date"),
            ("review_method", "MIGRATED_UNREVIEWED"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                registry = _write_test_registry(root)
                review = _write_review_csv(root / "review.csv", **{field: value})
                before = registry.pack_path("TEST", "1.0").read_bytes()
                with self.assertRaises(FrameworkPackError):
                    apply_review(review, "TEST", "1.0", registry)
                self.assertEqual(registry.pack_path("TEST", "1.0").read_bytes(), before)

    def test_unknown_mapping_aborts_entire_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            registry = _write_test_registry(root)
            review = _write_review_csv(root / "review.csv", rule_id="NO-SUCH-RULE")
            before = registry.pack_path("TEST", "1.0").read_bytes()
            with self.assertRaises(FrameworkPackError):
                apply_review(review, "TEST", "1.0", registry)
            self.assertEqual(registry.pack_path("TEST", "1.0").read_bytes(), before)
            audit = registry.pack_path("TEST", "1.0").with_name("review-audit.json")
            self.assertFalse(audit.exists())

    def test_reject_removes_existing_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            registry = _write_test_registry(root)
            review = _write_review_csv(root / "review.csv", decision="REJECT")
            apply_review(review, "TEST", "1.0", registry)
            self.assertEqual(registry.resolve("TEST", "1.0").controls[0].mappings, ())


class FrameworkEvaluationAndReportTests(unittest.TestCase):
    """Verify traceability-only runtime and presentation behavior."""

    def test_review_required_pack_needs_explicit_flag(self) -> None:
        pack = _model_pack(PackStatus.REVIEW_REQUIRED, _provisional_mapping())
        with self.assertRaisesRegex(FrameworkPackError, "allow-unreviewed-frameworks"):
            FrameworkEvaluator().evaluate(pack, [])

    def test_allow_unreviewed_is_traceability_only(self) -> None:
        pack = _model_pack(PackStatus.REVIEW_REQUIRED, _provisional_mapping())
        evaluation = FrameworkEvaluator().evaluate(pack, [], allow_unreviewed=True)
        self.assertEqual(evaluation.evaluation_mode, EvaluationMode.TRACEABILITY_ONLY)
        self.assertFalse(evaluation.formal_assessment_performed)
        self.assertEqual(evaluation.coverage.validated_mapped_control_count, 0)
        self.assertEqual(evaluation.results[0].presentation_status, "REVIEW_PENDING")

    def test_active_pack_with_provisional_mapping_fails_at_runtime(self) -> None:
        with self.assertRaisesRegex(FrameworkPackError, "provisional"):
            FrameworkEvaluator().evaluate(
                _model_pack(PackStatus.ACTIVE, _provisional_mapping()),
                [],
            )

    def test_nis2_presentation_never_uses_legal_satisfaction_status(self) -> None:
        pack = FrameworkPackRegistry().resolve(
            "NIS2_TECHNICAL_TRACEABILITY",
            "EU-2022-2555",
        )
        evaluation = FrameworkEvaluator().evaluate(pack, [], allow_unreviewed=True)
        labels = {item.presentation_status for item in evaluation.results}
        self.assertNotIn("SATISFIED", labels)
        self.assertNotIn("NOT_SATISFIED", labels)

    def test_report_shows_review_state_disclaimer_and_no_local_path(self) -> None:
        mapping = replace(
            _provisional_mapping(),
            source_reference="C:\\Users\\Secret\\mapping.csv",
        )
        pack = replace(
            _model_pack(PackStatus.REVIEW_REQUIRED, mapping),
            disclaimer_en="This is a CSA-authored mapping, not an official package.",
            disclaimer_et="See on CSA koostatud mapping, mitte ametlik pakett.",
        )
        evaluation = FrameworkEvaluator().evaluate(pack, [], allow_unreviewed=True)
        with tempfile.TemporaryDirectory() as temp_dir:
            report = generate_html_report(
                data={"ComputerName": "TEST-PC"},
                audit_findings=[],
                score=100,
                software_inventory=SoftwareInventory(),
                rule_metadata={},
                cve_summary=None,
                framework_evaluations=[evaluation],
                output_path=Path(temp_dir) / "report.html",
            ).read_text(encoding="utf-8")
        self.assertIn("REVIEW_REQUIRED", report)
        self.assertIn("Provisional mappings", report)
        self.assertIn("traceability only", report)
        self.assertIn("not an official package", report)
        self.assertNotIn("C:\\Users\\Secret", report)


def _validated_mapping():
    from frameworks.models import RuleMapping

    return RuleMapping(
        rule_id="BIT-001",
        strength=MappingStrength.DIRECT,
        status=MappingStatus.VALIDATED,
        rationale="The endpoint rule checks the same technical setting.",
        evidence_limitations=("Point-in-time endpoint evidence.",),
        reviewer="Human Reviewer",
        reviewed_at="2026-07-22",
        source_reference="https://example.invalid/control/1",
        source_release="1.0",
        review_method=ReviewMethod.MANUAL_SOURCE_REVIEW,
    )


def _provisional_mapping():
    return replace(
        _validated_mapping(),
        status=MappingStatus.PROVISIONAL,
        reviewer=None,
        reviewed_at=None,
        review_method=ReviewMethod.MIGRATED_UNREVIEWED,
        review_pending_reason=ReviewPendingReason.SOURCE_VERSION_UNCONFIRMED,
    )


def _model_pack(status: PackStatus, mapping):
    from frameworks.enums import AutomationCapability, FrameworkControlLevel
    from frameworks.models import FrameworkControl, FrameworkPack, FrameworkSource

    control = FrameworkControl(
        control_id="TEST-1",
        title="Test control",
        section="Test",
        profile=("Test",),
        level=FrameworkControlLevel.TECHNICAL,
        automation=AutomationCapability.AUTOMATED,
        mappings=(mapping,),
    )
    return FrameworkPack(
        schema_version="1.0",
        framework_id="TEST",
        name="Test Pack",
        version="1.0",
        status=status,
        source=FrameworkSource(
            publisher="Test",
            release="1.0",
            published_at="2026-07-22",
            retrieved_at="2026-07-22",
            reference="https://example.invalid/source",
        ),
        scope=("test",),
        license_notice="Test",
        created_at="2026-07-22",
        updated_at="2026-07-22",
        maintainer="CSA",
        minimum_csa_version="3.2",
        deprecated=False,
        supersedes=None,
        superseded_by=None,
        controls=(control,),
        content_hash_sha256="0" * 64,
    )


def _write_cis_csv(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["controlId", "title", "profile", "ruleIds"])
        writer.writeheader()
        writer.writerow(
            {
                "controlId": "1.1",
                "title": "Test",
                "profile": "L1",
                "ruleIds": "BIT-001",
            }
        )
    return path


def _write_test_registry(root: Path) -> FrameworkPackRegistry:
    pack_path = root / "test" / "1.0" / "pack.json"
    pack_path.parent.mkdir(parents=True)
    document = _pack_document()
    document["contentHashSha256"] = pack_content_digest(document)
    pack_path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    registry = {
        "schemaVersion": "1.0",
        "packs": [{
            "frameworkId": "TEST",
            "version": "1.0",
            "path": "test/1.0/pack.json",
            "status": "REVIEW_REQUIRED",
            "default": False,
        }],
    }
    (root / "registry.json").write_text(json.dumps(registry), encoding="utf-8")
    return FrameworkPackRegistry(root)


def _pack_document() -> dict:
    return {
        "schemaVersion": "1.0",
        "frameworkId": "TEST",
        "name": "Test Pack",
        "version": "1.0",
        "status": "REVIEW_REQUIRED",
        "assessmentMode": "FORMAL_ASSESSMENT",
        "source": {
            "publisher": "Test",
            "release": "1.0",
            "publishedAt": "2026-07-22",
            "retrievedAt": "2026-07-22",
            "reference": "https://example.invalid/source",
            "digestSha256": None,
        },
        "scope": ["test"],
        "license": "Test",
        "createdAt": "2026-07-22",
        "updatedAt": "2026-07-22",
        "maintainer": "CSA",
        "minimumCsaVersion": "3.2",
        "deprecated": False,
        "supersedes": None,
        "supersededBy": None,
        "controls": [{
            "controlId": "TEST-1",
            "title": "Test control",
            "section": "Test",
            "profile": ["Test"],
            "level": "TECHNICAL",
            "automation": "AUTOMATED",
            "mappings": [{
                "ruleId": "BIT-001",
                "mappingStrength": "DIRECT",
                "mappingStatus": "PROVISIONAL",
                "rationale": "The rule checks the same endpoint setting.",
                "evidenceLimitations": ["Point-in-time endpoint evidence."],
                "reviewer": None,
                "reviewedAt": None,
                "sourceReference": "https://example.invalid/control/1",
                "sourceRelease": "1.0",
                "reviewMethod": "MIGRATED_UNREVIEWED",
                "reviewPendingReason": "SOURCE_VERSION_UNCONFIRMED",
            }],
            "tags": ["test"],
            "notes": None,
        }],
        "contentHashSha256": "",
    }


def _write_review_csv(path: Path, **overrides: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "control_id": "TEST-1",
        "rule_id": "BIT-001",
        "decision": "VALIDATE",
        "reviewer": "Human Reviewer",
        "reviewed_at": "2026-07-22",
        "review_method": "MANUAL_SOURCE_REVIEW",
        "comment": "Checked against source.",
    }
    row.update(overrides)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)
    return path


if __name__ == "__main__":
    unittest.main()
