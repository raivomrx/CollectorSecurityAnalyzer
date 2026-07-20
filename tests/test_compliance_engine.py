"""Tests for the Compliance & Policy Intelligence Engine."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from analysis_context import AnalysisContext
from compliance.engine import ComplianceEngine
from compliance.enums import (
    ComplianceStatus,
    EvidenceResult,
    EvidenceSourceType,
)
from compliance.evaluator import ComplianceEvaluator
from compliance.evidence.composite_evidence import CompositeEvidenceExtractor
from compliance.evidence.field_evidence import FieldEvidenceExtractor, resolve_path
from compliance.evidence.finding_evidence import FindingEvidenceExtractor
from compliance.exceptions import ComplianceDefinitionError
from compliance.loader import load_framework
from compliance.models import ComplianceProfile, EvidenceRequirement
from compliance.profile_resolver import ComplianceProfileResolver
from compliance.repository import FrameworkRepository
from compliance.repository import ControlMappingRepository
from compliance.scoring import weighted_score
from compliance.validation import ComplianceDefinitionValidator
from knowledge.models import Knowledge
from risk import AuditFinding, Finding, Severity, Status
from software.inventory import build_inventory


class ComplianceRepositoryTests(unittest.TestCase):
    """Validate framework repository and definition loading."""

    def test_repository_loads_default_frameworks_and_profiles(self) -> None:
        """Bundled compliance catalog should be loadable."""

        repository = FrameworkRepository()

        self.assertGreaterEqual(len(repository.list_frameworks()), 3)
        self.assertGreaterEqual(len(repository.list_profiles()), 7)
        self.assertEqual(
            repository.get_framework("MICROSOFT_BASELINE", "WINDOWS_11_25H2_CSA_2026.1").framework_id,
            "MICROSOFT_BASELINE",
        )

    def test_duplicate_control_id_is_rejected(self) -> None:
        """Framework validation should reject duplicate control IDs."""

        with tempfile.TemporaryDirectory() as temp_dir:
            path = _framework_path(Path(temp_dir), [_control("CTRL-1"), _control("CTRL-1")])
            framework = load_framework(path)

        with self.assertRaises(ComplianceDefinitionError):
            ComplianceDefinitionValidator().validate_framework(framework)

    def test_missing_parent_control_is_rejected(self) -> None:
        """Framework validation should reject missing parent references."""

        with tempfile.TemporaryDirectory() as temp_dir:
            path = _framework_path(
                Path(temp_dir),
                [_control("CTRL-1", parent_control_id="MISSING")],
            )
            framework = load_framework(path)

        with self.assertRaises(ComplianceDefinitionError):
            ComplianceDefinitionValidator().validate_framework(framework)

    def test_two_framework_versions_can_coexist(self) -> None:
        """Repository should keep separate versions of the same framework."""

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            first = _framework_path(root / "first", [_control("CTRL-1")], version="1.0")
            second = _framework_path(root / "second", [_control("CTRL-1")], version="2.0")
            repository = FrameworkRepository(framework_paths=[first, second], profile_paths=[])

            self.assertEqual(repository.get_framework("CUSTOM_POLICY", "1.0").version, "1.0")
            self.assertEqual(repository.get_framework("CUSTOM_POLICY", "2.0").version, "2.0")
            with self.assertRaises(ComplianceDefinitionError):
                repository.get_framework("CUSTOM_POLICY")


class ComplianceMappingTests(unittest.TestCase):
    """Validate rule-control mapping loading and decision impact."""

    def test_default_mappings_load_by_rule_and_control(self) -> None:
        """Bundled mappings should be queryable by rule and exact framework control."""

        framework_repository = FrameworkRepository()
        mapping_repository = ControlMappingRepository(framework_repository)

        self.assertTrue(mapping_repository.get_by_rule("BIT-001"))
        self.assertTrue(
            mapping_repository.get_by_control(
                "MICROSOFT_BASELINE",
                "WINDOWS_11_25H2_CSA_2026.1",
                "MSB-BITLOCKER-001",
            )
        )

    def test_mapping_validation_rejects_unknown_control_and_rule(self) -> None:
        """Mapping validation should catch unknown controls and rules."""

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            framework_path = _framework_path(root / "framework", [_control("CTRL-1")])
            repository = FrameworkRepository(framework_paths=[framework_path], profile_paths=[])
            bad_control = _mapping_path(root / "bad_control", ["UNKNOWN"], rule_id="BIT-001")
            bad_rule = _mapping_path(root / "bad_rule", ["CTRL-1"], rule_id="UNKNOWN-RULE")

            with self.assertRaises(ComplianceDefinitionError):
                ControlMappingRepository(repository, [bad_control], {"BIT-001"})
            with self.assertRaises(ComplianceDefinitionError):
                ControlMappingRepository(repository, [bad_rule], {"BIT-001"})

    def test_mapping_validation_rejects_duplicate_mapping(self) -> None:
        """Duplicate rule/control/relationship mappings should fail."""

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            framework_path = _framework_path(root / "framework", [_control("CTRL-1")])
            repository = FrameworkRepository(framework_paths=[framework_path], profile_paths=[])
            mapping_path = _mapping_path(
                root / "mapping",
                ["CTRL-1"],
                duplicate=True,
            )

            with self.assertRaises(ComplianceDefinitionError):
                ControlMappingRepository(repository, [mapping_path], {"BIT-001"})

    def test_mapping_relationships_affect_control_decisions(self) -> None:
        """PARTIAL and CONTEXT_ONLY mappings must not produce full compliance."""

        partial = _evaluate_custom_mapping("PARTIAL", Status.PASS)
        context_only = _evaluate_custom_mapping("CONTEXT_ONLY", Status.PASS)
        inverse = _evaluate_custom_mapping("CONTRADICTS", Status.FAIL)

        self.assertEqual(partial.status, ComplianceStatus.PARTIALLY_COMPLIANT)
        self.assertEqual(context_only.status, ComplianceStatus.MANUAL_REVIEW)
        self.assertEqual(inverse.status, ComplianceStatus.COMPLIANT)

    def test_mapping_confidence_limits_evidence_confidence(self) -> None:
        """Effective finding evidence confidence should be capped by mapping confidence."""

        assessment = _evaluate_custom_mapping("SUPPORTS", Status.PASS, confidence=40)

        self.assertEqual(assessment.evidence[0].confidence, 40)
        self.assertEqual(assessment.decision_confidence, 40)
        self.assertEqual(assessment.status, ComplianceStatus.PARTIALLY_COMPLIANT)

    def test_unvalidated_mapping_requires_manual_review(self) -> None:
        """Unvalidated mapping should not make a mandatory control compliant."""

        assessment = _evaluate_custom_mapping("SUPPORTS", Status.PASS, validated=False)

        self.assertEqual(assessment.status, ComplianceStatus.MANUAL_REVIEW)


class ComplianceEvidenceTests(unittest.TestCase):
    """Validate evidence extraction."""

    def test_finding_evidence_maps_statuses_to_results(self) -> None:
        """Finding evidence should support, contradict, or remain inconclusive."""

        extractor = FindingEvidenceExtractor()
        context = _context()
        requirement = _requirement("E1", EvidenceSourceType.FINDING, "BIT-001", "PASS", "STATUS_IS")

        self.assertEqual(
            extractor.extract(requirement, context, [_audit_finding("BIT-001", Status.PASS)]).result,
            EvidenceResult.SUPPORTS,
        )
        self.assertEqual(
            extractor.extract(requirement, context, [_audit_finding("BIT-001", Status.FAIL)]).result,
            EvidenceResult.CONTRADICTS,
        )
        self.assertEqual(
            extractor.extract(requirement, context, [_audit_finding("BIT-001", Status.WARNING)]).result,
            EvidenceResult.INCONCLUSIVE,
        )
        self.assertEqual(
            extractor.extract(requirement, context, []).result,
            EvidenceResult.MISSING,
        )

    def test_raw_field_evidence_supports_safe_dot_paths(self) -> None:
        """Raw-field evidence should resolve nested values without unsafe paths."""

        extractor = FieldEvidenceExtractor()
        context = _context({"Computer": {"OS": "Windows 11"}, "Profiles": [{"Enabled": True}]})

        self.assertEqual(resolve_path(context.raw_data, "Profiles.0.Enabled"), True)
        self.assertEqual(
            extractor.extract(
                _requirement("E1", EvidenceSourceType.RAW_FIELD, "Computer.OS", "Windows 11", "EQUALS"),
                context,
                [],
            ).result,
            EvidenceResult.SUPPORTS,
        )
        self.assertEqual(
            extractor.extract(
                _requirement("E2", EvidenceSourceType.RAW_FIELD, "Computer.__class__", None, "EXISTS"),
                context,
                [],
            ).result,
            EvidenceResult.INCONCLUSIVE,
        )

    def test_composite_evidence_supports_and_or_modes(self) -> None:
        """Composite evidence should combine child evidence deterministically."""

        extractor = CompositeEvidenceExtractor()
        context = _context({"A": True, "B": False})
        requirement = _requirement(
            "E1",
            EvidenceSourceType.RAW_FIELD,
            "",
            True,
            "EQUALS",
            extractor="composite",
            parameters={
                "mode": "AND",
                "requirements": [
                    {
                        "id": "A",
                        "sourceType": "RAW_FIELD",
                        "sourceReference": "A",
                        "operator": "EQUALS",
                        "expectedResult": True,
                    },
                    {
                        "id": "B",
                        "sourceType": "RAW_FIELD",
                        "sourceReference": "B",
                        "operator": "EQUALS",
                        "expectedResult": True,
                    },
                ],
            },
        )

        self.assertEqual(extractor.extract(requirement, context, []).result, EvidenceResult.CONTRADICTS)
        requirement.parameters["mode"] = "OR"
        self.assertEqual(extractor.extract(requirement, context, []).result, EvidenceResult.SUPPORTS)


class ComplianceResolverAndEvaluatorTests(unittest.TestCase):
    """Validate profile detection and control evaluation."""

    def test_profile_resolver_detects_join_types_and_fallback(self) -> None:
        """Resolver should pick profiles from endpoint context."""

        repository = FrameworkRepository()

        self.assertEqual(
            ComplianceProfileResolver(repository).resolve(
                _context({"TenantID": "tenant", "Current_user": "AzureAD\\alice"})
            )[0].profile_id,
            "windows_11_entra_joined",
        )
        self.assertEqual(
            ComplianceProfileResolver(repository).resolve(_context({"Domain": "EXAMPLE"}))[0].profile_id,
            "windows_11_domain_joined",
        )
        self.assertEqual(
            ComplianceProfileResolver(repository).resolve(_context({"Domain": "WORKGROUP"}))[0].profile_id,
            "windows_11_standalone",
        )
        fallback = ComplianceProfileResolver(repository)
        self.assertEqual(fallback.resolve(_context({}))[0].profile_id, "windows_11_workstation")
        self.assertTrue(fallback.warnings)

    def test_profile_resolver_rejects_wrong_os_without_manual_override(self) -> None:
        """Automatic resolver must not apply Windows 11 profiles to unsupported OS data."""

        repository = FrameworkRepository()
        resolver = ComplianceProfileResolver(repository)

        self.assertEqual(resolver.resolve(_context({"OS": "Windows Server 2022"})), [])
        self.assertTrue(resolver.warnings)

    def test_profile_resolver_honors_manual_override(self) -> None:
        """Manual CLI-style profile selection should bypass automatic detection."""

        repository = FrameworkRepository()
        profiles = ComplianceProfileResolver(repository).resolve(
            _context({"OS": "Windows Server 2022"}),
            manual_profile_ids=["windows_11_entra_joined"],
        )

        self.assertEqual(profiles[0].profile_id, "windows_11_entra_joined")

    def test_evaluator_scores_compliant_and_non_compliant_controls(self) -> None:
        """Endpoint evidence should drive control status and score."""

        repository = FrameworkRepository()
        profile = repository.get_profile("windows_11_workstation")
        control = repository.get_control("MICROSOFT_BASELINE", "MSB-BITLOCKER-001", "WINDOWS_11_25H2_CSA_2026.1")
        evaluator = ComplianceEvaluator()

        compliant = evaluator.evaluate_control(control, profile, _context(), [_audit_finding("BIT-001", Status.PASS)])
        non_compliant = evaluator.evaluate_control(control, profile, _context(), [_audit_finding("BIT-001", Status.FAIL)])
        missing = evaluator.evaluate_control(control, profile, _context(), [])

        self.assertEqual(compliant.status, ComplianceStatus.COMPLIANT)
        self.assertEqual(non_compliant.status, ComplianceStatus.NON_COMPLIANT)
        self.assertEqual(missing.status, ComplianceStatus.NOT_ASSESSED)
        self.assertEqual(weighted_score([compliant, non_compliant]), 50.0)

    def test_engine_builds_summary_for_profile(self) -> None:
        """Compliance engine should return a summary for selected profiles."""

        repository = FrameworkRepository()
        profile = repository.get_profile("windows_11_workstation")
        engine = ComplianceEngine(repository=repository, framework_filter=["MICROSOFT_BASELINE"])
        summary = engine.assess(_context(), [_audit_finding("BIT-001", Status.PASS)], [profile])

        self.assertEqual(summary.profile_ids, ["windows_11_workstation"])
        self.assertEqual(len(summary.framework_assessments), 1)
        self.assertEqual(summary.framework_assessments[0].profile_version, profile.version)
        self.assertGreater(summary.total_controls, 0)

    def test_cis_ig_profile_does_not_duplicate_cis_framework(self) -> None:
        """Endpoint profile plus --cis-ig should assess CIS only once."""

        repository = FrameworkRepository()
        profiles = ComplianceProfileResolver(repository).resolve(
            _context({"OS": "Windows 11"}),
            cis_ig="IG1",
        )
        summary = ComplianceEngine(repository=repository, framework_filter=["CIS_CONTROLS"]).assess(
            _context(),
            [_audit_finding("FW-001", Status.PASS)],
            profiles,
        )

        self.assertEqual(len(summary.framework_assessments), 1)
        self.assertEqual(summary.framework_assessments[0].framework.framework_id, "CIS_CONTROLS")
        self.assertEqual(summary.total_controls, len(summary.framework_assessments[0].controls))

    def test_mixed_scope_is_partially_assessable(self) -> None:
        """Endpoint + organisation controls should not become fully compliant from endpoint evidence."""

        repository = FrameworkRepository()
        mapping_repository = ControlMappingRepository(repository)
        evaluator = ComplianceEvaluator(mapping_repository=mapping_repository)
        profile = repository.get_profile("windows_11_workstation")
        control = repository.get_control("CIS_CONTROLS", "CIS-1.1", "8.1")
        assessment = evaluator.evaluate_control(
            control,
            profile,
            _context(),
            [_audit_finding("SW-001", Status.PASS)],
        )

        self.assertEqual(assessment.status, ComplianceStatus.PARTIALLY_COMPLIANT)
        self.assertIn("ENDPOINT", [scope.value for scope in assessment.assessed_scopes])
        self.assertIn("ORGANISATION", [scope.value for scope in assessment.unassessed_scopes])

    def test_pure_organisation_scope_is_not_assessed(self) -> None:
        """Pure organisation controls should not be assessed from endpoint evidence."""

        repository = FrameworkRepository()
        profile = repository.get_profile("windows_11_workstation")
        control = repository.get_control("EITS", "EITS-PATCHING-PROCESS", "2025")
        assessment = ComplianceEvaluator().evaluate_control(control, profile, _context(), [])

        self.assertEqual(assessment.status, ComplianceStatus.NOT_ASSESSED)

    def test_evidence_weighting_affects_control_score_and_coverage(self) -> None:
        """Mandatory support plus optional missing evidence should produce weighted partial score."""

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            control = _control(
                "CTRL-1",
                requirements=[
                    _raw_requirement("CTRL-1-E1", "A", True, weight=0.8, mandatory=True),
                    _raw_requirement("CTRL-1-E2", "B", True, weight=0.2, mandatory=False),
                ],
            )
            framework_path = _framework_path(root / "framework", [control])
            profile_path = _profile_path(root / "profiles", {"CUSTOM_POLICY": "1.0"})
            repository = FrameworkRepository([framework_path], [profile_path])
            profile = repository.get_profile("custom_profile")
            assessment = ComplianceEvaluator().evaluate_control(
                repository.get_control("CUSTOM_POLICY", "CTRL-1", "1.0"),
                profile,
                _context({"A": True}),
                [],
            )

        self.assertEqual(assessment.status, ComplianceStatus.PARTIALLY_COMPLIANT)
        self.assertEqual(assessment.score, 0.8)
        self.assertEqual(assessment.evidence_coverage_percent, 50.0)
        self.assertEqual(assessment.mandatory_evidence_coverage_percent, 100.0)

    def test_summary_coverage_is_requirement_weighted(self) -> None:
        """Overall coverage should use requirement counts across frameworks."""

        repository = FrameworkRepository()
        profile = repository.get_profile("windows_11_workstation")
        summary = ComplianceEngine(repository=repository).assess(
            _context(),
            [_audit_finding("BIT-001", Status.PASS)],
            [profile],
        )
        covered = sum(item.covered_evidence_requirement_count for item in summary.framework_assessments)
        total = sum(item.evidence_requirement_count for item in summary.framework_assessments)

        self.assertEqual(summary.evidence_coverage_percent, round((covered / total) * 100, 1))

    def test_profile_validation_rejects_unknown_version_and_control_overlap(self) -> None:
        """Profiles should validate exact framework versions and control references."""

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            framework_path = _framework_path(root / "framework", [_control("CTRL-1")])
            bad_version = _profile_path(root / "bad_version", {"CUSTOM_POLICY": "9.9"})
            overlap = _profile_path(
                root / "overlap",
                {"CUSTOM_POLICY": "1.0"},
                enabled={"CUSTOM_POLICY": ["CTRL-1"]},
                excluded={"CUSTOM_POLICY": ["CTRL-1"]},
            )

            with self.assertRaises(ComplianceDefinitionError):
                FrameworkRepository([framework_path], [bad_version])
            with self.assertRaises(ComplianceDefinitionError):
                FrameworkRepository([framework_path], [overlap])

    def test_snapshot_metadata_and_completion_semantics(self) -> None:
        """Framework metadata and zero-control completion semantics should be explicit."""

        repository = FrameworkRepository()
        framework = repository.get_framework("MICROSOFT_BASELINE", "WINDOWS_11_25H2_CSA_2026.1")

        self.assertEqual(framework.official_version, "Windows 11 25H2 security baseline")
        self.assertEqual(framework.snapshot_version, "CSA-MSB-WIN11-25H2-2026.1")
        self.assertEqual(framework.mapping_version, "CSA-MAP-2026.1")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            framework_path = _framework_path(root / "framework", [])
            profile_path = _profile_path(root / "profiles", {"CUSTOM_POLICY": "1.0"})
            custom_repository = FrameworkRepository([framework_path], [profile_path])
            mapping_repository = ControlMappingRepository(custom_repository, [], {"BIT-001"})
            summary = ComplianceEngine(
                repository=custom_repository,
                mapping_repository=mapping_repository,
            ).assess(_context(), [], [custom_repository.get_profile("custom_profile")])

        self.assertEqual(summary.overall_status, ComplianceStatus.NOT_ASSESSED)
        self.assertFalse(summary.framework_assessments[0].assessment_complete)


def _context(data: dict | None = None) -> AnalysisContext:
    """Create a test analysis context."""

    return AnalysisContext(raw_data=data or {}, software_inventory=build_inventory([]))


def _audit_finding(rule_id: str, status: Status) -> AuditFinding:
    """Create a test audit finding."""

    return AuditFinding(
        finding=Finding(rule_id=rule_id, severity=Severity.HIGH, status=status, score=0),
        knowledge=Knowledge(
            id=rule_id,
            title=rule_id,
            description="",
            risk="",
            recommendation="",
            frameworks={},
            references=[],
            knowledge_version="test",
        ),
    )


def _requirement(
    evidence_id: str,
    source_type: EvidenceSourceType,
    source_reference: str,
    expected_result,
    operator: str,
    extractor: str | None = None,
    parameters: dict | None = None,
) -> EvidenceRequirement:
    """Create a test evidence requirement."""

    return EvidenceRequirement(
        evidence_id=evidence_id,
        description="test",
        source_type=source_type,
        source_reference=source_reference,
        expected_result=expected_result,
        operator=operator,
        weight=1.0,
        mandatory=True,
        extractor=extractor,
        parameters=parameters or {},
    )


def _framework_path(
    directory: Path,
    controls: list[dict],
    version: str = "1.0",
) -> Path:
    """Write a minimal framework JSON file."""

    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "framework.json"
    path.write_text(
        json.dumps(
            {
                "framework": {
                    "id": "CUSTOM_POLICY",
                    "type": "CUSTOM_POLICY",
                    "name": "Custom Policy",
                    "version": version,
                    "publisher": "test",
                },
                "controls": controls,
            }
        ),
        encoding="utf-8",
    )
    return path


def _control(
    control_id: str,
    parent_control_id: str | None = None,
    requirements: list[dict] | None = None,
) -> dict:
    """Return a minimal control definition."""

    return {
        "id": control_id,
        "title": control_id,
        "description": "",
        "requirementLevel": "MUST",
        "scope": ["ENDPOINT"],
        "parentControlId": parent_control_id,
        "evidenceRequirements": requirements if requirements is not None else [_raw_requirement(f"{control_id}-E1", "Field", None, operator="EXISTS")],
        "references": [],
    }


def _raw_requirement(
    requirement_id: str,
    source_reference: str,
    expected,
    operator: str = "EQUALS",
    weight: float = 1.0,
    mandatory: bool = True,
) -> dict:
    """Return a raw-field evidence requirement."""

    return {
        "id": requirement_id,
        "sourceType": "RAW_FIELD",
        "sourceReference": source_reference,
        "operator": operator,
        "expectedResult": expected,
        "weight": weight,
        "mandatory": mandatory,
    }


def _finding_requirement(
    requirement_id: str,
    rule_id: str = "BIT-001",
    weight: float = 1.0,
    mandatory: bool = True,
) -> dict:
    """Return a finding evidence requirement."""

    return {
        "id": requirement_id,
        "sourceType": "FINDING",
        "sourceReference": rule_id,
        "operator": "STATUS_IS",
        "expectedResult": "PASS",
        "weight": weight,
        "mandatory": mandatory,
    }


def _mapping_path(
    directory: Path,
    control_ids: list[str],
    rule_id: str = "BIT-001",
    relationship: str = "SUPPORTS",
    confidence: int = 95,
    validated: bool = True,
    duplicate: bool = False,
) -> Path:
    """Write a minimal mapping JSON file."""

    directory.mkdir(parents=True, exist_ok=True)
    if not (directory / "framework.json").exists():
        _framework_path(directory, [_control("CTRL-1", requirements=[_finding_requirement("CTRL-1-E1", rule_id)])])
    mapping = {
        "ruleId": rule_id,
        "controlIds": control_ids,
        "relationship": relationship,
        "confidence": confidence,
        "notes": "test",
        "mapping_source": "test",
        "mapping_author": "test",
        "mapping_version": "test",
        "validated": validated,
        "validated_at": "2026-07-20" if validated else None,
    }
    data = {"mappings": [mapping, mapping] if duplicate else [mapping]}
    path = directory / "mappings.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _profile_path(
    directory: Path,
    framework_versions: dict[str, str],
    enabled: dict[str, list[str]] | None = None,
    excluded: dict[str, list[str]] | None = None,
) -> Path:
    """Write a minimal compliance profile JSON file."""

    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "custom_profile.json"
    path.write_text(
        json.dumps(
            {
                "profileId": "custom_profile",
                "name": "Custom Profile",
                "version": "2026.1",
                "operatingSystemPatterns": ["Windows"],
                "joinTypes": ["unknown"],
                "deviceRoles": ["workstation"],
                "frameworkVersions": framework_versions,
                "enabledControls": enabled or {},
                "excludedControls": excluded or {},
                "applicabilityTags": ["endpoint"],
                "policyOverrides": {},
            }
        ),
        encoding="utf-8",
    )
    return path


def _evaluate_custom_mapping(
    relationship: str,
    status: Status,
    confidence: int = 95,
    validated: bool = True,
):
    """Evaluate a one-control custom framework with a specific mapping."""

    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        control = _control("CTRL-1", requirements=[_finding_requirement("CTRL-1-E1")])
        framework_path = _framework_path(root / "framework", [control])
        mapping_path = _mapping_path(
            root / "framework",
            ["CTRL-1"],
            relationship=relationship,
            confidence=confidence,
            validated=validated,
        )
        profile_path = _profile_path(root / "profiles", {"CUSTOM_POLICY": "1.0"})
        repository = FrameworkRepository([framework_path], [profile_path])
        mapping_repository = ControlMappingRepository(repository, [mapping_path], {"BIT-001"})
        evaluator = ComplianceEvaluator(mapping_repository=mapping_repository)
        return evaluator.evaluate_control(
            repository.get_control("CUSTOM_POLICY", "CTRL-1", "1.0"),
            repository.get_profile("custom_profile"),
            _context(),
            [_audit_finding("BIT-001", status)],
        )


if __name__ == "__main__":
    unittest.main()
