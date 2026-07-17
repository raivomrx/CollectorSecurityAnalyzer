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
            repository.get_framework("MICROSOFT_BASELINE", "WINDOWS_11_25H2_1.0").framework_id,
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
        control = repository.get_control("MICROSOFT_BASELINE", "MSB-BITLOCKER-001", "WINDOWS_11_25H2_1.0")
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


def _control(control_id: str, parent_control_id: str | None = None) -> dict:
    """Return a minimal control definition."""

    return {
        "id": control_id,
        "title": control_id,
        "description": "",
        "requirementLevel": "MUST",
        "scope": ["ENDPOINT"],
        "parentControlId": parent_control_id,
        "evidenceRequirements": [
            {
                "id": f"{control_id}-E1",
                "sourceType": "RAW_FIELD",
                "sourceReference": "Field",
                "operator": "EXISTS",
                "weight": 1.0,
                "mandatory": True,
            }
        ],
        "references": [],
    }


if __name__ == "__main__":
    unittest.main()
