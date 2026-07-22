"""Immutable models for versioned framework content packs."""

from __future__ import annotations

from dataclasses import dataclass, field

from frameworks.enums import (
    AutomationCapability,
    FrameworkControlLevel,
    FrameworkControlStatus,
    MappingStatus,
    MappingStrength,
    PackStatus,
)


@dataclass(frozen=True, slots=True)
class FrameworkSource:
    """Record the upstream source provenance for a pack."""

    publisher: str
    release: str | None
    published_at: str | None
    retrieved_at: str
    reference: str
    digest_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class RuleMapping:
    """Map one CSA rule to one framework control."""

    rule_id: str
    strength: MappingStrength
    status: MappingStatus
    rationale: str
    evidence_limitations: tuple[str, ...] = ()
    reviewer: str | None = None
    reviewed_at: str | None = None
    source_reference: str | None = None


@dataclass(frozen=True, slots=True)
class FrameworkControl:
    """Describe one framework control without duplicating rule logic."""

    control_id: str
    title: str
    section: str
    profile: tuple[str, ...]
    level: FrameworkControlLevel
    automation: AutomationCapability
    mappings: tuple[RuleMapping, ...] = ()
    tags: tuple[str, ...] = ()
    notes: str | None = None


@dataclass(frozen=True, slots=True)
class FrameworkPack:
    """Represent one immutable, versioned framework content pack."""

    schema_version: str
    framework_id: str
    name: str
    version: str
    status: PackStatus
    source: FrameworkSource
    scope: tuple[str, ...]
    license_notice: str
    created_at: str
    updated_at: str
    maintainer: str
    minimum_csa_version: str
    deprecated: bool
    supersedes: str | None
    superseded_by: str | None
    controls: tuple[FrameworkControl, ...]
    content_hash_sha256: str


@dataclass(frozen=True, slots=True)
class AssessmentPolicy:
    """Hold explicit applicability decisions for an assessment."""

    not_applicable_controls: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class FrameworkControlResult:
    """Hold the endpoint assessment and traceability for one control."""

    framework_id: str
    framework_version: str
    control_id: str
    title: str
    status: FrameworkControlStatus
    automation: AutomationCapability
    mapped_rule_ids: tuple[str, ...]
    passed_rule_ids: tuple[str, ...]
    failed_rule_ids: tuple[str, ...]
    unavailable_rule_ids: tuple[str, ...]
    provisional_rule_ids: tuple[str, ...]
    confidence: int
    limitations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FrameworkCoverage:
    """Hold explicitly named framework coverage metrics."""

    framework_control_count: int = 0
    mapped_control_count: int = 0
    unmapped_control_count: int = 0
    automated_control_count: int = 0
    partially_automated_control_count: int = 0
    manual_control_count: int = 0
    assessable_control_count: int = 0
    evaluated_control_count: int = 0
    satisfied_control_count: int = 0
    not_satisfied_control_count: int = 0
    partially_satisfied_control_count: int = 0
    not_assessable_control_count: int = 0
    mapping_coverage_percent: float = 0.0
    technical_automation_coverage_percent: float = 0.0
    assessment_coverage_percent: float = 0.0
    satisfied_assessable_controls_percent: float = 0.0


@dataclass(frozen=True, slots=True)
class FrameworkEvaluation:
    """Hold one pack's results, coverage, digest, and warnings."""

    pack: FrameworkPack
    results: tuple[FrameworkControlResult, ...]
    coverage: FrameworkCoverage
    evaluated_at: str
    warnings: tuple[str, ...] = field(default_factory=tuple)
