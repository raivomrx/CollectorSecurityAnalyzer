"""Compliance and policy intelligence data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

from compliance.enums import (
    AssessmentScope,
    ComplianceStatus,
    EvidenceResult,
    EvidenceSourceType,
    FrameworkType,
    MappingRelationship,
    RequirementLevel,
)


@dataclass(slots=True)
class EvidenceRequirement:
    """Describe one evidence requirement for a control."""

    evidence_id: str
    description: str
    source_type: EvidenceSourceType
    source_reference: str
    expected_result: str | bool | int | float | list[str] | None
    operator: str
    weight: float
    mandatory: bool
    extractor: str | None = None
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ControlDefinition:
    """Define one framework control."""

    control_id: str
    framework_id: str
    title: str
    description: str
    requirement_level: RequirementLevel
    scope: list[AssessmentScope]
    parent_control_id: str | None
    implementation_groups: list[str]
    applicability_tags: list[str]
    evidence_requirements: list[EvidenceRequirement]
    references: list[str]
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class FrameworkDefinition:
    """Define a versioned compliance framework snapshot."""

    framework_id: str
    framework_type: FrameworkType
    name: str
    version: str
    publisher: str
    effective_date: date | None
    source_url: str | None
    description: str
    language: str
    controls: list[ControlDefinition]
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class EvidenceRecord:
    """Represent evaluated evidence for a control."""

    evidence_id: str
    source_type: EvidenceSourceType
    source_reference: str
    result: EvidenceResult
    actual_value: Any
    expected_value: Any
    description: str
    confidence: int
    collected_at: datetime | None
    evaluated_at: datetime
    provenance: str


@dataclass(slots=True)
class ControlAssessment:
    """Represent one control assessment."""

    control: ControlDefinition
    status: ComplianceStatus
    score: float | None
    confidence: int
    evidence: list[EvidenceRecord]
    rationale: str
    remediation: str | None
    applicable: bool
    manual_review_required: bool
    related_findings: list[str]
    assessed_at: datetime


@dataclass(slots=True)
class FrameworkAssessment:
    """Represent assessment output for one framework."""

    framework: FrameworkDefinition
    profile_id: str
    profile_version: str
    controls: list[ControlAssessment]
    compliant_count: int
    non_compliant_count: int
    partially_compliant_count: int
    not_assessed_count: int
    not_applicable_count: int
    manual_review_count: int
    assessed_controls: int
    applicable_controls: int
    evidence_coverage_percent: float
    weighted_score_percent: float | None
    assessment_complete: bool
    warnings: list[str]
    assessed_at: datetime


@dataclass(slots=True)
class ComplianceSummary:
    """Represent all compliance assessments for one analyzer run."""

    profile_ids: list[str]
    framework_assessments: list[FrameworkAssessment]
    total_controls: int
    applicable_controls: int
    assessed_controls: int
    evidence_coverage_percent: float
    overall_status: ComplianceStatus
    warnings: list[str]


@dataclass(slots=True)
class ComplianceProfile:
    """Define a compliance assessment profile."""

    profile_id: str
    name: str
    version: str
    description: str
    operating_system_patterns: list[str]
    join_types: list[str]
    device_roles: list[str]
    framework_versions: dict[str, str]
    enabled_controls: dict[str, list[str]]
    excluded_controls: dict[str, list[str]]
    applicability_tags: list[str]
    policy_overrides: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RuleControlMapping:
    """Map CSA rule IDs to framework controls."""

    rule_id: str
    control_ids: list[str]
    relationship: MappingRelationship
    confidence: int
    notes: str
    mapping_source: str
    mapping_author: str
    mapping_version: str
    validated: bool
    validated_at: str | None
