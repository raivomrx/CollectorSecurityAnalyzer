"""Load compliance framework and profile JSON files."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

from compliance.enums import AssessmentScope, EvidenceSourceType, FrameworkType, RequirementLevel
from compliance.models import (
    ComplianceProfile,
    ControlDefinition,
    EvidenceRequirement,
    FrameworkDefinition,
)

BASE_DIR = Path(__file__).resolve().parent
FRAMEWORKS_DIR = BASE_DIR / "frameworks"
PROFILES_DIR = BASE_DIR / "profiles"


def load_framework(path: str | Path) -> FrameworkDefinition:
    """Load one framework definition file."""

    data = _load_json(path)
    framework = data["framework"]
    framework_id = str(framework["id"])
    framework_version = str(framework["version"])
    controls = [_parse_control(framework_id, framework_version, item) for item in data.get("controls", [])]
    return FrameworkDefinition(
        framework_id=framework_id,
        framework_type=FrameworkType(framework.get("type", framework_id)),
        name=str(framework["name"]),
        version=str(framework["version"]),
        publisher=str(framework.get("publisher", "")),
        effective_date=_parse_date(framework.get("effectiveDate")),
        source_url=framework.get("sourceUrl"),
        description=str(framework.get("description", "")),
        language=str(framework.get("language", "en")),
        controls=controls,
        metadata=framework.get("metadata", {}) if isinstance(framework.get("metadata", {}), dict) else {},
        official_version=str(framework.get("officialVersion", framework.get("version", ""))),
        snapshot_version=str(framework.get("snapshotVersion", framework.get("version", ""))),
        mapping_version=str(framework.get("mappingVersion", framework.get("snapshotVersion", framework.get("version", "")))),
        source_retrieved_at=_parse_date(framework.get("sourceRetrievedAt")),
        source_hash=framework.get("sourceHash"),
    )


def load_profile(path: str | Path) -> ComplianceProfile:
    """Load one compliance profile."""

    data = _load_json(path)
    return ComplianceProfile(
        profile_id=str(data["profileId"]),
        name=str(data["name"]),
        version=str(data["version"]),
        description=str(data.get("description", "")),
        operating_system_patterns=[str(item) for item in data.get("operatingSystemPatterns", [])],
        join_types=[str(item) for item in data.get("joinTypes", [])],
        device_roles=[str(item) for item in data.get("deviceRoles", [])],
        framework_versions={str(k): str(v) for k, v in data.get("frameworkVersions", {}).items()},
        enabled_controls={str(k): [str(item) for item in v] for k, v in data.get("enabledControls", {}).items()},
        excluded_controls={str(k): [str(item) for item in v] for k, v in data.get("excludedControls", {}).items()},
        applicability_tags=[str(item) for item in data.get("applicabilityTags", [])],
        policy_overrides=data.get("policyOverrides", {}) if isinstance(data.get("policyOverrides", {}), dict) else {},
    )


def discover_framework_paths(root: str | Path = FRAMEWORKS_DIR) -> list[Path]:
    """Return framework definition paths."""

    return sorted(Path(root).glob("**/framework.json"))


def discover_profile_paths(root: str | Path = PROFILES_DIR) -> list[Path]:
    """Return profile definition paths."""

    return sorted(Path(root).glob("*.json"))


def discover_mapping_paths(root: str | Path = FRAMEWORKS_DIR) -> list[Path]:
    """Return rule-control mapping definition paths."""

    return sorted(Path(root).glob("**/mappings.json"))


def _parse_control(framework_id: str, framework_version: str, item: dict[str, Any]) -> ControlDefinition:
    """Parse one control definition."""

    return ControlDefinition(
        control_id=str(item["id"]),
        framework_id=framework_id,
        framework_version=framework_version,
        title=str(item.get("title", "")),
        description=str(item.get("description", "")),
        requirement_level=RequirementLevel(item.get("requirementLevel", "MUST")),
        scope=[AssessmentScope(value) for value in item.get("scope", ["ENDPOINT"])],
        parent_control_id=item.get("parentControlId"),
        implementation_groups=[str(value) for value in item.get("implementationGroups", [])],
        applicability_tags=[str(value) for value in item.get("applicabilityTags", [])],
        evidence_requirements=[_parse_requirement(req) for req in item.get("evidenceRequirements", [])],
        references=[str(value) for value in item.get("references", [])],
        metadata=item.get("metadata", {}) if isinstance(item.get("metadata", {}), dict) else {},
        official_control_id=item.get("officialControlId"),
        csa_objective_id=item.get("csaObjectiveId") or str(item["id"]),
    )


def _parse_requirement(item: dict[str, Any]) -> EvidenceRequirement:
    """Parse one evidence requirement."""

    return EvidenceRequirement(
        evidence_id=str(item["id"]),
        description=str(item.get("description", "")),
        source_type=EvidenceSourceType(item["sourceType"]),
        source_reference=str(item.get("sourceReference", "")),
        expected_result=item.get("expectedResult"),
        operator=str(item.get("operator", "EXISTS")),
        weight=float(item.get("weight", 1.0)),
        mandatory=bool(item.get("mandatory", True)),
        extractor=item.get("extractor"),
        parameters=item.get("parameters", {}) if isinstance(item.get("parameters", {}), dict) else {},
    )


def _load_json(path: str | Path) -> dict[str, Any]:
    """Load a JSON object."""

    with Path(path).open("r", encoding="utf-8-sig") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return data


def _parse_date(value: Any) -> date | None:
    """Parse optional date."""

    if not value:
        return None
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None
