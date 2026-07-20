"""Repository for versioned compliance frameworks and profiles."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from compliance.enums import MappingRelationship
from compliance.exceptions import ComplianceDefinitionError
from compliance.loader import (
    discover_framework_paths,
    discover_mapping_paths,
    discover_profile_paths,
    load_framework,
    load_profile,
)
from compliance.models import ComplianceProfile, FrameworkDefinition, RuleControlMapping
from compliance.validation import ComplianceDefinitionValidator
from rules.loader import load_registry

LOGGER = logging.getLogger(__name__)


class FrameworkRepository:
    """Load and serve versioned compliance frameworks."""

    def __init__(
        self,
        framework_paths: list[Path] | None = None,
        profile_paths: list[Path] | None = None,
    ) -> None:
        """Create a repository."""

        self.validator = ComplianceDefinitionValidator()
        self._frameworks: dict[tuple[str, str], FrameworkDefinition] = {}
        self._profiles: dict[str, ComplianceProfile] = {}
        self._load_frameworks(discover_framework_paths() if framework_paths is None else framework_paths)
        self._load_profiles(discover_profile_paths() if profile_paths is None else profile_paths)

    def get_framework(self, framework_id: str, version: str | None = None) -> FrameworkDefinition:
        """Return a framework by explicit version or the only available version."""

        matches = [
            framework for (fid, fversion), framework in self._frameworks.items()
            if fid == framework_id and (version is None or fversion == version)
        ]
        if not matches:
            raise ComplianceDefinitionError(f"Unknown framework/version: {framework_id} {version or ''}".strip())
        if version is None and len(matches) > 1:
            raise ComplianceDefinitionError(f"Framework version must be explicit: {framework_id}")
        return matches[0]

    def get_control(self, framework_id: str, control_id: str, version: str | None = None):
        """Return one control."""

        framework = self.get_framework(framework_id, version)
        for control in framework.controls:
            if control.control_id == control_id:
                return control
        raise ComplianceDefinitionError(f"Unknown control: {framework_id}:{control_id}")

    def list_frameworks(self) -> list[FrameworkDefinition]:
        """Return loaded frameworks."""

        return list(self._frameworks.values())

    def get_profile(self, profile_id: str) -> ComplianceProfile:
        """Return a compliance profile."""

        profile = self._profiles.get(profile_id)
        if profile is None:
            raise ComplianceDefinitionError(f"Unknown compliance profile: {profile_id}")
        return profile

    def list_profiles(self) -> list[ComplianceProfile]:
        """Return loaded profiles."""

        return list(self._profiles.values())

    def _load_frameworks(self, paths: list[Path]) -> None:
        """Load framework files."""

        for path in paths:
            framework = load_framework(path)
            self.validator.validate_framework(framework)
            key = (framework.framework_id, framework.version)
            if key in self._frameworks:
                raise ComplianceDefinitionError(f"Duplicate framework version: {key}")
            self._frameworks[key] = framework

    def _load_profiles(self, paths: list[Path]) -> None:
        """Load profile files."""

        for path in paths:
            profile = load_profile(path)
            self.validator.validate_profile(profile, self._frameworks)
            self._profiles[profile.profile_id] = profile


class ControlMappingRepository:
    """Load and serve rule-control mappings by rule and control."""

    def __init__(
        self,
        framework_repository: FrameworkRepository | None = None,
        mapping_paths: list[Path] | None = None,
        known_rules: set[str] | None = None,
    ) -> None:
        """Create a mapping repository."""

        self.framework_repository = framework_repository or FrameworkRepository()
        self.validator = ComplianceDefinitionValidator()
        self._by_rule: dict[str, list[RuleControlMapping]] = {}
        self._by_control: dict[tuple[str, str, str], list[RuleControlMapping]] = {}
        self._warnings: list[str] = []
        self._load_mappings(
            discover_mapping_paths() if mapping_paths is None else mapping_paths,
            known_rules if known_rules is not None else _registered_rule_ids(),
        )

    @property
    def warnings(self) -> list[str]:
        """Return non-fatal mapping warnings."""

        return list(self._warnings)

    def get_by_rule(self, rule_id: str) -> list[RuleControlMapping]:
        """Return mappings for a rule ID."""

        return list(self._by_rule.get(rule_id, []))

    def get_by_control(
        self,
        framework_id: str,
        framework_version: str,
        control_id: str,
    ) -> list[RuleControlMapping]:
        """Return mappings for one framework control."""

        return list(self._by_control.get((framework_id, framework_version, control_id), []))

    def _load_mappings(self, paths: list[Path], known_rules: set[str]) -> None:
        """Load and validate mapping files."""

        seen: set[tuple[str, str, str, str, str]] = set()
        frameworks = self.framework_repository._frameworks
        for path in paths:
            framework = self._framework_for_mapping(path)
            for mapping in load_mappings(path, framework.framework_id, framework.version):
                self.validator.validate_mapping(mapping, known_rules, frameworks)
                self._by_rule.setdefault(mapping.rule_id, []).append(mapping)
                for control_id in mapping.control_ids:
                    key = (
                        mapping.rule_id,
                        mapping.framework_id,
                        mapping.framework_version,
                        control_id,
                        mapping.relationship.value,
                    )
                    if key in seen:
                        raise ComplianceDefinitionError(f"Duplicate mapping: {key}")
                    seen.add(key)
                    self._by_control.setdefault(
                        (mapping.framework_id, mapping.framework_version, control_id),
                        [],
                    ).append(mapping)
                if not mapping.validated and mapping.confidence >= 80:
                    self._warnings.append(
                        f"Unvalidated high-confidence mapping: {mapping.rule_id} "
                        f"{mapping.framework_id} {mapping.framework_version}"
                    )

    def _framework_for_mapping(self, path: Path) -> FrameworkDefinition:
        """Return parent framework for a mapping file."""

        framework_path = path.parent / "framework.json"
        framework = load_framework(framework_path)
        return self.framework_repository.get_framework(framework.framework_id, framework.version)


def load_mappings(
    path: str | Path,
    framework_id: str = "",
    framework_version: str = "",
) -> list[RuleControlMapping]:
    """Load rule-control mappings."""

    with Path(path).open("r", encoding="utf-8") as handle:
        data: Any = json.load(handle)
    mappings = []
    for item in data.get("mappings", []) if isinstance(data, dict) else []:
        mappings.append(
            RuleControlMapping(
                rule_id=str(item["ruleId"]),
                control_ids=[str(value) for value in item.get("controlIds", [])],
                relationship=MappingRelationship(item.get("relationship", "SUPPORTS")),
                confidence=int(item.get("confidence", 0)),
                notes=str(item.get("notes", "")),
                mapping_source=str(item.get("mapping_source", "")),
                mapping_author=str(item.get("mapping_author", "")),
                mapping_version=str(item.get("mapping_version", "")),
                validated=bool(item.get("validated", False)),
                validated_at=item.get("validated_at"),
                framework_id=str(item.get("frameworkId", framework_id)),
                framework_version=str(item.get("frameworkVersion", framework_version)),
            )
        )
    return mappings


def _registered_rule_ids() -> set[str]:
    """Return currently registered CSA rule IDs."""

    registry = load_registry(log_startup=False)
    return {
        metadata.id
        for execution in registry.get_execution_info()
        for metadata in [registry.get_metadata(execution.rule_id)]
        if metadata is not None
    }
