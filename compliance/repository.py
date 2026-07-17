"""Repository for versioned compliance frameworks and profiles."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from compliance.enums import MappingRelationship
from compliance.exceptions import ComplianceDefinitionError
from compliance.loader import discover_framework_paths, discover_profile_paths, load_framework, load_profile
from compliance.models import ComplianceProfile, FrameworkDefinition, RuleControlMapping
from compliance.validation import ComplianceDefinitionValidator

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
        self._load_frameworks(framework_paths or discover_framework_paths())
        self._load_profiles(profile_paths or discover_profile_paths())

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

        framework_by_id = {framework.framework_id: framework for framework in self._frameworks.values()}
        for path in paths:
            profile = load_profile(path)
            self.validator.validate_profile(profile, framework_by_id)
            self._profiles[profile.profile_id] = profile


def load_mappings(path: str | Path) -> list[RuleControlMapping]:
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
            )
        )
    return mappings
