"""Collector capability registry and collection profile loading."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from csa_console.canonical import sha256_value
from csa_console.models import CollectorCapabilityDefinition

DEFAULT_REGISTRY_PATH = (
    Path(__file__).resolve().parents[1]
    / "collector"
    / "windows"
    / "collection-capabilities.json"
)
DEFAULT_PROFILE_PATH = (
    Path(__file__).resolve().parents[1]
    / "collector"
    / "windows"
    / "profiles"
    / "windows-standard-v1.json"
)


class CapabilityRegistry:
    """Load and validate self-describing collection capabilities."""

    def __init__(self, path: str | Path = DEFAULT_REGISTRY_PATH) -> None:
        """Load a capability registry from JSON."""

        self.path = Path(path)
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or not isinstance(raw.get("capabilities"), list):
            raise ValueError("Capability registry must contain a capabilities list")
        self.version = str(raw.get("version", ""))
        self._definitions: dict[str, CollectorCapabilityDefinition] = {}
        for item in raw["capabilities"]:
            definition = CollectorCapabilityDefinition.from_dict(item)
            if definition.capability_id in self._definitions:
                raise ValueError(
                    f"Duplicate capability ID: {definition.capability_id}"
                )
            if definition.timeout_seconds < 1:
                raise ValueError(
                    f"Invalid capability timeout: {definition.capability_id}"
                )
            self._definitions[definition.capability_id] = definition

    def get(self, capability_id: str) -> CollectorCapabilityDefinition:
        """Return one capability definition."""

        try:
            return self._definitions[capability_id]
        except KeyError as error:
            raise KeyError(f"Unknown capability: {capability_id}") from error

    def get_all(self) -> list[CollectorCapabilityDefinition]:
        """Return all capabilities in deterministic order."""

        return [self._definitions[key] for key in sorted(self._definitions)]

    def for_module(self, module: str) -> list[CollectorCapabilityDefinition]:
        """Return capabilities implemented by a PowerShell module."""

        return [
            item
            for item in self.get_all()
            if item.module.casefold() == module.casefold()
        ]


class CollectionProfile:
    """Represent an ordered capability selection and privacy policy."""

    def __init__(self, data: dict[str, Any], source_path: Path) -> None:
        """Create a validated collection profile."""

        self.profile_id = str(data["profileId"])
        self.version = str(data["version"])
        self.collector_mode = str(data["collectorMode"])
        self.capability_ids = [str(item) for item in data["capabilities"]]
        self.privacy_policy = str(data["privacyPolicy"])
        self.source_path = source_path
        self.digest = sha256_value(data)

    @classmethod
    def load(
        cls,
        path: str | Path = DEFAULT_PROFILE_PATH,
        registry: CapabilityRegistry | None = None,
    ) -> "CollectionProfile":
        """Load and validate a collection profile."""

        source = Path(path)
        raw = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Collection profile root must be an object")
        profile = cls(raw, source)
        active_registry = registry or CapabilityRegistry()
        unknown = [
            item
            for item in profile.capability_ids
            if item not in {definition.capability_id for definition in active_registry.get_all()}
        ]
        if unknown:
            raise ValueError(f"Unknown profile capabilities: {', '.join(unknown)}")
        if len(profile.capability_ids) != len(set(profile.capability_ids)):
            raise ValueError("Collection profile contains duplicate capabilities")
        return profile
