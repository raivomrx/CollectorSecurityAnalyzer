"""Versioned active validator registry."""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any

from active_validation.enums import RiskLevel, ValidatorStatus
from active_validation.json_io import load_strict_json
from active_validation.models import RegistryEntry, ValidatorDefinition
from active_validation.protocol import ActiveValidator

DEFAULT_REGISTRY_PATH = Path(__file__).with_name("registry.json")


class ValidatorRegistryError(ValueError):
    """Report invalid validator registry content."""


class ValidatorRegistry:
    """Load reviewed validator plug-ins without filesystem discovery."""

    def __init__(self, path: str | Path = DEFAULT_REGISTRY_PATH) -> None:
        """Load and validate the versioned registry."""

        document = load_strict_json(path)
        if document.get("schemaVersion") != "1.0":
            raise ValidatorRegistryError("Unsupported validator registry schema")
        raw_entries = document.get("validators")
        if not isinstance(raw_entries, list):
            raise ValidatorRegistryError("Registry validators must be an array")
        self._entries: dict[str, RegistryEntry] = {}
        for raw in raw_entries:
            entry = self._parse_entry(raw)
            if entry.validator_id in self._entries:
                raise ValidatorRegistryError(
                    f"Duplicate validator ID: {entry.validator_id}"
                )
            self._entries[entry.validator_id] = entry
            self._validate_implementation(entry)

    def get(self, validator_id: str) -> RegistryEntry | None:
        """Return one registry entry by validator ID."""

        return self._entries.get(validator_id)

    def get_all(self) -> list[RegistryEntry]:
        """Return all entries in deterministic order."""

        return [self._entries[key] for key in sorted(self._entries)]

    def get_active(self) -> list[RegistryEntry]:
        """Return only reviewed ACTIVE entries."""

        return [
            entry
            for entry in self.get_all()
            if entry.status == ValidatorStatus.ACTIVE
        ]

    def instantiate(self, entry: RegistryEntry) -> ActiveValidator:
        """Instantiate a registered validator class."""

        module = importlib.import_module(entry.module)
        validator_class = getattr(module, entry.class_name)
        return validator_class()

    def definition(self, entry: RegistryEntry) -> ValidatorDefinition:
        """Return and validate one implementation definition."""

        definition = self.instantiate(entry).describe()
        self._validate_definition(entry, definition)
        return definition

    def _validate_implementation(self, entry: RegistryEntry) -> None:
        """Reject unsafe registry/implementation mismatches at startup."""

        definition = self.definition(entry)
        if (
            definition.risk_level == RiskLevel.PROHIBITED
            and entry.status == ValidatorStatus.ACTIVE
        ):
            raise ValidatorRegistryError(
                f"Prohibited validator cannot be ACTIVE: {entry.validator_id}"
            )

    @staticmethod
    def _parse_entry(raw: Any) -> RegistryEntry:
        """Parse one strict registry entry."""

        if not isinstance(raw, dict):
            raise ValidatorRegistryError("Registry entry must be an object")
        required = {
            "validatorId",
            "version",
            "module",
            "class",
            "status",
            "supportedRuleIds",
        }
        if set(raw) != required:
            raise ValidatorRegistryError("Registry entry fields are invalid")
        try:
            status = ValidatorStatus(raw["status"])
        except ValueError as error:
            raise ValidatorRegistryError("Invalid validator status") from error
        rules = raw["supportedRuleIds"]
        if not isinstance(rules, list) or any(
            not isinstance(item, str) for item in rules
        ):
            raise ValidatorRegistryError("supportedRuleIds must be a string array")
        return RegistryEntry(
            validator_id=str(raw["validatorId"]),
            version=str(raw["version"]),
            module=str(raw["module"]),
            class_name=str(raw["class"]),
            status=status,
            supported_rule_ids=tuple(rules),
        )

    @staticmethod
    def _validate_definition(
        entry: RegistryEntry,
        definition: ValidatorDefinition,
    ) -> None:
        """Validate reviewed metadata against implementation metadata."""

        if (
            definition.validator_id != entry.validator_id
            or definition.version != entry.version
            or definition.supported_rule_ids != entry.supported_rule_ids
        ):
            raise ValidatorRegistryError(
                f"Validator definition mismatch: {entry.validator_id}"
            )
        if definition.default_timeout_seconds < 1:
            raise ValidatorRegistryError("Validator timeout must be positive")
        if definition.maximum_timeout_seconds < definition.default_timeout_seconds:
            raise ValidatorRegistryError("Maximum timeout is below default timeout")
