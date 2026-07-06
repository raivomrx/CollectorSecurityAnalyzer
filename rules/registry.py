"""Rule registry for self-describing analyzer rules."""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass

from risk import Severity
from rules.base import BaseRule
from rules.categories import RuleCategory
from rules.metadata import RuleMetadata

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class RuleExecutionInfo:
    """Report-ready execution metadata for one rule."""

    rule_id: str
    version: str
    category: RuleCategory
    severity: Severity
    enabled: bool
    execution_time_ms: float | None = None
    result: str | None = None


class RuleRegistry:
    """Store rule classes and metadata by rule identifier."""

    def __init__(self) -> None:
        """Create an empty rule registry."""

        self._rules: dict[str, type[BaseRule]] = {}
        self._metadata: dict[str, RuleMetadata] = {}

    def register(self, rule_class: type[BaseRule]) -> None:
        """Register a rule class when its metadata is valid."""

        metadata = getattr(rule_class, "metadata", None)
        if not self._is_valid_metadata(rule_class, metadata):
            return

        assert isinstance(metadata, RuleMetadata)
        if metadata.id in self._rules:
            LOGGER.warning("Duplicate Rule ID detected: %s", metadata.id)
            return

        self._rules[metadata.id] = rule_class
        self._metadata[metadata.id] = metadata

    def get(self, rule_id: str) -> type[BaseRule] | None:
        """Return a registered rule class by id."""

        return self._rules.get(rule_id)

    def get_all(self) -> list[BaseRule]:
        """Return instantiated registered rules."""

        return [
            self._rules[rule_id]()
            for rule_id in sorted(self._rules)
        ]

    def get_enabled(self) -> list[BaseRule]:
        """Return instantiated enabled rules."""

        return [
            self._rules[rule_id]()
            for rule_id in sorted(self._rules)
            if self._metadata[rule_id].enabled
        ]

    def get_categories(self) -> list[RuleCategory]:
        """Return categories used by registered rules."""

        return sorted(
            {metadata.category for metadata in self._metadata.values()},
            key=lambda category: category.value,
        )

    def get_metadata(self, rule_id: str) -> RuleMetadata | None:
        """Return metadata for a registered rule id."""

        return self._metadata.get(rule_id)

    def get_statistics(self) -> dict[str, object]:
        """Return registry statistics for startup logs and reports."""

        total = len(self._metadata)
        enabled = sum(1 for metadata in self._metadata.values() if metadata.enabled)
        categories = Counter(metadata.category.value for metadata in self._metadata.values())
        severities = Counter(metadata.severity.value for metadata in self._metadata.values())
        return {
            "total_rules": total,
            "enabled_rules": enabled,
            "disabled_rules": total - enabled,
            "rules_by_category": dict(categories),
            "rules_by_severity": dict(severities),
        }

    def get_execution_info(self) -> list[RuleExecutionInfo]:
        """Return report-ready rule execution placeholders."""

        return [
            RuleExecutionInfo(
                rule_id=metadata.id,
                version=metadata.version,
                category=metadata.category,
                severity=metadata.severity,
                enabled=metadata.enabled,
            )
            for rule_id in sorted(self._metadata)
            for metadata in [self._metadata[rule_id]]
        ]

    def _is_valid_metadata(self, rule_class: type[BaseRule], metadata: object) -> bool:
        """Validate required metadata fields for a rule class."""

        if not isinstance(metadata, RuleMetadata):
            LOGGER.warning("Rule metadata missing or invalid: %s", rule_class.__name__)
            return False

        required = {
            "id": metadata.id,
            "version": metadata.version,
            "category": metadata.category,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            LOGGER.warning(
                "Rule metadata incomplete for %s: %s",
                rule_class.__name__,
                ", ".join(missing),
            )
            return False

        if not isinstance(metadata.category, RuleCategory):
            LOGGER.warning("Rule metadata category invalid for %s", rule_class.__name__)
            return False

        if not isinstance(metadata.severity, Severity):
            LOGGER.warning("Rule metadata severity invalid for %s", rule_class.__name__)
            return False

        return True
