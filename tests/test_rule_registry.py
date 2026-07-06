"""Tests for the rule registry."""

from __future__ import annotations

import unittest
from typing import Any

from risk import Finding, Severity
from rules.base import BaseRule
from rules.categories import RuleCategory
from rules.loader import load_registry
from rules.metadata import RuleMetadata
from rules.registry import RuleRegistry


class RuleRegistryTests(unittest.TestCase):
    """Validate rule registry behavior."""

    def test_01_loader_registers_existing_rules(self) -> None:
        """Loader should discover and register the six existing rules."""

        registry = load_registry()

        self.assertEqual(len(registry.get_all()), 6)
        self.assertEqual(len(registry.get_enabled()), 6)
        self.assertIsNotNone(registry.get("BIT-001"))

    def test_duplicate_rule_id_logs_warning(self) -> None:
        """Duplicate rule ids should be ignored with a warning."""

        class FirstDuplicateRule(BaseRule):
            metadata = _metadata("DUP-001")

            def check(self, data: dict[str, Any]) -> list[Finding]:
                return []

        class SecondDuplicateRule(BaseRule):
            metadata = _metadata("DUP-001")

            def check(self, data: dict[str, Any]) -> list[Finding]:
                return []

        registry = RuleRegistry()
        registry.register(FirstDuplicateRule)
        with self.assertLogs("rules.registry", level="WARNING") as logs:
            registry.register(SecondDuplicateRule)

        self.assertEqual(len(registry.get_all()), 1)
        self.assertIn("Duplicate Rule ID detected: DUP-001", "\n".join(logs.output))

    def test_disabled_rule_is_ignored_by_get_enabled(self) -> None:
        """Disabled rules should remain registered but not returned as enabled."""

        class DisabledRule(BaseRule):
            metadata = _metadata("DIS-001", enabled=False)

            def check(self, data: dict[str, Any]) -> list[Finding]:
                return []

        registry = RuleRegistry()
        registry.register(DisabledRule)

        self.assertEqual(len(registry.get_all()), 1)
        self.assertEqual(registry.get_enabled(), [])

    def test_category_statistics(self) -> None:
        """Registry statistics should include counts by category."""

        class EncryptionRule(BaseRule):
            metadata = _metadata("ENC-001", category=RuleCategory.ENCRYPTION)

            def check(self, data: dict[str, Any]) -> list[Finding]:
                return []

        class NetworkRule(BaseRule):
            metadata = _metadata("NET-TST-001", category=RuleCategory.NETWORK)

            def check(self, data: dict[str, Any]) -> list[Finding]:
                return []

        registry = RuleRegistry()
        registry.register(EncryptionRule)
        registry.register(NetworkRule)

        statistics = registry.get_statistics()
        self.assertEqual(statistics["rules_by_category"]["Encryption"], 1)
        self.assertEqual(statistics["rules_by_category"]["Network"], 1)

    def test_metadata_validation_logs_warning(self) -> None:
        """Rules without metadata should not be registered."""

        class MissingMetadataRule(BaseRule):
            def check(self, data: dict[str, Any]) -> list[Finding]:
                return []

        registry = RuleRegistry()
        with self.assertLogs("rules.registry", level="WARNING") as logs:
            registry.register(MissingMetadataRule)

        self.assertEqual(registry.get_all(), [])
        self.assertIn("Rule metadata missing or invalid", "\n".join(logs.output))


def _metadata(
    rule_id: str,
    category: RuleCategory = RuleCategory.COMPLIANCE,
    enabled: bool = True,
) -> RuleMetadata:
    """Create test metadata."""

    return RuleMetadata(
        id=rule_id,
        title="Test Rule",
        version="1.0",
        author="CSA",
        category=category,
        severity=Severity.LOW,
        enabled=enabled,
        description="Test rule metadata.",
    )


if __name__ == "__main__":
    unittest.main()
