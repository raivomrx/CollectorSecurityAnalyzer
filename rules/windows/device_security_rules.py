"""Windows device security evidence-backed rules."""

from __future__ import annotations

from risk import Severity
from rules.categories import RuleCategory
from rules.windows.common import SettingRuleSpec, create_setting_rule

SPECS = [
    SettingRuleSpec("DEV-001", "Secure Boot disabled", RuleCategory.DEVICE_SECURITY, "SECURE_BOOT_ENABLED", True, Severity.HIGH),
    SettingRuleSpec("DEV-002", "TPM unavailable or not ready", RuleCategory.DEVICE_SECURITY, "TPM_READY", True, Severity.HIGH),
    SettingRuleSpec("DEV-003", "VBS disabled", RuleCategory.DEVICE_SECURITY, "VBS_RUNNING", True, Severity.MEDIUM),
    SettingRuleSpec("DEV-004", "Credential Guard disabled", RuleCategory.DEVICE_SECURITY, "CREDENTIAL_GUARD_RUNNING", True, Severity.MEDIUM),
    SettingRuleSpec("DEV-005", "Memory Integrity disabled", RuleCategory.DEVICE_SECURITY, "MEMORY_INTEGRITY_ENABLED", True, Severity.MEDIUM),
]

for spec in SPECS:
    rule_class = create_setting_rule(spec)
    globals()[rule_class.__name__] = rule_class
