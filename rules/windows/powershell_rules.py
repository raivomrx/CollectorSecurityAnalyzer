"""Windows PowerShell hardening evidence-backed rules."""

from __future__ import annotations

from risk import Severity
from rules.categories import RuleCategory
from rules.windows.common import SettingRuleSpec, create_setting_rule

SPECS = [
    SettingRuleSpec("PS-001", "PowerShell 2.0 enabled", RuleCategory.POWERSHELL, "POWERSHELL_2_ENABLED", False, Severity.MEDIUM),
    SettingRuleSpec("PS-002", "Script Block Logging disabled", RuleCategory.POWERSHELL, "POWERSHELL_SCRIPT_BLOCK_LOGGING_ENABLED", True, Severity.LOW),
    SettingRuleSpec("PS-003", "Module Logging disabled", RuleCategory.POWERSHELL, "POWERSHELL_MODULE_LOGGING_ENABLED", True, Severity.LOW),
    SettingRuleSpec("PS-004", "Transcription disabled", RuleCategory.POWERSHELL, "POWERSHELL_TRANSCRIPTION_ENABLED", True, Severity.LOW),
]

for spec in SPECS:
    rule_class = create_setting_rule(spec)
    globals()[rule_class.__name__] = rule_class
