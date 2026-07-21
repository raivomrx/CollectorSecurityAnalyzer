"""Windows Defender evidence-backed rules."""

from __future__ import annotations

from risk import Severity
from rules.categories import RuleCategory
from rules.windows.common import SettingRuleSpec, create_setting_rule

SPECS = [
    SettingRuleSpec("DEF-002", "Real-time protection disabled", RuleCategory.DEFENDER, "DEFENDER_REALTIME_PROTECTION_ENABLED", True, Severity.HIGH),
    SettingRuleSpec("DEF-003", "Defender signatures outdated", RuleCategory.DEFENDER, "DEFENDER_SIGNATURE_AGE_DAYS", severity=Severity.MEDIUM, threshold_key="MaximumSignatureAgeDays"),
    SettingRuleSpec("DEF-004", "Cloud-delivered protection disabled", RuleCategory.DEFENDER, "DEFENDER_CLOUD_PROTECTION_ENABLED", True, Severity.MEDIUM),
    SettingRuleSpec("DEF-005", "PUA protection disabled", RuleCategory.DEFENDER, "DEFENDER_PUA_PROTECTION_ENABLED", True, Severity.MEDIUM),
    SettingRuleSpec("DEF-006", "Network protection disabled", RuleCategory.DEFENDER, "DEFENDER_NETWORK_PROTECTION_ENABLED", True, Severity.MEDIUM),
    SettingRuleSpec("DEF-007", "Excessive or risky exclusions", RuleCategory.DEFENDER, "DEFENDER_EXCLUSION_RISKY_COUNT", severity=Severity.MEDIUM, maximum_value=0),
    SettingRuleSpec("DEF-008", "Tamper protection unavailable or disabled", RuleCategory.DEFENDER, "DEFENDER_TAMPER_PROTECTION_ENABLED", True, Severity.HIGH),
]

for spec in SPECS:
    rule_class = create_setting_rule(spec)
    globals()[rule_class.__name__] = rule_class
