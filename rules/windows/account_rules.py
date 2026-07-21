"""Windows account evidence-backed rules."""

from __future__ import annotations

from risk import Severity
from rules.categories import RuleCategory
from rules.windows.common import SettingRuleSpec, create_setting_rule

SPECS = [
    SettingRuleSpec("ACC-001", "Guest account enabled", RuleCategory.ACCOUNTS, "GUEST_ACCOUNT_ENABLED", False, Severity.MEDIUM),
    SettingRuleSpec("ACC-002", "Built-in Administrator enabled", RuleCategory.ACCOUNTS, "BUILTIN_ADMINISTRATOR_ENABLED", False, Severity.MEDIUM),
    SettingRuleSpec("ACC-003", "Password never expires on interactive account", RuleCategory.ACCOUNTS, "PASSWORD_NEVER_EXPIRES_INTERACTIVE_COUNT", severity=Severity.MEDIUM, maximum_value=0),
    SettingRuleSpec("ACC-004", "Excessive local administrators", RuleCategory.ACCOUNTS, "LOCAL_ADMINISTRATOR_COUNT", severity=Severity.MEDIUM, threshold_key="MaximumLocalAdministrators"),
    SettingRuleSpec("ACC-005", "Stale enabled local account", RuleCategory.ACCOUNTS, "STALE_ENABLED_LOCAL_ACCOUNT_COUNT", severity=Severity.MEDIUM, maximum_value=0),
    SettingRuleSpec("ACC-006", "Weak local password policy", RuleCategory.ACCOUNTS, "PASSWORD_POLICY_MIN_LENGTH", severity=Severity.MEDIUM, minimum_value=12),
    SettingRuleSpec("ACC-007", "Weak account lockout policy", RuleCategory.ACCOUNTS, "ACCOUNT_LOCKOUT_THRESHOLD", severity=Severity.MEDIUM, minimum_value=1),
]

for spec in SPECS:
    rule_class = create_setting_rule(spec)
    globals()[rule_class.__name__] = rule_class
