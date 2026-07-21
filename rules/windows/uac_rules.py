"""Windows UAC evidence-backed rules."""

from __future__ import annotations

from risk import Severity
from rules.categories import RuleCategory
from rules.windows.common import SettingRuleSpec, create_setting_rule

SPECS = [
    SettingRuleSpec("UAC-001", "UAC disabled", RuleCategory.UAC, "UAC_ENABLE_LUA", True, Severity.HIGH),
    SettingRuleSpec("UAC-002", "Admin consent prompt weakened", RuleCategory.UAC, "UAC_ADMIN_CONSENT_PROMPT_WEAK", False, Severity.MEDIUM),
    SettingRuleSpec("UAC-003", "Secure Desktop prompt disabled", RuleCategory.UAC, "UAC_PROMPT_ON_SECURE_DESKTOP", True, Severity.MEDIUM),
    SettingRuleSpec("UAC-004", "LocalAccountTokenFilterPolicy weakens remote restrictions", RuleCategory.UAC, "LOCAL_ACCOUNT_TOKEN_FILTER_POLICY_WEAK", False, Severity.MEDIUM),
]

for spec in SPECS:
    rule_class = create_setting_rule(spec)
    globals()[rule_class.__name__] = rule_class
