"""Windows remote access evidence-backed rules."""

from __future__ import annotations

from risk import Severity
from rules.categories import RuleCategory
from rules.windows.common import SettingRuleSpec, create_setting_rule

SPECS = [
    SettingRuleSpec("REMOTE-001", "RDP enabled without NLA", RuleCategory.REMOTE_ACCESS, "RDP_NLA_REQUIRED", True, Severity.HIGH, only_when_setting_id="RDP_ENABLED", only_when_value=True),
    SettingRuleSpec("REMOTE-002", "Weak RDP security layer", RuleCategory.REMOTE_ACCESS, "RDP_SECURITY_LAYER_WEAK", False, Severity.MEDIUM, only_when_setting_id="RDP_ENABLED", only_when_value=True),
    SettingRuleSpec("REMOTE-003", "WinRM allows unencrypted traffic", RuleCategory.REMOTE_ACCESS, "WINRM_ALLOW_UNENCRYPTED", False, Severity.HIGH),
    SettingRuleSpec("REMOTE-004", "WinRM Basic authentication enabled", RuleCategory.REMOTE_ACCESS, "WINRM_BASIC_AUTH_ENABLED", False, Severity.HIGH),
    SettingRuleSpec("REMOTE-005", "Remote Registry enabled", RuleCategory.REMOTE_ACCESS, "REMOTE_REGISTRY_ENABLED", False, Severity.MEDIUM),
    SettingRuleSpec("REMOTE-006", "Unapproved remote access software", RuleCategory.REMOTE_ACCESS, "REMOTE_ACCESS_PRODUCTS", severity=Severity.MEDIUM, approved_remote_products=True),
]

for spec in SPECS:
    rule_class = create_setting_rule(spec)
    globals()[rule_class.__name__] = rule_class
