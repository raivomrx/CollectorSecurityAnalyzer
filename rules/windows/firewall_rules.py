"""Windows Firewall evidence-backed rules."""

from __future__ import annotations

from risk import Severity
from rules.categories import RuleCategory
from rules.windows.common import SettingRuleSpec, create_setting_rule

SPECS = [
    SettingRuleSpec("FW-002", "Domain firewall profile disabled", RuleCategory.FIREWALL, "WINDOWS_FIREWALL_DOMAIN_ENABLED", True, Severity.HIGH),
    SettingRuleSpec("FW-003", "Private firewall profile disabled", RuleCategory.FIREWALL, "WINDOWS_FIREWALL_PRIVATE_ENABLED", True, Severity.HIGH),
    SettingRuleSpec("FW-004", "Public firewall profile disabled", RuleCategory.FIREWALL, "WINDOWS_FIREWALL_PUBLIC_ENABLED", True, Severity.HIGH),
    SettingRuleSpec("FW-005", "Inbound default action not blocked", RuleCategory.FIREWALL, "WINDOWS_FIREWALL_INBOUND_DEFAULT_BLOCK", True, Severity.HIGH),
    SettingRuleSpec("FW-006", "Blocked connection logging disabled", RuleCategory.FIREWALL, "WINDOWS_FIREWALL_LOG_BLOCKED_ENABLED", True, Severity.LOW),
]

for spec in SPECS:
    rule_class = create_setting_rule(spec)
    globals()[rule_class.__name__] = rule_class
