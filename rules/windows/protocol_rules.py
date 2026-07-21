"""Windows legacy protocol evidence-backed rules."""

from __future__ import annotations

from risk import Severity
from rules.categories import RuleCategory
from rules.windows.common import SettingRuleSpec, create_setting_rule

SPECS = [
    SettingRuleSpec("PROTO-001", "SMBv1 enabled", RuleCategory.PROTOCOLS, "SMBV1_ENABLED", False, Severity.HIGH),
    SettingRuleSpec("PROTO-002", "SMB signing not required", RuleCategory.PROTOCOLS, "SMB_SIGNING_REQUIRED", True, Severity.MEDIUM),
    SettingRuleSpec("PROTO-003", "LLMNR enabled", RuleCategory.PROTOCOLS, "LLMNR_ENABLED", False, Severity.MEDIUM),
    SettingRuleSpec("PROTO-004", "NetBIOS over TCP/IP enabled", RuleCategory.PROTOCOLS, "NETBIOS_TCPIP_ENABLED", False, Severity.MEDIUM),
    SettingRuleSpec("PROTO-005", "Insecure guest logons enabled", RuleCategory.PROTOCOLS, "INSECURE_GUEST_LOGONS_ENABLED", False, Severity.HIGH),
    SettingRuleSpec("PROTO-006", "Weak LAN Manager authentication level", RuleCategory.PROTOCOLS, "LAN_MANAGER_AUTH_LEVEL", "NTLMV2_ONLY", Severity.HIGH),
]

for spec in SPECS:
    rule_class = create_setting_rule(spec)
    globals()[rule_class.__name__] = rule_class
