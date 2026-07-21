"""Windows Audit Policy evidence-backed rules."""

from __future__ import annotations

from risk import Severity
from rules.categories import RuleCategory
from rules.windows.common import SettingRuleSpec, create_setting_rule

SPECS = [
    SettingRuleSpec("AUD-001", "Advanced audit policy coverage insufficient", RuleCategory.AUDIT, "AUDIT_ADVANCED_POLICY_COVERAGE_PERCENT", severity=Severity.MEDIUM, minimum_value=80),
    SettingRuleSpec("AUD-002", "Logon failures not audited", RuleCategory.AUDIT, "AUDIT_LOGON_FAILURE_ENABLED", True, Severity.MEDIUM),
    SettingRuleSpec("AUD-003", "Account management not audited", RuleCategory.AUDIT, "AUDIT_ACCOUNT_MANAGEMENT_ENABLED", True, Severity.MEDIUM),
    SettingRuleSpec("AUD-004", "Process creation not audited", RuleCategory.AUDIT, "AUDIT_PROCESS_CREATION_ENABLED", True, Severity.LOW),
    SettingRuleSpec("AUD-005", "Policy changes not audited", RuleCategory.AUDIT, "AUDIT_POLICY_CHANGE_ENABLED", True, Severity.MEDIUM),
]

for spec in SPECS:
    rule_class = create_setting_rule(spec)
    globals()[rule_class.__name__] = rule_class
