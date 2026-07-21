"""Windows Update evidence-backed rules."""

from __future__ import annotations

from risk import Severity
from rules.categories import RuleCategory
from rules.windows.common import SettingRuleSpec, create_setting_rule

SPECS = [
    SettingRuleSpec("UPD-002", "Pending reboot is stale", RuleCategory.UPDATES, "WINDOWS_UPDATE_PENDING_REBOOT_AGE_DAYS", severity=Severity.MEDIUM, threshold_key="MaximumPendingRebootAgeDays", only_when_setting_id="WINDOWS_UPDATE_PENDING_REBOOT", only_when_value=True),
    SettingRuleSpec("UPD-003", "Update scan too old", RuleCategory.UPDATES, "WINDOWS_UPDATE_LAST_SCAN_AGE_DAYS", severity=Severity.MEDIUM, threshold_key="MaximumUpdateScanAgeDays"),
    SettingRuleSpec("UPD-004", "Update installation too old", RuleCategory.UPDATES, "WINDOWS_UPDATE_LAST_INSTALL_AGE_DAYS", severity=Severity.MEDIUM, threshold_key="MaximumUpdateInstallAgeDays"),
    SettingRuleSpec("UPD-005", "Windows Update service disabled", RuleCategory.UPDATES, "WINDOWS_UPDATE_SERVICE_ENABLED", True, Severity.HIGH),
    SettingRuleSpec("UPD-006", "Device outside target Windows release", RuleCategory.UPDATES, "WINDOWS_RELEASE_TARGET_MATCH", True, Severity.LOW),
]

for spec in SPECS:
    rule_class = create_setting_rule(spec)
    globals()[rule_class.__name__] = rule_class
