"""Windows account evidence-backed rules."""

from __future__ import annotations

import logging
from typing import Any

from analysis_context import AnalysisContext
from risk import Finding, Severity, Status
from rules.base import BaseRule
from rules.categories import RuleCategory
from rules.metadata import RuleMetadata
from rules.windows.common import SettingRuleSpec, create_setting_rule

LOGGER = logging.getLogger(__name__)

SPECS = [
    SettingRuleSpec("ACC-001", "Guest account enabled", RuleCategory.ACCOUNTS, "GUEST_ACCOUNT_ENABLED", False, Severity.MEDIUM),
    SettingRuleSpec("ACC-002", "Built-in Administrator enabled", RuleCategory.ACCOUNTS, "BUILTIN_ADMINISTRATOR_ENABLED", False, Severity.MEDIUM),
    SettingRuleSpec("ACC-003", "Password never expires on interactive account", RuleCategory.ACCOUNTS, "PASSWORD_NEVER_EXPIRES_INTERACTIVE_COUNT", severity=Severity.MEDIUM, maximum_value=0),
    SettingRuleSpec("ACC-004", "Excessive local administrators", RuleCategory.ACCOUNTS, "LOCAL_ADMINISTRATOR_COUNT", severity=Severity.MEDIUM, threshold_key="MaximumLocalAdministrators"),
    SettingRuleSpec("ACC-005", "Stale enabled local account", RuleCategory.ACCOUNTS, "STALE_ENABLED_LOCAL_ACCOUNT_COUNT", severity=Severity.MEDIUM, maximum_value=0),
    SettingRuleSpec("ACC-006", "Local password policy strength", RuleCategory.ACCOUNTS, "PASSWORD_POLICY_MIN_LENGTH", severity=Severity.MEDIUM, minimum_threshold_key="MinimumPasswordLength"),
    SettingRuleSpec("ACC-007", "Weak account lockout policy", RuleCategory.ACCOUNTS, "ACCOUNT_LOCKOUT_THRESHOLD", severity=Severity.MEDIUM, minimum_value=1),
    SettingRuleSpec("ACC-008", "Multiple active local administrator accounts", RuleCategory.ACCOUNTS, "ACTIVE_LOCAL_ADMINISTRATOR_ACCOUNT_COUNT", severity=Severity.MEDIUM, maximum_value=1),
    SettingRuleSpec("ACC-010", "Unresolved principal in local Administrators", RuleCategory.ACCOUNTS, "UNRESOLVED_LOCAL_ADMINISTRATOR_COUNT", severity=Severity.MEDIUM, maximum_value=0),
]

for spec in SPECS:
    rule_class = create_setting_rule(spec)
    globals()[rule_class.__name__] = rule_class


class Acc009Rule(BaseRule):
    """List enabled local accounts whose PasswordRequired flag is false."""

    metadata = RuleMetadata(
        id="ACC-009",
        title="Password requirement for enabled local accounts",
        version="1.1",
        author="CSA",
        category=RuleCategory.ACCOUNTS,
        severity=Severity.HIGH,
        enabled=True,
        description=(
            "Correlates the local password-not-required count with the "
            "collected local-user inventory."
        ),
    )

    def check(
        self,
        data: dict[str, Any],
        context: AnalysisContext | None = None,
    ) -> list[Finding]:
        """Return affected account names without weakening count evidence."""

        LOGGER.info("Running Acc009Rule")
        try:
            registry = context.evidence_registry if context else None
            if registry is None:
                return self.not_evaluated(
                    ["LOCAL_PASSWORD_NOT_REQUIRED_COUNT", "LOCAL_USERS"]
                )
            count_setting = registry.get("LOCAL_PASSWORD_NOT_REQUIRED_COUNT")
            if count_setting is None:
                return self.not_evaluated(["LOCAL_PASSWORD_NOT_REQUIRED_COUNT"])
            if count_setting.collection_status.value != "SUCCESS":
                return self.not_evaluated(
                    ["LOCAL_PASSWORD_NOT_REQUIRED_COUNT"],
                    "EVIDENCE_NOT_SUCCESSFUL",
                )
            count = _integer(count_setting.effective_value)
            if count is None:
                return self.not_evaluated(
                    ["LOCAL_PASSWORD_NOT_REQUIRED_COUNT"],
                    "COUNT_NOT_NUMERIC",
                )
            users_setting = registry.get("LOCAL_USERS")
            affected_accounts: list[dict[str, str]] = []
            users_status = "NOT_AVAILABLE"
            if users_setting is not None:
                users_status = users_setting.collection_status.value
                if users_status == "SUCCESS" and isinstance(
                    users_setting.effective_value, list
                ):
                    affected_accounts = [
                        {
                            "name": _principal_value(user, "Name") or "Unknown",
                            "sid": _principal_value(user, "Sid"),
                        }
                        for user in users_setting.effective_value
                        if isinstance(user, dict)
                        and _boolean_value(user, "Enabled") is True
                        and _boolean_value(user, "PasswordRequired") is False
                    ]
            failed = count > 0
            evidence = {
                "reason": (
                    f"{count} enabled local account(s) have PasswordRequired=false."
                    if failed else
                    "No enabled local account with PasswordRequired=false was found."
                ),
                "affected_account_count": count,
                "affected_accounts": affected_accounts,
                "local_users_collection_status": users_status,
                "policy_scope": "LOCAL_ACCOUNTS",
            }
            return [Finding(
                rule_id=self.id,
                severity=Severity.HIGH if failed else Severity.LOW,
                status=Status.FAIL if failed else Status.PASS,
                score=20 if failed else 0,
                evidence=evidence,
                affected_asset=(
                    context.collector_document.device.computer_name
                    if context and context.collector_document else None
                ),
            )]
        except Exception as error:
            LOGGER.exception("Acc009Rule failed")
            return self.error(str(error))


class Acc011Rule(BaseRule):
    """Detect when the interactive user is a local Administrators member."""

    metadata = RuleMetadata(
        id="ACC-011",
        title="Daily user has local administrator privileges",
        version="1.0",
        author="CSA",
        category=RuleCategory.ACCOUNTS,
        severity=Severity.HIGH,
        enabled=True,
        description=(
            "Correlates the current interactive user SID with local "
            "Administrators membership."
        ),
    )

    def check(
        self,
        data: dict[str, Any],
        context: AnalysisContext | None = None,
    ) -> list[Finding]:
        """Return a SID-backed least-privilege finding."""

        LOGGER.info("Running Acc011Rule")
        try:
            registry = context.evidence_registry if context else None
            if registry is None:
                return self.not_evaluated(
                    ["CURRENT_EXECUTION_USER", "LOCAL_ADMINISTRATORS"]
                )
            current = registry.get("CURRENT_EXECUTION_USER")
            administrators = registry.get("LOCAL_ADMINISTRATORS")
            if current is None or administrators is None:
                return self.not_evaluated(
                    ["CURRENT_EXECUTION_USER", "LOCAL_ADMINISTRATORS"]
                )
            if (
                current.collection_status.value != "SUCCESS"
                or administrators.collection_status.value != "SUCCESS"
            ):
                return self.not_evaluated(
                    ["CURRENT_EXECUTION_USER", "LOCAL_ADMINISTRATORS"],
                    "EVIDENCE_NOT_SUCCESSFUL",
                )

            current_value = (
                current.effective_value
                if isinstance(current.effective_value, dict)
                else {}
            )
            current_sid = _principal_value(current_value, "Sid")
            if not current_sid and context.collector_document:
                current_sid = str(
                    context.collector_document.device.current_user_sid or ""
                ).strip()
            if not current_sid:
                return self.not_evaluated(
                    ["CURRENT_EXECUTION_USER"], "CURRENT_USER_SID_UNAVAILABLE"
                )

            members = (
                administrators.effective_value
                if isinstance(administrators.effective_value, list)
                else []
            )
            matched = next(
                (
                    member
                    for member in members
                    if isinstance(member, dict)
                    and _principal_value(member, "Sid").casefold()
                    == current_sid.casefold()
                ),
                None,
            )
            affected_asset = (
                context.collector_document.device.computer_name
                if context.collector_document
                else None
            )
            evidence = {
                "current_user": _principal_value(current_value, "Name"),
                "current_user_sid": current_sid,
                "membership_source": "LOCAL_ADMINISTRATORS_SID_CORRELATION",
                "matched": matched is not None,
            }
            if matched is not None:
                evidence["matched_principal"] = {
                    "name": _principal_value(matched, "Name"),
                    "sid": _principal_value(matched, "Sid"),
                    "classification": _principal_value(
                        matched, "Classification"
                    ),
                    "resolved": bool(matched.get("Resolved", False)),
                }
            return [
                Finding(
                    rule_id=self.id,
                    severity=Severity.HIGH if matched else Severity.LOW,
                    status=Status.FAIL if matched else Status.PASS,
                    score=20 if matched else 0,
                    evidence=evidence,
                    affected_asset=affected_asset,
                )
            ]
        except Exception as error:
            LOGGER.exception("Acc011Rule failed")
            return self.error(str(error))


def _principal_value(principal: dict[str, Any], key: str) -> str:
    """Read a principal field with collector-compatible casing."""

    for candidate, value in principal.items():
        if str(candidate).casefold() == key.casefold():
            return str(value or "").strip()
    return ""


def _boolean_value(principal: dict[str, Any], key: str) -> bool | None:
    """Read a case-insensitive boolean principal field."""

    for candidate, value in principal.items():
        if str(candidate).casefold() == key.casefold():
            return value if isinstance(value, bool) else None
    return None


def _integer(value: Any) -> int | None:
    """Return an integer count without accepting booleans."""

    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None
