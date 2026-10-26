"""Windows account evidence-backed rules."""

from __future__ import annotations

import logging
from typing import Any

from analysis_context import AnalysisContext
from risk import Finding, Severity, Status
from evidence.administrator_membership import membership_observation, resolve_administrator_membership
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
    """Assess the Collector execution account's effective administrator membership."""

    metadata = RuleMetadata(
        id="ACC-011", title="Collector execution account administrator membership",
        version="1.1", author="CSA", category=RuleCategory.ACCOUNTS,
        severity=Severity.HIGH, enabled=True,
        description="Reconciles direct SID membership and identity-bound Windows token groups, including UAC deny-only SIDs.",
    )

    def check(self, data: dict[str, Any], context: AnalysisContext | None = None) -> list[Finding]:
        LOGGER.info("Running Acc011Rule")
        try:
            registry = context.evidence_registry if context else None
            if registry is None:
                return self.not_evaluated(["CURRENT_EXECUTION_USER", "LOCAL_ADMINISTRATORS", "EXECUTION_TOKEN_ADMIN_MEMBERSHIP"])
            ids = {"CURRENT_EXECUTION_USER", "LOCAL_ADMINISTRATORS", "EXECUTION_TOKEN_ADMIN_MEMBERSHIP"}
            if ids.intersection(registry.duplicates):
                return [Finding(rule_id=self.id, severity=Severity.INFO, status=Status.PARTIAL, score=0,
                                evidence={"state": "SOURCE_CONFLICT", "reason": "Membership evidence contains duplicate settings."})]
            def setting(key):
                row = registry.get(key)
                return {"effectiveValue": row.effective_value, "collectionStatus": row.collection_status.value,
                        "provider": row.provider} if row is not None else {}
            document = context.collector_document
            fallback_sid = document.device.current_user_sid if document else None
            observation = membership_observation(setting("CURRENT_EXECUTION_USER"), setting("LOCAL_ADMINISTRATORS"),
                                                 setting("EXECUTION_TOKEN_ADMIN_MEMBERSHIP"), fallback_sid)
            resolved = resolve_administrator_membership(observation)
            direct = observation["direct"]
            evidence = {
                "current_user": observation["identity"]["name"], "current_user_sid": observation["identity"]["sid"],
                "matched": direct["isMember"], "matched_principal": direct["matchedPrincipal"],
                "membership_source": "LOCAL_ADMINISTRATORS_SID_CORRELATION" if direct["isMember"] is True else "WINDOWS_TOKEN_GROUP_RECONCILIATION",
                "membership_evidence": observation, "effective_membership": resolved,
                "reason": resolved["reason"], "observation_scope": "COLLECTOR_EXECUTION_ACCOUNT",
            }
            return [Finding(rule_id=self.id, severity=Severity.HIGH if resolved["status"] == "FAIL" else Severity.LOW if resolved["status"] == "PASS" else Severity.INFO,
                            status=Status(resolved["status"]), score=20 if resolved["status"] == "FAIL" else 0,
                            evidence=evidence, affected_asset=document.device.computer_name if document else None)]
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
