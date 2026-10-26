"""Report execution-account membership independently of process elevation."""

from __future__ import annotations

from typing import Any

from evidence.administrator_membership import membership_observation, resolve_administrator_membership


def administrative_privilege_posture(evidence: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    privilege = evidence.get("privilegeContext")
    privilege = privilege if isinstance(privilege, dict) else {}
    elevated = privilege.get("isElevated")
    elevated = elevated if type(elevated) is bool else None
    result = {
        "status": "NOT_EVALUATED", "state": "NOT_EVALUATED", "isAdministratorMember": None,
        "user": None, "sourceControl": "ACC-011", "membershipType": "NOT_EVALUATED",
        "tokenState": "NOT_EVALUATED", "identityScope": "COLLECTOR_EXECUTION_ACCOUNT",
        "desktopUsersState": "NOT_EVALUATED",
        "reason": "Administrator membership of the Collector execution account was not evaluated.",
        "processElevation": {
            "state": ("ELEVATED_PROCESS_OBSERVED" if elevated is True else
                      "PROCESS_NOT_ELEVATED" if elevated is False else "NOT_EVALUATED"),
            "isElevated": elevated,
            "scope": "Collector process only; other processes and sessions were not evaluated.",
        },
    }
    controls = [row.get("finding", {}) for row in findings if row.get("finding", {}).get("rule_id") == "ACC-011"]
    if len(controls) != 1:
        return result
    control = controls[0]
    observed = control.get("evidence")
    if not isinstance(observed, dict):
        return result
    settings = {}
    for section in evidence.values():
        if not isinstance(section, dict) or not isinstance(section.get("settings"), list):
            continue
        for setting in section["settings"]:
            if isinstance(setting, dict) and setting.get("settingId") in {
                "CURRENT_EXECUTION_USER", "LOCAL_ADMINISTRATORS", "EXECUTION_TOKEN_ADMIN_MEMBERSHIP",
            }:
                key = setting["settingId"]
                if key in settings:
                    return {**result, "status": "PARTIAL", "state": "SOURCE_CONFLICT",
                            "reason": "Duplicate membership evidence cannot be reconciled."}
                settings[key] = setting
    device = evidence.get("identity", evidence.get("device", {}))
    fallback_sid = device.get("currentUserSid") if isinstance(device, dict) else None
    modern = isinstance(observed.get("membership_evidence"), dict)
    if modern:
        observation = observed["membership_evidence"]
        if settings:
            raw = membership_observation(settings.get("CURRENT_EXECUTION_USER"), settings.get("LOCAL_ADMINISTRATORS"),
                                         settings.get("EXECUTION_TOKEN_ADMIN_MEMBERSHIP"), fallback_sid)
            if raw != observation:
                return {**result, "status": "PARTIAL", "state": "SOURCE_CONFLICT",
                        "reason": "Stored ACC-011 membership proof conflicts with its collected source evidence."}
    else:
        # A legacy direct-SID miss cannot rule out inherited membership.
        if control.get("status") not in {"PASS", "FAIL"}:
            if observed.get("state") == "SOURCE_CONFLICT":
                result.update(status="PARTIAL", state="SOURCE_CONFLICT", reason=observed.get("reason", result["reason"]))
            return result
        sid, member = observed.get("current_user_sid"), observed.get("matched")
        if (type(member) is not bool or (control["status"] == "FAIL") != member or
                observed.get("membership_source") != "LOCAL_ADMINISTRATORS_SID_CORRELATION"):
            return result
        principal = observed.get("matched_principal")
        principal = principal if isinstance(principal, dict) else {}
        if member and (str(principal.get("sid", "")).casefold() != str(sid).casefold() or
                       str(principal.get("classification", "")).upper() == "SERVICE"):
            return result
        for key, setting in settings.items():
            if key == "EXECUTION_TOKEN_ADMIN_MEMBERSHIP":
                continue
            if setting.get("collectionStatus") != "SUCCESS":
                return result
            if key == "CURRENT_EXECUTION_USER":
                current = membership_observation(setting, {}, fallback_sid=fallback_sid)["identity"]["sid"]
                if not isinstance(current, str) or current.casefold() != str(sid).casefold():
                    return result
        observation = {
            "identityScope": "COLLECTOR_EXECUTION_ACCOUNT",
            "identity": {"sid": sid, "name": observed.get("current_user"), "classification": principal.get("classification", "UNKNOWN")},
            "direct": {"collectionStatus": "SUCCESS", "isMember": member, "matchedPrincipal": principal},
        }
    resolved = resolve_administrator_membership(observation)
    if modern and control.get("status") != resolved["status"]:
        return {**result, "status": "PARTIAL", "state": "SOURCE_CONFLICT",
                "reason": "ACC-011 result conflicts with the reconciled membership proof."}
    identity = observation.get("identity", {})
    result.update(status=resolved["status"], state=resolved["state"], isAdministratorMember=resolved["member"],
                  membershipType=resolved["membershipType"], tokenState=resolved["tokenState"], reason=resolved["reason"])
    if resolved["member"] is not None:
        result["user"] = {"identity": identity["sid"].casefold(), "name": str(identity.get("name") or "Identified Collector account"),
                          "classification": resolved["classification"]}
    return result
