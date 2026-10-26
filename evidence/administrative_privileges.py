"""Report existing ACC-011 membership evidence separately from process elevation."""

from __future__ import annotations

import re
from typing import Any


def administrative_privilege_posture(
    evidence: dict[str, Any], findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Describe the observed execution user; never infer membership from UAC."""

    privilege = evidence.get("privilegeContext")
    privilege = privilege if isinstance(privilege, dict) else {}
    elevated = privilege.get("isElevated")
    elevated = elevated if type(elevated) is bool else None
    result = {
        "status": "NOT_EVALUATED", "isAdministratorMember": None,
        "user": None, "sourceControl": "ACC-011",
        "reason": "SID-correlated ACC-011 membership evidence is unavailable.",
        "processElevation": {
            "state": ("ELEVATED_PROCESS_OBSERVED" if elevated is True else
                      "PROCESS_NOT_ELEVATED" if elevated is False else "NOT_EVALUATED"),
            "isElevated": elevated,
            "scope": "Collector process only; other processes and sessions were not evaluated.",
        },
    }
    controls = [row.get("finding", {}) for row in findings
                if row.get("finding", {}).get("rule_id") == "ACC-011"]
    if len(controls) != 1:
        return result
    control = controls[0]
    observed = control.get("evidence")
    if control.get("status") not in {"PASS", "FAIL"} or not isinstance(observed, dict):
        return result
    sid = observed.get("current_user_sid")
    if not isinstance(sid, str) or not re.fullmatch(
        r"(?:S-\d+(?:-\d+){2,}|id-[0-9a-f]{12})", sid, re.IGNORECASE
    ):
        result["reason"] = "The interactive user's SID or collected SID pseudonym is unavailable."
        return result
    if sid.upper() in {"S-1-5-18", "S-1-5-19", "S-1-5-20"} or sid.upper().startswith("S-1-5-32-"):
        result["reason"] = "The supplied identity does not identify an interactive user account."
        return result
    member = observed.get("matched")
    if (type(member) is not bool or (control["status"] == "FAIL") != member or
            observed.get("membership_source") != "LOCAL_ADMINISTRATORS_SID_CORRELATION"):
        result["reason"] = "ACC-011 membership evidence is incomplete or inconsistent."
        return result
    principal = observed.get("matched_principal")
    principal = principal if isinstance(principal, dict) else {}
    if member and (str(principal.get("sid", "")).casefold() != sid.casefold() or
                   str(principal.get("classification", "")).upper() == "SERVICE"):
        result["reason"] = "The administrator principal cannot be correlated with the interactive user SID."
        return result
    for section in evidence.values():
        if not isinstance(section, dict) or not isinstance(section.get("settings"), list):
            continue
        for setting in section["settings"]:
            if not isinstance(setting, dict) or setting.get("settingId") not in {
                "CURRENT_EXECUTION_USER", "LOCAL_ADMINISTRATORS",
            }:
                continue
            if setting.get("collectionStatus") != "SUCCESS":
                result["reason"] = "Current-user or administrator-list evidence was not collected successfully."
                return result
            if setting["settingId"] == "CURRENT_EXECUTION_USER":
                current = setting.get("effectiveValue")
                current_sid = next((value for key, value in current.items() if key.casefold() == "sid"), None) if isinstance(current, dict) else None
                if not current_sid:
                    device = evidence.get("identity", evidence.get("device", {}))
                    current_sid = device.get("currentUserSid") if isinstance(device, dict) else None
                if not isinstance(current_sid, str) or current_sid.casefold() != sid.casefold():
                    result["reason"] = "Current-user evidence conflicts with the ACC-011 identity."
                    return result
    result.update(
        status=control["status"], isAdministratorMember=member,
        user={"identity": sid.casefold(), "name": str(observed.get("current_user") or "Identified interactive user"),
              "classification": str(principal.get("classification") or "UNKNOWN").upper()},
        reason=("The observed interactive user's SID matches local Administrators membership."
                if member else "The observed interactive user's SID is absent from the successfully collected local Administrators list."),
    )
    return result
