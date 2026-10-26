"""Resolve administrator membership without treating a direct-SID miss as proof."""

from __future__ import annotations

import re
from typing import Any

ADMIN_SID = "S-1-5-32-544"


def valid_principal_sid(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(
        r"(?:S-\d+(?:-\d+){2,}|id-[0-9a-f]{12})", value, re.IGNORECASE
    ))


def resolve_administrator_membership(observation: dict[str, Any]) -> dict[str, Any]:
    """Reconcile scoped direct-list and complete, identity-bound token evidence.

    Only the Collector execution identity is observed. Enabled and deny-only
    administrator SIDs establish membership, not process elevation or access.
    """
    current = observation.get("identity", {})
    current = current if isinstance(current, dict) else {}
    direct = observation.get("direct", {})
    direct = direct if isinstance(direct, dict) else {}
    token = observation.get("token", {})
    token = token if isinstance(token, dict) else {}
    sid = current.get("sid")
    result = {
        "status": "NOT_EVALUATED", "state": "NOT_EVALUATED", "member": None,
        "membershipType": "NOT_EVALUATED", "tokenState": "NOT_EVALUATED",
        "classification": str(current.get("classification") or "UNKNOWN").upper(),
        "reason": "Effective administrator membership of the Collector execution account was not evaluated.",
    }
    if (observation.get("identityScope") != "COLLECTOR_EXECUTION_ACCOUNT" or
            not valid_principal_sid(sid) or sid.upper() in {"S-1-5-18", "S-1-5-19", "S-1-5-20"}
            or sid.upper().startswith("S-1-5-32-") or result["classification"] == "SERVICE"):
        return result
    direct_member = direct.get("isMember") if direct.get("collectionStatus") == "SUCCESS" else None
    if type(direct_member) is not bool:
        direct_member = None
    principal = direct.get("matchedPrincipal", {})
    principal = principal if isinstance(principal, dict) else {}
    if direct_member is True and str(principal.get("sid", "")).casefold() != sid.casefold():
        return {**result, "status": "PARTIAL", "state": "SOURCE_CONFLICT",
                "reason": "The direct membership principal conflicts with the execution identity."}
    if result["classification"] == "UNKNOWN" and direct_member is True:
        result["classification"] = str(principal.get("classification") or "UNKNOWN").upper()
    if result["classification"] == "SERVICE":
        return result
    token_member = None
    token_valid = (
        token.get("collectionStatus") == "SUCCESS" and token.get("provider") == "GetTokenInformation"
        and token.get("groupsComplete") is True and token.get("administratorSid") == ADMIN_SID
        and isinstance(token.get("subjectSid"), str)
        and token["subjectSid"].casefold() == sid.casefold()
    )
    if token.get("collectionStatus") == "SUCCESS" and isinstance(token.get("subjectSid"), str) and token["subjectSid"].casefold() != sid.casefold():
        return {**result, "status": "PARTIAL", "state": "SOURCE_CONFLICT",
                "reason": "Token membership evidence belongs to a different execution identity."}
    if token_valid:
        present = token.get("administratorSidPresent")
        enabled = token.get("administratorGroupEnabled")
        deny_only = token.get("administratorGroupDenyOnly")
        attributes = token.get("administratorGroupAttributes")
        if present is False and enabled is False and deny_only is False and attributes is None:
            token_member = False
            result["tokenState"] = "ABSENT"
        elif (present is True and type(attributes) is int and 0 <= attributes <= 0xffffffff
              and type(enabled) is bool and type(deny_only) is bool
              and enabled == bool(attributes & 4) and deny_only == bool(attributes & 16)
              and not (enabled and deny_only)):
            if enabled or deny_only:
                token_member = True
                result["tokenState"] = (
                    "UAC_FILTERED_DENY_ONLY" if deny_only and token.get("elevationType") == "LIMITED"
                    else "DENY_ONLY" if deny_only else "ENABLED"
                )
            else:
                result["tokenState"] = "DISABLED"
        else:
            return {**result, "status": "PARTIAL", "state": "SOURCE_CONFLICT",
                    "reason": "Token administrator SID attributes are incomplete or inconsistent."}
    groups = direct.get("groupCandidates", [])
    groups = groups if isinstance(groups, list) else []
    candidates = {str(row.get("sid", "")).casefold(): row for row in groups
                  if isinstance(row, dict) and valid_principal_sid(row.get("sid"))}
    matches = token.get("matchedAdministratorGroups", []) if token_valid else []
    inherited = []
    for row in matches if isinstance(matches, list) else []:
        if not isinstance(row, dict) or str(row.get("sid", "")).casefold() not in candidates:
            continue
        attributes = row.get("attributes")
        if type(attributes) is int and 0 <= attributes <= 0xffffffff and bool(attributes & (4 | 16)) and not (attributes & 4 and attributes & 16):
            inherited.append(candidates[row["sid"].casefold()])
    if token_member is False and (direct_member is True or inherited):
        return {**result, "status": "PARTIAL", "state": "SOURCE_CONFLICT",
                "reason": "The direct or inherited Administrators assignment and current security token disagree; membership was not resolved."}
    if token_member is True and direct_member is False:
        if not inherited:
            return {**result, "status": "PARTIAL", "state": "SOURCE_CONFLICT",
                    "reason": "The token contains an administrator SID, but the negative direct-list result has no proven group-inheritance path."}
        kind = "INHERITED_DOMAIN_GROUP" if any(str(row.get("classification", "")).upper() == "DOMAIN" for row in inherited) else "INHERITED_GROUP"
        return {**result, "status": "FAIL", "state": "MEMBER", "member": True,
                "membershipType": kind,
                "reason": "The execution token confirms membership through a group listed in local Administrators. This does not prove an elevated process."}
    if direct_member is True or token_member is True:
        return {**result, "status": "FAIL", "state": "MEMBER", "member": True,
                "membershipType": "DIRECT" if direct_member is True else "TOKEN_BASED",
                "reason": "Administrator membership of the Collector execution account is confirmed; process elevation is a separate observation."}
    if token_member is False:
        return {**result, "status": "PASS", "state": "NOT_MEMBER", "member": False,
                "membershipType": "STANDARD_USER_TOKEN",
                "reason": "The complete execution-token group query contains no Administrators SID; no direct membership contradicts it."}
    if result["tokenState"] == "DISABLED":
        return {**result, "status": "PARTIAL",
                "reason": "The Administrators SID is present but disabled; effective membership remains unresolved."}
    return {**result, "reason": "Token-group evidence is unavailable or incomplete. A direct SID miss cannot exclude inherited administrator membership."}


def membership_observation(current, administrators, token=None, fallback_sid=None) -> dict[str, Any]:
    """Reduce canonical setting evidence to the data needed for reconciliation."""
    current = current if isinstance(current, dict) else {}
    administrators = administrators if isinstance(administrators, dict) else {}
    token = token if isinstance(token, dict) else {}
    value = current.get("effectiveValue")
    value = value if isinstance(value, dict) else {}
    def principal_field(row, key):
        return next((value for name, value in row.items() if str(name).casefold() == key.casefold()), None)
    sid = principal_field(value, "Sid") or fallback_sid
    current_ok = current.get("collectionStatus") == "SUCCESS" and valid_principal_sid(sid)
    members = administrators.get("effectiveValue")
    direct_ok = current_ok and administrators.get("collectionStatus") == "SUCCESS" and isinstance(members, list)
    matched = next((row for row in members if isinstance(row, dict)
                    and str(principal_field(row, "Sid") or "").casefold() == str(sid).casefold()), None) if direct_ok else None
    groups = [{"sid": principal_field(row, "Sid"), "classification": principal_field(row, "Classification") or "UNKNOWN"}
              for row in members if isinstance(row, dict) and str(principal_field(row, "ObjectClass") or "").upper() == "GROUP"] if direct_ok else []
    token_value = token.get("effectiveValue")
    token_value = dict(token_value) if isinstance(token_value, dict) else {}
    if token.get("collectionStatus") != "SUCCESS" or token.get("provider") != "GetTokenInformation":
        token_value["collectionStatus"] = token.get("collectionStatus", "NOT_AVAILABLE")
        if token.get("provider") != "GetTokenInformation":
            token_value["collectionStatus"] = "NOT_AVAILABLE"
    return {
        "schemaVersion": "1.0", "identityScope": "COLLECTOR_EXECUTION_ACCOUNT",
        "identity": {"sid": sid if current_ok else None, "name": principal_field(value, "Name") or "Identified Collector account",
                     "classification": principal_field(value, "Classification") or "UNKNOWN"},
        "direct": {"collectionStatus": "SUCCESS" if direct_ok else "NOT_AVAILABLE",
                   "isMember": matched is not None if direct_ok else None,
                   "matchedPrincipal": {"sid": principal_field(matched, "Sid"), "name": principal_field(matched, "Name"),
                                        "classification": principal_field(matched, "Classification") or "UNKNOWN"} if matched else {},
                   "groupCandidates": groups},
        "token": token_value,
    }
