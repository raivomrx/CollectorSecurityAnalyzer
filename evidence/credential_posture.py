"""Passive credential-exposure correlation; never executes active validation."""

from __future__ import annotations

from typing import Any


def credential_posture(settings: list[dict[str, Any]]) -> dict[str, Any]:
    indexed = {item.get("settingId"): item for item in settings if isinstance(item, dict)}
    fields = (
        ("LLMNR_ENABLED", "LLMNR"), ("NETBIOS_TCPIP_ENABLED", "NBT-NS / NetBIOS adapters"),
        ("WPAD_RELEVANT_STATE", "WPAD (WinHTTP policy)"),
        ("NTLM_RESTRICTION_LEVEL", "Outbound NTLM restriction"),
        ("LAN_MANAGER_AUTHENTICATION_LEVEL", "LM compatibility level"),
        ("SMB_CLIENT_SIGNING_REQUIRED", "SMB client signing required"),
        ("SMB_SERVER_SIGNING_REQUIRED", "SMB server signing required"),
        ("INSECURE_GUEST_LOGONS_ENABLED", "Insecure guest logons"),
    )
    rows, limitations, known = [], [], {}
    for setting_id, label in fields:
        setting = indexed.get(setting_id, {})
        status = setting.get("collectionStatus", "NOT_AVAILABLE")
        value = setting.get("effectiveValue")
        metadata = setting.get("metadata") or {}
        usable = status == "SUCCESS" and value is not None
        if usable:
            known[setting_id] = value
        else:
            limitations.append(f"{label}: {status}; effective posture is not fully established.")
        if isinstance(value, bool):
            display = "Enabled" if value else "Disabled"
        elif setting_id == "NTLM_RESTRICTION_LEVEL" and usable:
            display = {0: "Allow outbound NTLM", 1: "Audit outbound NTLM", 2: "Deny outbound NTLM"}.get(value, "Not evaluated")
        elif setting_id == "LAN_MANAGER_AUTHENTICATION_LEVEL" and usable:
            display = f"Level {value}" + (" — NTLMv2 only; LM/NTLM refused" if value == 5 else " — does not enforce refusal of all legacy authentication")
        elif value is not None:
            display = str(value).replace("_", " ").title()
        else:
            display = "Not evaluated"
        if not usable and not metadata.get("adapters"):
            display = "Not evaluated"
        rows.append({"settingId": setting_id, "label": label, "display": display,
                     "collectionStatus": status, "source": setting.get("source", "UNKNOWN"),
                     "provider": setting.get("provider", "Unknown"), "adapters": metadata.get("adapters", [])})
    name_resolution = known.get("LLMNR_ENABLED") is True or known.get("NETBIOS_TCPIP_ENABLED") is True
    auto_proxy = known.get("WPAD_RELEVANT_STATE") == "ENABLED_OR_DEFAULT"
    outbound = known.get("NTLM_RESTRICTION_LEVEL") in (0, 1)
    signing_gap = known.get("SMB_CLIENT_SIGNING_REQUIRED") is False or known.get("SMB_SERVER_SIGNING_REQUIRED") is False
    correlated = bool((name_resolution or auto_proxy) and outbound and signing_gap)
    reasons = []
    if name_resolution:
        reasons.append("Local name-resolution exposure is enabled.")
    if auto_proxy:
        reasons.append("WinHTTP WPAD is not explicitly disabled.")
    if outbound:
        reasons.append("Collected local policy does not deny outbound NTLM.")
    if signing_gap:
        reasons.append("SMB signing is not required by every readable SMB role.")
    return {
        "rating": "NOT FULLY EVALUATED" if limitations else "ELEVATED" if correlated else "NO CORRELATED EXPOSURE IDENTIFIED",
        "correlatedPrerequisitesObserved": correlated, "components": rows,
        "reasons": reasons, "limitations": limitations,
        "explanation": "Passive policy correlation identifies potential attack prerequisites, not proven credential exploitability. Domain-effective restrictions, exceptions and network reachability may differ. No credential capture, relay or password-strength test was performed.",
    }
