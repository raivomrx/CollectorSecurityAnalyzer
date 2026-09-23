"""Passive credential-exposure correlation; never executes active validation."""

from __future__ import annotations

from typing import Any


def credential_posture(settings: list[dict[str, Any]]) -> dict[str, Any]:
    """Correlate capture and relay prerequisites without conflating gaps."""

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
    capture_observed = bool((name_resolution or auto_proxy) and outbound)
    relay_observed = bool(capture_observed and signing_gap)
    reasons: list[str] = []
    if name_resolution:
        reasons.append("Local name-resolution exposure is enabled.")
    if auto_proxy:
        reasons.append("WinHTTP WPAD is not explicitly disabled.")
    if outbound:
        reasons.append("Collected local policy does not deny outbound NTLM.")
    if signing_gap:
        reasons.append("SMB signing is not required by every readable SMB role.")
    capture_ids = {
        "LLMNR_ENABLED", "NETBIOS_TCPIP_ENABLED", "WPAD_RELEVANT_STATE",
        "NTLM_RESTRICTION_LEVEL",
    }
    relay_ids = capture_ids | {
        "SMB_CLIENT_SIGNING_REQUIRED", "SMB_SERVER_SIGNING_REQUIRED",
    }
    capture_limitations = _limitations_for(rows, capture_ids)
    relay_limitations = _limitations_for(rows, relay_ids)
    capture = _exposure_result(
        capture_observed,
        any(item in known for item in (
            "LLMNR_ENABLED", "NETBIOS_TCPIP_ENABLED", "WPAD_RELEVANT_STATE",
        )) and "NTLM_RESTRICTION_LEVEL" in known,
        capture_limitations,
        [reason for reason in reasons if "SMB signing" not in reason],
    )
    relay = _exposure_result(
        relay_observed,
        capture["state"] == "NO_CORRELATED_EXPOSURE_IDENTIFIED"
        or capture_observed and any(item in known for item in (
            "SMB_CLIENT_SIGNING_REQUIRED", "SMB_SERVER_SIGNING_REQUIRED",
        )),
        relay_limitations,
        reasons,
    )
    return {
        "rating": (
            "ELEVATED" if capture_observed or relay_observed
            else "NOT FULLY EVALUATED" if limitations
            else "NO CORRELATED EXPOSURE IDENTIFIED"
        ),
        "evidenceCompleteness": "PARTIAL" if limitations else "COMPLETE",
        "credentialCaptureExposure": capture,
        "smbRelayExposure": relay,
        "correlatedPrerequisitesObserved": capture_observed or relay_observed,
        "components": rows,
        "reasons": reasons, "limitations": limitations,
        "explanation": "Passive policy correlation identifies potential attack prerequisites, not proven credential exploitability. Domain-effective restrictions, exceptions and network reachability may differ. No credential capture, relay or password-strength test was performed.",
    }


def _limitations_for(
    rows: list[dict[str, Any]],
    setting_ids: set[str],
) -> list[str]:
    """Return evidence gaps relevant to one exposure path."""

    return [
        f"{row['label']}: {row['collectionStatus']}; effective posture is not fully established."
        for row in rows
        if row["settingId"] in setting_ids
        and row["collectionStatus"] != "SUCCESS"
    ]


def _exposure_result(
    observed: bool,
    minimum_evidence_available: bool,
    limitations: list[str],
    reasons: list[str],
) -> dict[str, Any]:
    """Keep the exposure conclusion independent from completeness."""

    if observed:
        state = "EXPOSURE_PREREQUISITES_CONFIRMED"
    elif minimum_evidence_available:
        state = "NO_CORRELATED_EXPOSURE_IDENTIFIED"
    else:
        state = "NOT_EVALUATED"
    return {
        "state": state,
        "prerequisitesObserved": observed,
        "evidenceCompleteness": "PARTIAL" if limitations else "COMPLETE",
        "reasons": reasons,
        "limitations": limitations,
    }
