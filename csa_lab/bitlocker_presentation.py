"""Present assessed BitLocker states without changing their evidence semantics."""

from typing import Any


def bitlocker_presentation(result: dict[str, Any]) -> dict[str, Any]:
    """Use one interpretation in endpoint, summary and limitation views."""
    status = result.get("status", "NOT_EVALUATED")
    state = result.get("state", "NOT_EVALUATED")
    shell = result.get("shellProtectionIndication", "UNKNOWN")
    protection = result.get("authoritativeProtectionStatus")
    reported_on = state != "SOURCE_CONFLICT" and (
        protection == "ON" or protection is None and shell == "ON"
    )
    label = result.get("displayLabel", "NOT EVALUATED")
    if state in {"PROTECTION_ON_INDICATED", "PROTECTION_OFF_INDICATED"}:
        label += " — not verified"
    recommendation = "Verify conversion and protection using authorized read-only evidence."
    if state == "DISABLED_FULLY_DECRYPTED":
        recommendation = "Enable BitLocker using the approved policy."
    elif state == "PROTECTION_OFF_ENCRYPTED":
        recommendation = "Investigate suspension and resume BitLocker protection using the approved policy."
    elif status == "PASS":
        recommendation = "Verify protection remains on after the next authorized collection."
    return {
        "label": label,
        "reportedOn": reported_on,
        "confirmedProtected": status == "PASS" and state == "ENABLED",
        "unresolved": status not in {"PASS", "FAIL"},
        "recommendation": recommendation,
    }
