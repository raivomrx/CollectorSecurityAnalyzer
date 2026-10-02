"""One evidence-backed conclusion for the assessed BitLocker system volume.

Only a successful query with an actual boolean effective value establishes
protection. Policy intent, false-like values, and missing evidence do not.
Raw collector evidence is never rewritten by this interpretation.
"""

from __future__ import annotations

from typing import Any


def resolve_bitlocker(setting: dict[str, Any] | None) -> dict[str, Any]:
    """Return additive semantic state, control status and client wording."""

    setting = setting if isinstance(setting, dict) else {}
    metadata = setting.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    collection_status = setting.get("collectionStatus", "NOT_AVAILABLE")
    value = setting.get("effectiveValue")
    state, status, label = "NOT_EVALUATED", "NOT_EVALUATED", "NOT EVALUATED"
    reason = "No reliable protection state was obtained for the system volume."
    conversion = str(metadata.get("encryptionState", "UNKNOWN")).upper()
    percentage = metadata.get("encryptionPercentage")
    if conversion == "SOURCE_CONFLICT":
        state, status, label = "SOURCE_CONFLICT", "PARTIAL", "SOURCE CONFLICT"
        reason = "Trustworthy BitLocker observations disagree; protection is not established."
    elif collection_status in {"SUCCESS", "PARTIAL"} and conversion in {
        "ENCRYPTION_IN_PROGRESS", "DECRYPTION_IN_PROGRESS", "SUSPENDED", "LOCKED",
        "ENCRYPTION_PAUSED", "DECRYPTION_PAUSED",
    }:
        state, status, label = conversion, "PARTIAL", conversion.replace("_", " ")
        reason = "System-volume state: " + label.lower() + "; verify active protection after completion."
    elif collection_status == "FAILED":
        state, status, label = "ERROR", "ERROR", "ERROR"
        reason = "BitLocker evidence collection failed."
    elif (
        setting.get("settingId") == "BITLOCKER_OS_PROTECTION"
        and collection_status == "SUCCESS"
        and metadata.get("volumeType", "OperatingSystem") == "OperatingSystem"
        and isinstance(value, bool)
    ):
        state = "ENABLED" if value else "NOT_ENABLED"
        status = "PASS" if value else "FAIL"
        label = "ENABLED" if value else "NOT ENABLED"
        reason = "System-volume protection was confirmed " + ("enabled." if value else "not enabled.")
        if value is False and conversion == "FULLY_DECRYPTED" and percentage == 0:
            state = "DISABLED_FULLY_DECRYPTED"
            label = "NOT ENABLED — volume fully decrypted"
            reason = "The system volume is fully decrypted (0% encrypted), with protection off."
        elif value is True and conversion == "FULLY_DECRYPTED":
            state, status, label = "SOURCE_CONFLICT", "PARTIAL", "SOURCE CONFLICT"
            reason = "Protection and conversion evidence are internally inconsistent."
    return {
        "state": state,
        "status": status,
        "displayLabel": label,
        "protectionEnabled": value if status in {"PASS", "FAIL"} else None,
        "collectionStatus": collection_status,
        "reason": reason,
        "provider": metadata.get("provider", setting.get("provider", "Unknown")),
        "mountPoint": metadata.get("mountPoint"),
        "encryptionState": conversion,
        "encryptionPercentage": percentage,
        "protectionStatus": metadata.get("protectionStatus"),
        "lockStatus": metadata.get("lockStatus"),
    }
