"""One evidence-backed conclusion for the assessed BitLocker system volume.

Full protection requires authoritative conversion and protection observations.
Raw collector evidence stays immutable.
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
    provider = metadata.get("provider", setting.get("provider", "Unknown"))
    authoritative = (
        metadata.get("authority") == "AUTHORITATIVE"
        and provider in ("Get-BitLockerVolume", "WIN32_ENCRYPTABLE_VOLUME")
        and metadata.get("volumeType") == "OperatingSystem"
        and isinstance(metadata.get("mountPoint"), str)
        and len(metadata["mountPoint"]) == 2
        and metadata["mountPoint"][0] in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        and metadata["mountPoint"][1] == ":"
    )
    shell = provider == "SHELL_VOLUME_BITLOCKER_PROPERTY"
    raw = metadata.get("rawEvidence")
    shell_raw = metadata.get("shellRawValue", raw.get("value") if isinstance(raw, dict) else None) if shell else None
    indication = {1: "ON", 2: "OFF"}.get(shell_raw, "UNKNOWN") if type(shell_raw) is int else "UNKNOWN"
    recorded_conversion = str(metadata.get("encryptionState", "UNKNOWN")).upper()
    conversion = recorded_conversion if authoritative or recorded_conversion == "SOURCE_CONFLICT" and not shell else "UNKNOWN"
    if authoritative and conversion != "SOURCE_CONFLICT" and str(metadata.get("lockStatus", "")).upper() == "LOCKED":
        conversion = "LOCKED"
    percentage = metadata.get("encryptionPercentage") if authoritative else None
    if type(percentage) not in {int, float} or not 0 <= percentage <= 100:
        percentage = None
    protection = str(metadata.get("protectionStatus", "")).upper() if authoritative else "UNKNOWN"
    if conversion == "SOURCE_CONFLICT":
        state, status, label = "SOURCE_CONFLICT", "PARTIAL", "SOURCE CONFLICT"
        reason = "Trustworthy BitLocker observations disagree; protection is not established."
    elif collection_status in {"SUCCESS", "PARTIAL"} and conversion in {
        "ENCRYPTION_IN_PROGRESS", "DECRYPTION_IN_PROGRESS", "LOCKED",
        "ENCRYPTION_PAUSED", "DECRYPTION_PAUSED", "WIPE_IN_PROGRESS_OR_PAUSED",
    }:
        state, status, label = conversion, "PARTIAL", conversion.replace("_", " ")
        reason = "System-volume state: " + label.lower() + "; verify active protection after completion."
    elif shell and indication != "UNKNOWN" and collection_status in {"SUCCESS", "PARTIAL"}:
        state, status = f"PROTECTION_{indication}_INDICATED", "PARTIAL"
        label = state.replace("_", " ")
        reason = "Windows Shell indicates protection " + indication.lower() + ". OS volume conversion was not measured."
    elif collection_status == "FAILED":
        state, status, label = "ERROR", "ERROR", "ERROR"
        reason = "BitLocker evidence collection failed."
    elif (
        setting.get("settingId") == "BITLOCKER_OS_PROTECTION"
        and collection_status == "SUCCESS"
        and authoritative
        and isinstance(value, bool)
    ):
        if (value and protection not in {"ON", "1"}) or (not value and protection not in {"OFF", "0"}):
            state, status, label = "SOURCE_CONFLICT", "PARTIAL", "SOURCE CONFLICT"
            reason = "The recorded protection fields disagree."
        elif conversion == "FULLY_ENCRYPTED" and percentage not in {None, 100} or conversion == "FULLY_DECRYPTED" and percentage not in {None, 0}:
            state, status, label = "SOURCE_CONFLICT", "PARTIAL", "SOURCE CONFLICT"
            reason = "Conversion and percentage observations disagree."
        elif value and conversion == "FULLY_ENCRYPTED":
            state, status, label = "ENABLED", "PASS", "ENABLED — fully encrypted"
            reason = "Authoritative evidence confirms completed encryption and active protection."
        elif not value and conversion == "FULLY_DECRYPTED":
            state = "DISABLED_FULLY_DECRYPTED"
            status = "FAIL"
            label = "NOT ENABLED — volume fully decrypted"
            reason = "The system volume is fully decrypted with protection off. Enable BitLocker using the approved policy."
        elif not value and conversion in {"FULLY_ENCRYPTED", "SUSPENDED"}:
            state, status, label = "PROTECTION_OFF_ENCRYPTED", "FAIL", "ENCRYPTED — PROTECTION OFF"
            reason = "The encrypted OS volume has protection off. Investigate suspension and resume protection using the approved policy."
        elif value is True and conversion == "FULLY_DECRYPTED":
            state, status, label = "SOURCE_CONFLICT", "PARTIAL", "SOURCE CONFLICT"
            reason = "Protection and conversion evidence are internally inconsistent."
    attempts = []
    recorded_attempts = metadata.get("fallbacksAttempted")
    for attempt in recorded_attempts if isinstance(recorded_attempts, list) else []:
        if not isinstance(attempt, dict):
            continue
        observation = dict(attempt)
        if observation.get("authority") != "AUTHORITATIVE":
            observation.update(encryptionPercentage=None, encryptionMethod=None, parsedState="UNKNOWN", protectionEnabled=None, selectedAsAuthoritative=False)
        attempts.append(observation)
    return {
        "state": state,
        "status": status,
        "displayLabel": label,
        "protectionEnabled": value if status in {"PASS", "FAIL"} else None,
        "collectionStatus": collection_status,
        "reason": reason,
        "provider": provider,
        "authority": "AUTHORITATIVE" if authoritative else "INDICATION" if shell else "UNVERIFIED",
        "reasonCode": state if state != "NOT_EVALUATED" else collection_status if collection_status not in {"SUCCESS", "PARTIAL"} else "INSUFFICIENT_VOLUME_EVIDENCE",
        "observedAt": metadata.get("observedAt", setting.get("collectedAt")),
        "shellRawValue": shell_raw,
        "shellIndicatedProtection": indication if shell else None,
        "providerAttempts": attempts,
        "mountPoint": metadata.get("mountPoint"),
        "encryptionState": conversion,
        "encryptionPercentage": percentage,
        "protectionStatus": protection,
        "encryptionMethod": metadata.get("encryptionMethod") if authoritative else None,
        "lockStatus": metadata.get("lockStatus") if authoritative else None,
    }
