"""One evidence-backed conclusion for the assessed BitLocker system volume.

Full protection requires authoritative conversion and protection observations.
Raw collector evidence stays immutable.
"""

from __future__ import annotations

from typing import Any

SHELL_PROVIDER = "SHELL_VOLUME_BITLOCKER_PROPERTY"
SHELL_LABELS = {
    0: ("OFF", "FIELD_HEURISTIC", "OFF — Shell field heuristic; verify"),
    1: ("ON", "SHELL_ENUM", "ON — Shell indication"),
    2: ("OFF", "SHELL_ENUM", "OFF — Shell indication"),
    3: ("TRANSITIONING", "SHELL_ENUM", "Encrypting — Shell indication"),
    4: ("TRANSITIONING", "SHELL_ENUM", "Decrypting — Shell indication"),
    5: ("SUSPENDED", "SHELL_ENUM", "Suspended — Shell indication"),
    6: ("LOCKED", "SHELL_ENUM", "Locked — Shell indication"),
}


def _is_os_volume(metadata: dict[str, Any]) -> bool:
    mount = metadata.get("mountPoint")
    return (
        metadata.get("volumeType") == "OperatingSystem"
        and isinstance(mount, str)
        and len(mount) == 2
        and mount[0] in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        and mount[1] == ":"
    )


def _shell_observation(metadata: dict[str, Any], provider: str, attempts: list[dict[str, Any]]) -> dict[str, Any]:
    raw = metadata.get("rawEvidence") if provider == SHELL_PROVIDER else None
    attempt = next((row for row in attempts if row.get("provider") == SHELL_PROVIDER and row.get("volume") == metadata.get("mountPoint")), {})
    if provider != SHELL_PROVIDER:
        raw = attempt.get("rawState")
    raw = raw if isinstance(raw, dict) else {}
    value = metadata.get("shellRawValue", raw.get("value")) if provider == SHELL_PROVIDER else raw.get("value")
    read = (metadata.get("shellReadStatus") if provider == SHELL_PROVIDER else None) or raw.get("shellReadStatus")
    if attempt.get("status") in ("ERROR", "FAILED", "ACCESS_DENIED"):
        read = "ERROR"
    if read not in ("SUCCESS", "UNAVAILABLE", "ERROR"):
        # Historical evidence can retain its original 1/2 indication. The
        # field convention and transition labels require a recorded valid read.
        read = "SUCCESS" if type(value) is int and value in (1, 2) and provider == SHELL_PROVIDER else "UNAVAILABLE"
    interpreted = read == "SUCCESS" and type(value) is int and _is_os_volume(metadata)
    indication, method, label = SHELL_LABELS.get(value, ("UNKNOWN", None, "Unknown")) if interpreted else ("UNKNOWN", None, "Unknown")
    return {
        "shellRawValue": value if type(value) is int else None,
        "shellReadStatus": read,
        "shellProtectionIndication": indication,
        "shellInterpretationMethod": method,
        "shellEvidenceSource": SHELL_PROVIDER if provider == SHELL_PROVIDER or attempt else None,
        "shellDisplayLabel": label,
        "shellObservedAt": metadata.get("observedAt") if provider == SHELL_PROVIDER else attempt.get("observedAt"),
    }


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
        and provider in ("Get-BitLockerVolume", "WIN32_ENCRYPTABLE_VOLUME", "MANAGE_BDE")
        and _is_os_volume(metadata)
    )
    shell = provider == SHELL_PROVIDER
    recorded_attempts = metadata.get("fallbacksAttempted")
    attempts = [dict(row) for row in recorded_attempts if isinstance(row, dict)] if isinstance(recorded_attempts, list) else []
    observation = _shell_observation(metadata, provider, attempts)
    indication = observation["shellProtectionIndication"]
    recorded_conversion = str(metadata.get("encryptionState", "UNKNOWN")).upper()
    if recorded_conversion in ("USED_SPACE_ONLY_ENCRYPTED", "USED SPACE ONLY ENCRYPTED", "USEDSPACEONLYENCRYPTED"):
        recorded_conversion = "FULLY_ENCRYPTED"
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
    if state == "NOT_EVALUATED" and indication != "UNKNOWN" and collection_status in ("SUCCESS", "PARTIAL"):
        state = f"PROTECTION_{indication}_INDICATED" if indication in ("ON", "OFF") else f"SHELL_{indication}"
        status, label = "PARTIAL", observation["shellDisplayLabel"]
        reason = "Source: Windows Shell; confirmation recommended. Combined conversion and protection are unconfirmed."
        if observation["shellInterpretationMethod"] == "FIELD_HEURISTIC":
            reason += " Confirm with an approved elevated read-only status check."
        elif indication == "SUSPENDED":
            reason += " Confirm suspension before resuming protection under the approved policy."
        elif indication == "TRANSITIONING":
            reason += " Check conversion progress and verify protection when it completes."
        elif indication == "LOCKED":
            reason += " Verify status with the authorized operator."
    verified_protection = {"ON": "ON", "1": "ON", "OFF": "OFF", "0": "OFF"}.get(protection)
    if state != "SOURCE_CONFLICT" and authoritative and collection_status in ("SUCCESS", "PARTIAL"):
        if verified_protection and indication in ("ON", "OFF") and indication != verified_protection or indication == "SUSPENDED" and verified_protection == "ON":
            disagreement = f"protection {verified_protection}"
        elif indication == "TRANSITIONING" and conversion in ("FULLY_ENCRYPTED", "FULLY_DECRYPTED"):
            disagreement = f"conversion {conversion}"
        elif indication == "LOCKED" and str(metadata.get("lockStatus", "")).upper() == "UNLOCKED":
            disagreement = "an unlocked volume"
        else:
            disagreement = None
        if disagreement:
            state, status, label = "SOURCE_CONFLICT", "PARTIAL", "SOURCE CONFLICT"
            reason = f"Windows Shell indicates {indication}; {provider} reports {disagreement}. Review both observations."
    if state == "NOT_EVALUATED" and observation["shellReadStatus"] == "ERROR":
        reason = "The Windows Shell property could not be read. Verify BitLocker using an approved read-only check."
    for attempt in attempts:
        if attempt.get("authority") != "AUTHORITATIVE":
            attempt.update(encryptionPercentage=None, encryptionMethod=None, parsedState="UNKNOWN", protectionEnabled=None, selectedAsAuthoritative=False)
    reason_code = state if state != "NOT_EVALUATED" else collection_status if collection_status not in {"SUCCESS", "PARTIAL"} else "INSUFFICIENT_VOLUME_EVIDENCE"
    if state == "NOT_EVALUATED" and observation["shellEvidenceSource"]:
        reason_code = "SHELL_READ_" + observation["shellReadStatus"] if observation["shellReadStatus"] != "SUCCESS" else "SHELL_VALUE_UNRECOGNIZED"
    return {
        "state": state,
        "status": status,
        "displayLabel": label,
        "protectionEnabled": value if status in {"PASS", "FAIL"} else None,
        "collectionStatus": collection_status,
        "reason": reason,
        "provider": provider,
        "authority": "AUTHORITATIVE" if authoritative else "INDICATION" if shell else "UNVERIFIED",
        "reasonCode": reason_code,
        "assessmentReasonCode": reason_code,
        "assessmentStatus": status,
        "observedAt": metadata.get("observedAt", setting.get("collectedAt")),
        **observation,
        "shellIndicatedProtection": indication,
        "evidenceSource": provider,
        "evidenceSources": list(dict.fromkeys(source for source in (provider, *(row.get("provider") for row in attempts)) if isinstance(source, str))),
        "providerAttempts": attempts,
        "mountPoint": metadata.get("mountPoint"),
        "encryptionState": conversion,
        "encryptionPercentage": percentage,
        "protectionStatus": protection,
        "authoritativeProtectionStatus": verified_protection if authoritative else None,
        "authoritativeVolumeStatus": conversion if authoritative and conversion not in ("UNKNOWN", "SOURCE_CONFLICT") else None,
        "encryptionMethod": metadata.get("encryptionMethod") if authoritative else None,
        "lockStatus": metadata.get("lockStatus") if authoritative else None,
    }
