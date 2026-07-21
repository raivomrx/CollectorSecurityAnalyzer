"""Privacy and provenance helpers for evidence values."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from collector_schema.enums import PrivacyMode

USER_PATH_RE = re.compile(r"C:\\Users\\([^\\]+)", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


def redact_value(value: Any, privacy_mode: PrivacyMode = PrivacyMode.STANDARD) -> Any:
    """Redact sensitive usernames, paths, and IPs from report values."""

    if isinstance(value, list):
        return [redact_value(item, privacy_mode) for item in value]
    if isinstance(value, dict):
        return {key: redact_value(item, privacy_mode) for key, item in value.items()}
    if not isinstance(value, str):
        return value

    redacted = USER_PATH_RE.sub(r"C:\\Users\\<USER>", value)
    if privacy_mode == PrivacyMode.STRICT:
        redacted = IPV4_RE.sub(r"\1.\2.\3.xxx", redacted)
    return redacted


def pseudonymize_hostname(hostname: str | None, privacy_mode: PrivacyMode) -> str | None:
    """Return a deterministic hostname pseudonym in strict privacy mode."""

    if not hostname or privacy_mode != PrivacyMode.STRICT:
        return hostname
    digest = hashlib.sha256(hostname.encode("utf-8")).hexdigest()[:12]
    return f"host-{digest}"
