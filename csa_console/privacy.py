"""Sensitive-data scanning for endpoint evidence packages."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class PrivacyViolation:
    """Describe a sensitive-data policy violation without retaining its value."""

    code: str
    path: str


FORBIDDEN_KEY = re.compile(
    r"(?i)(^|_)(password|passwd|cookie|access.?token|refresh.?token|"
    r"private.?key|recovery.?key|ntlm.?response|kerberos.?ticket|"
    r"browser.?cookie|browser.?history|clipboard|document.?content)($|_)"
)
FORBIDDEN_TEXT = (
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "PRIVATE_KEY"),
    (re.compile(r"(?i)\b(?:password|passwd)\s*[:=]\s*\S+"), "PASSWORD_VALUE"),
    (re.compile(r"(?i)\b(?:cookie|authorization)\s*:\s*\S+"), "AUTH_MATERIAL"),
    (
        re.compile(r"(?i)\b[A-Z]:\\Users\\(?!<USER>)[^\\\r\n]+"),
        "USER_PROFILE_PATH",
    ),
    (
        re.compile(r"\b(?:\d{6}-){7}\d{6}\b"),
        "BITLOCKER_RECOVERY_KEY",
    ),
)
IDENTIFIER_KEYS = {
    "currentuser",
    "domain",
    "hostname",
    "principal",
    "serviceaccount",
    "username",
    "workgroup",
}
SAFE_KEY_FRAGMENTS = {
    "passwordPolicy",
    "recoveryPasswordPresent",
    "privateKeyPresent",
    "hasPrivateKey",
}


class SensitiveDataScanner:
    """Detect prohibited credential and private-content material."""

    def scan(self, value: Any) -> list[PrivacyViolation]:
        """Return all policy violations in a structured value."""

        violations: list[PrivacyViolation] = []
        self._scan(value, "$", violations)
        return violations

    def require_clean(self, value: Any) -> None:
        """Raise when prohibited material is detected."""

        violations = self.scan(value)
        if violations:
            summary = ", ".join(
                f"{item.code}@{item.path}" for item in violations[:10]
            )
            raise ValueError(f"Sensitive data policy violation: {summary}")

    def _scan(
        self,
        value: Any,
        path: str,
        violations: list[PrivacyViolation],
    ) -> None:
        """Recursively inspect values without copying sensitive text."""

        if isinstance(value, dict):
            for key, item in value.items():
                name = str(key)
                compact = re.sub(r"[^A-Za-z]", "", name)
                if (
                    FORBIDDEN_KEY.search(name)
                    and compact not in SAFE_KEY_FRAGMENTS
                    and not compact.endswith("Present")
                    and "Policy" not in compact
                ):
                    violations.append(
                        PrivacyViolation("FORBIDDEN_FIELD", f"{path}.{name}")
                    )
                if (
                    compact.casefold() in IDENTIFIER_KEYS
                    and isinstance(item, str)
                    and item
                    and not _is_protected_identifier(item)
                ):
                    violations.append(
                        PrivacyViolation(
                            "PLAINTEXT_IDENTIFIER", f"{path}.{name}"
                        )
                    )
                self._scan(item, f"{path}.{name}", violations)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                self._scan(item, f"{path}[{index}]", violations)
        elif isinstance(value, str):
            for pattern, code in FORBIDDEN_TEXT:
                if pattern.search(value):
                    violations.append(PrivacyViolation(code, path))


def _is_protected_identifier(value: str) -> bool:
    """Return whether an endpoint identifier uses a supported protected form."""

    return bool(
        re.fullmatch(r"id-[0-9a-f]{12}", value)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", value)
        or value in {"<REDACTED>", "<USER>"}
    )
