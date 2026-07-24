"""Metadata-only tamper-evident Console audit chain."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from csa_console.canonical import canonical_json, sha256_value
from csa_console.identifiers import utc_text


class AuditVerificationError(ValueError):
    """Report an invalid Console audit chain."""


class ConsoleAuditLog:
    """Append and verify assessment lifecycle events."""

    FORBIDDEN_KEYS = {
        "evidence",
        "payload",
        "raw",
        "password",
        "token",
        "secret",
        "privateKey",
    }

    def __init__(self, path: str | Path) -> None:
        """Create an audit log at an assessment-scoped path."""

        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event_type: str, details: dict[str, Any] | None = None) -> str:
        """Append a metadata-only event and return its hash."""

        safe_details = details or {}
        if self.FORBIDDEN_KEYS & set(safe_details):
            raise ValueError("Sensitive values are not allowed in Console audit details")
        entry = {
            "schemaVersion": "5.0",
            "timestamp": utc_text(),
            "eventType": event_type,
            "details": safe_details,
            "previousEntryHash": self.final_hash(),
        }
        entry_hash = sha256_value(entry)
        entry["entryHash"] = entry_hash
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(canonical_json(entry))
            handle.write("\n")
        self.path.chmod(0o600)
        return entry_hash

    def verify(self) -> dict[str, Any]:
        """Verify the full chain and return its summary."""

        if not self.path.exists():
            raise AuditVerificationError("Audit log does not exist")
        previous: str | None = None
        count = 0
        for count, line in enumerate(
            self.path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as error:
                raise AuditVerificationError(
                    f"Invalid audit JSON at line {count}"
                ) from error
            stored_hash = entry.pop("entryHash", None)
            if entry.get("previousEntryHash") != previous:
                raise AuditVerificationError(
                    f"Audit chain link mismatch at line {count}"
                )
            calculated = sha256_value(entry)
            if stored_hash != calculated:
                raise AuditVerificationError(
                    f"Audit entry hash mismatch at line {count}"
                )
            previous = stored_hash
        if count == 0:
            raise AuditVerificationError("Audit log is empty")
        return {
            "finalAuditEntryHash": previous,
            "auditEntryCount": count,
            "auditVerificationStatus": "VERIFIED",
        }

    def final_hash(self) -> str | None:
        """Return the final audit hash without validating the full chain."""

        if not self.path.exists():
            return None
        lines = self.path.read_text(encoding="utf-8").splitlines()
        if not lines:
            return None
        return str(json.loads(lines[-1]).get("entryHash") or "") or None
