"""Append-only hash-chained active validation audit log."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from active_validation.digest import sha256_digest
from active_validation.evidence import validate_evidence


class AuditVerificationError(ValueError):
    """Report a broken or incomplete audit hash chain."""


class AuditLog:
    """Append metadata-only events to a verifiable JSONL chain."""

    def __init__(self, path: str | Path) -> None:
        """Create an audit log writer."""

        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: str, details: dict[str, Any] | None = None) -> str:
        """Append one event and return its entry hash."""

        event_details = details or {}
        forbidden_keys = {"evidence", "rawEvidence", "payload", "eventData"}
        if forbidden_keys & set(event_details):
            raise ValueError("Raw evidence is not allowed in the audit log")
        validate_evidence([event_details])
        previous_hash = _last_hash(self.path)
        entry = {
            "schemaVersion": "1.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "eventType": event,
            "details": event_details,
            "previousEntryHash": previous_hash,
        }
        entry_hash = sha256_digest(entry)
        entry["entryHash"] = entry_hash
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(entry, separators=(",", ":"), sort_keys=True))
            handle.write("\n")
        return entry_hash


def verify_audit_log(path: str | Path) -> int:
    """Verify hash links and required terminal lifecycle events."""

    input_path = Path(path)
    entries: list[dict[str, Any]] = []
    with input_path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as error:
                raise AuditVerificationError(
                    f"Invalid audit JSON at line {line_number}"
                ) from error
            entries.append(entry)
    if not entries:
        raise AuditVerificationError("Audit log is empty")
    previous: str | None = None
    for line_number, entry in enumerate(entries, start=1):
        stored_hash = entry.pop("entryHash", None)
        if entry.get("previousEntryHash") != previous:
            raise AuditVerificationError(
                f"Audit chain link mismatch at line {line_number}"
            )
        calculated = sha256_digest(entry)
        if stored_hash != calculated:
            raise AuditVerificationError(
                f"Audit entry hash mismatch at line {line_number}"
            )
        previous = stored_hash
    if entries[0].get("eventType") != "authorization_loaded":
        raise AuditVerificationError("Audit start event is missing")
    if entries[-1].get("eventType") != "run_completed":
        raise AuditVerificationError("Audit terminal event is missing")
    return len(entries)


def audit_verification_summary(path: str | Path) -> dict[str, Any]:
    """Return the verified terminal hash and entry count."""

    entry_count = verify_audit_log(path)
    final_hash = _last_hash(Path(path))
    return {
        "finalAuditEntryHash": final_hash,
        "auditEntryCount": entry_count,
        "auditVerificationStatus": "VERIFIED",
    }


def _last_hash(path: Path) -> str | None:
    """Read the final hash without retaining audit contents."""

    if not path.exists():
        return None
    last = ""
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                last = line
    if not last:
        return None
    return str(json.loads(last).get("entryHash") or "") or None
