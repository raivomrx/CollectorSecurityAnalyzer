"""Allowlisted crash-recovery cleanup for CSA temporary objects."""

from __future__ import annotations

import json
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CSA_PREFIX = "CSA-VALIDATION-"
DEFAULT_STATE_PATH = Path(__file__).resolve().parent / "state" / "cleanup.json"
DEFAULT_TEMPORARY_ROOT = Path(tempfile.gettempdir())
ALLOWED_OBJECT_TYPES = {
    "temporary_directory",
    "temporary_file",
    "firewall_rule",
    "service",
    "scheduled_task",
    "registry_value",
    "listener",
    "certificate",
    "event_source",
}


class CleanupRegistry:
    """Track only explicitly namespaced temporary validation objects."""

    def __init__(self, state_path: str | Path, temporary_root: str | Path) -> None:
        """Create a cleanup registry."""

        self.state_path = Path(state_path)
        self.temporary_root = Path(temporary_root).resolve()

    def track(self, record: dict[str, Any]) -> None:
        """Append one allowlisted, namespaced cleanup record."""

        _validate_record(record)
        records = self.records()
        records.append(record)
        self._write_records(records)

    def forget(self, path: str | Path) -> None:
        """Remove a successfully cleaned filesystem object from recovery state."""

        target = str(Path(path).resolve())
        retained = [
            record
            for record in self.records()
            if str(Path(record.get("path", "")).resolve()) != target
        ]
        self._write_records(retained)

    def records(self) -> list[dict[str, Any]]:
        """Return tracked records without discovering arbitrary host objects."""

        if not self.state_path.exists():
            return []
        data = json.loads(self.state_path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []

    def cleanup(
        self,
        apply: bool = False,
        minimum_age_seconds: int = 3600,
    ) -> list[dict[str, Any]]:
        """Dry-run or remove stale allowlisted filesystem objects."""

        now = datetime.now(timezone.utc)
        actions: list[dict[str, Any]] = []
        retained: list[dict[str, Any]] = []
        for record in self.records():
            _validate_record(record)
            created = datetime.fromisoformat(
                str(record["createdAt"]).replace("Z", "+00:00")
            )
            if (now - created).total_seconds() < minimum_age_seconds:
                retained.append(record)
                continue
            action = {
                "objectType": record["objectType"],
                "redactedName": record["name"],
                "action": "WOULD_REMOVE" if not apply else "REMOVED",
            }
            if apply and record["objectType"] in {
                "temporary_directory",
                "temporary_file",
            }:
                target = Path(record["path"]).resolve()
                if self.temporary_root not in target.parents:
                    raise ValueError("Cleanup target is outside temporary root")
                if target.is_dir():
                    shutil.rmtree(target, ignore_errors=False)
                elif target.exists():
                    target.unlink()
            elif apply:
                action["action"] = "MANUAL_CLEANUP_REQUIRED"
                retained.append(record)
            actions.append(action)
        if apply:
            self._write_records(retained)
        return actions

    def _write_records(self, records: list[dict[str, Any]]) -> None:
        """Replace cleanup state atomically."""

        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        temporary.write_text(json.dumps(records, indent=2), encoding="utf-8")
        temporary.replace(self.state_path)


def _validate_record(record: dict[str, Any]) -> None:
    """Require explicit namespace, type, run ID, and timestamp."""

    if record.get("objectType") not in ALLOWED_OBJECT_TYPES:
        raise ValueError("Cleanup object type is not allowlisted")
    if not str(record.get("name", "")).startswith(CSA_PREFIX):
        raise ValueError("Cleanup object is outside the CSA namespace")
    if not record.get("runId") or not record.get("createdAt"):
        raise ValueError("Cleanup record lacks run metadata")
