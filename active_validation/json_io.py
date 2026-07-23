"""Bounded and duplicate-safe JSON loading."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MAX_JSON_BYTES = 1_048_576


class StrictJsonError(ValueError):
    """Report malformed, duplicate-key, or oversized JSON input."""


def load_strict_json(
    path: str | Path,
    maximum_bytes: int = MAX_JSON_BYTES,
) -> dict[str, Any]:
    """Load one JSON object while rejecting duplicates and oversized input."""

    input_path = Path(path)
    if input_path.stat().st_size > maximum_bytes:
        raise StrictJsonError("JSON input exceeds the configured size limit")
    try:
        value = json.loads(
            input_path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicates,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise StrictJsonError(f"Invalid JSON input: {error}") from error
    if not isinstance(value, dict):
        raise StrictJsonError("JSON root must be an object")
    return value


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build an object while rejecting duplicate keys."""

    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJsonError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result
