"""Stable active validation JSON serialization."""

from __future__ import annotations

import re
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any

from active_validation.models import ActiveValidationResult, ActiveValidationRun


def active_run_to_dict(run: ActiveValidationRun) -> dict[str, Any]:
    """Return a camelCase JSON-compatible active validation run."""

    return to_camel_dict(run)


def active_result_to_dict(result: ActiveValidationResult) -> dict[str, Any]:
    """Return a camelCase JSON-compatible validator result."""

    return to_camel_dict(result)


def to_camel_dict(value: Any) -> Any:
    """Return nested dataclasses and mappings in camelCase JSON form."""

    source = asdict(value) if is_dataclass(value) else value
    return _camelize(_normalize(source))


def _normalize(value: Any) -> Any:
    """Normalize nested enum values."""

    if is_dataclass(value):
        return _normalize(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {key: _normalize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    return value


def _camelize(value: Any) -> Any:
    """Convert nested dictionary keys to lower camelCase."""

    if isinstance(value, dict):
        return {
            re.sub(r"_([a-z])", lambda match: match.group(1).upper(), key):
            _camelize(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_camelize(item) for item in value]
    return value
