"""JSON serialization helpers for Console dataclasses."""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any


def snake_to_camel(value: str) -> str:
    """Convert a snake-case field name to camel case."""

    head, *tail = value.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in tail)


def model_to_dict(value: Any) -> Any:
    """Serialize dataclasses with camel-case field names."""

    if is_dataclass(value):
        return {
            snake_to_camel(item.name): model_to_dict(getattr(value, item.name))
            for item in fields(value)
        }
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): model_to_dict(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [model_to_dict(item) for item in value]
    return value
