"""General utility functions for Collector Security Analyzer."""

from __future__ import annotations

import logging
import re
from datetime import date, datetime
from typing import Any, Mapping, Sequence, TypeVar

LOGGER = logging.getLogger(__name__)
T = TypeVar("T")
_WHITESPACE_RE = re.compile(r"\s+")
_VERSION_PREFIX_RE = re.compile(r"^(?:version|v)\s*", re.IGNORECASE)


def safe_get(data: Mapping[str, Any] | None, path: str | Sequence[str], default: T | None = None) -> Any | T | None:
    """Safely read a nested mapping value using a dotted path or key sequence."""

    if data is None:
        return default

    keys = path.split(".") if isinstance(path, str) else list(path)
    current: Any = data
    for key in keys:
        if not isinstance(current, Mapping) or key not in current:
            return default
        current = current[key]
    return current


def normalize_name(value: Any) -> str:
    """Normalize a product, host, or rule name for comparison."""

    text = "" if value is None else str(value)
    text = text.strip().casefold()
    return _WHITESPACE_RE.sub(" ", text)


def normalize_vendor(value: Any) -> str:
    """Normalize a vendor name for comparison."""

    text = normalize_name(value)
    aliases = {
        "microsoft corporation": "microsoft",
        "microsoft corp.": "microsoft",
        "msft": "microsoft",
    }
    return aliases.get(text, text)


def normalize_version(value: Any) -> str:
    """Normalize a software version string."""

    text = normalize_name(value)
    text = _VERSION_PREFIX_RE.sub("", text)
    return text.strip()


def parse_date(value: Any) -> datetime | None:
    """Parse common date and datetime values into a datetime object."""

    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime.combine(value, datetime.min.time())

    text = str(value).strip()
    formats = (
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d.%m.%Y",
        "%d/%m/%Y",
    )

    iso_text = text.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(iso_text)
    except ValueError:
        pass

    for date_format in formats:
        try:
            return datetime.strptime(text, date_format)
        except ValueError:
            continue

    LOGGER.warning("Unable to parse date value: %r", value)
    return None
