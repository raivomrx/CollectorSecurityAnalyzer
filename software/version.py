"""Version parsing and comparison helpers."""

from __future__ import annotations

import re
from typing import Any

from software.models import ParsedVersion

_VERSION_PART_RE = re.compile(r"\d+")


def parse_version(value: Any) -> ParsedVersion:
    """Parse a software version into a comparable normalized form."""

    original = "" if value is None else str(value).strip()
    parts = tuple(int(part) for part in _VERSION_PART_RE.findall(original))
    normalized = ".".join(str(part) for part in parts)
    return ParsedVersion(original=original, parts=parts, normalized=normalized)


def normalize_version(value: Any) -> str:
    """Return the normalized software version string."""

    return parse_version(value).normalized


def compare_versions(left: Any, right: Any) -> int:
    """Compare two versions and return -1, 0, or 1."""

    parsed_left = parse_version(left)
    parsed_right = parse_version(right)
    if parsed_left < parsed_right:
        return -1
    if parsed_left > parsed_right:
        return 1
    return 0
