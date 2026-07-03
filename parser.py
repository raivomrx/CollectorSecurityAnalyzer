"""Input parsing helpers with UTF-8 and CP1252 detection."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)
SUPPORTED_ENCODINGS = ("utf-8-sig", "utf-8", "cp1252")


def detect_encoding(path: str | Path) -> str:
    """Detect whether a text file is UTF-8 compatible or CP1252 encoded."""

    file_path = Path(path)
    raw = file_path.read_bytes()

    for encoding in SUPPORTED_ENCODINGS:
        try:
            raw.decode(encoding)
        except UnicodeDecodeError:
            LOGGER.debug("Failed decoding %s as %s", file_path, encoding)
            continue
        LOGGER.debug("Detected %s encoding for %s", encoding, file_path)
        return encoding

    LOGGER.warning("Falling back to cp1252 for %s after detection failed", file_path)
    return "cp1252"


def read_text(path: str | Path) -> str:
    """Read a text file using automatic UTF-8/CP1252 encoding detection."""

    file_path = Path(path)
    try:
        encoding = detect_encoding(file_path)
        return file_path.read_text(encoding=encoding)
    except OSError:
        LOGGER.exception("Unable to read file: %s", file_path)
        raise


def parse_json(path: str | Path) -> dict[str, Any]:
    """Parse a JSON object from a file with automatic encoding detection."""

    file_path = Path(path)
    try:
        content = read_text(file_path).strip()
        if not content:
            LOGGER.warning("JSON file is empty, using empty object: %s", file_path)
            return {}
        data = json.loads(content)
    except json.JSONDecodeError:
        LOGGER.exception("Invalid JSON in file: %s", file_path)
        raise

    if not isinstance(data, dict):
        raise ValueError(f"Expected a JSON object in {file_path}")
    return data


def parse_collector_file(path: str | Path) -> dict[str, Any]:
    """Parse one collector export file."""

    return parse_json(path)
