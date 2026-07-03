"""Configuration loading for Collector Security Analyzer."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / "config" / "settings.json"
LEGACY_CONFIG_PATH = Path(__file__).resolve().parent / "config" / "config.json"


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """Load analyzer configuration from a JSON file."""

    config_path = _resolve_config_path(path)
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        LOGGER.warning("Configuration file not found: %s", config_path)
        return {}
    except json.JSONDecodeError:
        LOGGER.exception("Configuration file contains invalid JSON: %s", config_path)
        raise
    except OSError:
        LOGGER.exception("Unable to read configuration file: %s", config_path)
        raise

    if not isinstance(data, dict):
        raise ValueError(f"Configuration root must be a JSON object: {config_path}")

    LOGGER.debug("Loaded configuration from %s", config_path)
    return data


def get_config_value(
    key: str,
    default: Any = None,
    config: dict[str, Any] | None = None,
) -> Any:
    """Return a dotted-path configuration value."""

    current: Any = load_config() if config is None else config
    for part in key.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def _resolve_config_path(path: str | Path | None) -> Path:
    """Resolve the preferred settings file path."""

    if path is not None:
        return Path(path)
    if DEFAULT_CONFIG_PATH.exists():
        return DEFAULT_CONFIG_PATH
    return LEGACY_CONFIG_PATH
