"""Logging helpers for Collector Security Analyzer."""

from __future__ import annotations

import logging
from pathlib import Path

DEFAULT_LOG_FORMAT = "%(asctime)s %(levelname)s [%(name)s] %(message)s"


def setup_logging(
    level: int | str = logging.INFO,
    log_file: str | Path | None = None,
    logger_name: str | None = None,
) -> logging.Logger:
    """Configure and return an application logger."""

    logger = logging.getLogger(logger_name)
    logger.setLevel(_coerce_level(level))
    logger.handlers.clear()
    logger.propagate = False

    formatter = logging.Formatter(DEFAULT_LOG_FORMAT)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    if log_file is not None:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a named logger, configuring default logging if needed."""

    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(level=logging.INFO, format=DEFAULT_LOG_FORMAT)
    return logging.getLogger(name)


def _coerce_level(level: int | str) -> int:
    """Convert a logging level name or integer to a logging level value."""

    if isinstance(level, int):
        return level
    normalized = level.strip().upper()
    value = logging.getLevelName(normalized)
    if isinstance(value, int):
        return value
    raise ValueError(f"Unknown logging level: {level}")
