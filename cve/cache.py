"""SQLite cache for NVD API responses."""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from sqlite3 import Connection
from typing import Any

LOGGER = logging.getLogger(__name__)
DEFAULT_CACHE_PATH = Path(__file__).resolve().parent.parent / "cache" / "nvd_cache.sqlite3"
SCHEMA_VERSION = "nvd-api-2.0"


class NvdCache:
    """Persist NVD API responses in SQLite."""

    def __init__(self, path: str | Path = DEFAULT_CACHE_PATH) -> None:
        """Create the cache and ensure its table exists."""

        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    @staticmethod
    def make_key(endpoint: str, params: dict[str, Any]) -> str:
        """Build a deterministic cache key."""

        payload = {
            "schema": SCHEMA_VERSION,
            "endpoint": endpoint,
            "params": {key: params[key] for key in sorted(params)},
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get(self, key: str) -> dict[str, Any] | None:
        """Return a cached response when present and not expired."""

        now = _utc_now().isoformat()
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT response_json FROM nvd_cache WHERE cache_key = ? AND expires_at > ?",
                    (key, now),
                ).fetchone()
        except sqlite3.Error:
            LOGGER.exception("CVE cache database error")
            return None
        if row is None:
            return None
        try:
            return json.loads(row[0])
        except json.JSONDecodeError:
            LOGGER.warning("Corrupted cache entry ignored: %s", key)
            return None

    def set(
        self,
        key: str,
        endpoint: str,
        params: dict[str, Any],
        value: dict[str, Any],
        ttl_hours: int,
    ) -> None:
        """Store a response in cache."""

        created_at = _utc_now()
        expires_at = created_at + timedelta(hours=ttl_hours)
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT OR REPLACE INTO nvd_cache
                    (cache_key, endpoint, request_params_json, response_json, created_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        key,
                        endpoint,
                        json.dumps(params, sort_keys=True, default=str),
                        json.dumps(value, default=str),
                        created_at.isoformat(),
                        expires_at.isoformat(),
                    ),
                )
        except sqlite3.Error:
            LOGGER.exception("CVE cache database error")

    def clear_expired(self) -> int:
        """Clear expired cache entries and return the number removed."""

        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    "DELETE FROM nvd_cache WHERE expires_at <= ?",
                    (_utc_now().isoformat(),),
                )
                return cursor.rowcount
        except sqlite3.Error:
            LOGGER.exception("CVE cache database error")
            return 0

    def clear_all(self) -> None:
        """Clear all cache entries."""

        try:
            with self._connect() as connection:
                connection.execute("DELETE FROM nvd_cache")
        except sqlite3.Error:
            LOGGER.exception("CVE cache database error")

    def _ensure_schema(self) -> None:
        """Create the cache table."""

        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS nvd_cache (
                    cache_key TEXT PRIMARY KEY,
                    endpoint TEXT NOT NULL,
                    request_params_json TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )
                """
            )

    @contextmanager
    def _connect(self) -> Connection:
        """Open a SQLite connection and always close it."""

        connection = sqlite3.connect(self.path)
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()


def _utc_now() -> datetime:
    """Return the current UTC time."""

    return datetime.now(timezone.utc)
