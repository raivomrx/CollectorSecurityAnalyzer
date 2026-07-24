"""Identifier and timestamp helpers."""

from __future__ import annotations

import base64
import secrets
from datetime import datetime, timezone


def utc_now() -> datetime:
    """Return the current timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc)


def utc_text(value: datetime | None = None) -> str:
    """Return an ISO-8601 UTC timestamp."""

    current = value or utc_now()
    return current.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def random_id(prefix: str = "") -> str:
    """Return a sortable timestamp-prefixed random identifier."""

    stamp = utc_now().strftime("%Y%m%d%H%M%S%f")
    random_part = base64.b32encode(secrets.token_bytes(10)).decode("ascii").rstrip("=")
    return f"{prefix}{stamp}{random_part}"


def random_token() -> str:
    """Return a high-entropy URL-safe enrollment token."""

    return secrets.token_urlsafe(32)
