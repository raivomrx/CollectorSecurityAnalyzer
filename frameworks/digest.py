"""Deterministic SHA-256 helpers for framework artifacts."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize a JSON-compatible value deterministically."""

    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256_value(value: Any) -> str:
    """Return a deterministic SHA-256 digest for a JSON value."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def pack_content_digest(document: dict[str, Any]) -> str:
    """Hash a pack while excluding its self-referential digest field."""

    content = dict(document)
    content.pop("contentHashSha256", None)
    return sha256_value(content)
