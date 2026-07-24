"""Canonical serialization and digest helpers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any


def normalize(value: Any) -> Any:
    """Return a recursively JSON-compatible value."""

    if is_dataclass(value):
        return normalize(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {
            str(key): normalize(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [normalize(item) for item in value]
    return value


def canonical_json(value: Any) -> str:
    """Serialize a value as deterministic canonical JSON."""

    return json.dumps(
        normalize(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_bytes(value: Any) -> bytes:
    """Serialize a value as canonical UTF-8 bytes."""

    return canonical_json(value).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    """Return a prefixed SHA-256 digest for bytes."""

    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_value(value: Any) -> str:
    """Return a prefixed SHA-256 digest for a canonical value."""

    return sha256_bytes(canonical_bytes(value))


def sha256_file(path: str | Path) -> str:
    """Return a prefixed SHA-256 digest for a file."""

    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def write_canonical_json(path: str | Path, value: Any) -> Path:
    """Atomically write canonical JSON with restrictive permissions."""

    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    temporary.write_bytes(canonical_bytes(value))
    temporary.chmod(0o600)
    temporary.replace(output)
    return output


def read_json(path: str | Path) -> dict[str, Any]:
    """Read a JSON object from disk."""

    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value
