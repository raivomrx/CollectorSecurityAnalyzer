"""Collector schema migration helpers."""

from __future__ import annotations

from typing import Any

from collector_schema.compatibility import CollectorV1ToV2Adapter


def migrate_v1_to_v2(data: dict[str, Any]):
    """Migrate a Schema v1 collector dictionary to a v2 document."""

    return CollectorV1ToV2Adapter().convert(data)
