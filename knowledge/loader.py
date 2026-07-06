"""Knowledge-base loading helpers."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from knowledge.models import (
    DEFAULT_KNOWLEDGE_VERSION,
    Knowledge,
    KnowledgeBase,
    Reference,
    UNKNOWN_TEXT,
)

LOGGER = logging.getLogger(__name__)
DEFAULT_KNOWLEDGE_PATH = Path(__file__).resolve().parent / "knowledge.json"


def load_knowledge(path: str | Path = DEFAULT_KNOWLEDGE_PATH) -> KnowledgeBase:
    """Load knowledge entries from a JSON file."""

    knowledge_path = Path(path)
    try:
        with knowledge_path.open("r", encoding="utf-8") as handle:
            raw_entries = json.load(handle)
    except FileNotFoundError:
        LOGGER.warning("Knowledge base file not found: %s", knowledge_path)
        return KnowledgeBase(version=DEFAULT_KNOWLEDGE_VERSION, entries={})
    except json.JSONDecodeError:
        LOGGER.exception("Knowledge base contains invalid JSON: %s", knowledge_path)
        raise
    except OSError:
        LOGGER.exception("Unable to read knowledge base: %s", knowledge_path)
        raise

    if not isinstance(raw_entries, dict):
        raise ValueError(f"Knowledge base root must be an object: {knowledge_path}")

    version = _read_version(raw_entries)
    raw_knowledge_entries = _read_entries(raw_entries)
    entries = {
        rule_id: _build_knowledge(rule_id, payload, version)
        for rule_id, payload in raw_knowledge_entries.items()
        if isinstance(payload, dict)
    }
    LOGGER.info("Knowledge Base loaded")
    LOGGER.info("Entries: %s", len(entries))
    return KnowledgeBase(version=version, entries=entries)


def _read_version(raw_entries: dict[str, Any]) -> str:
    """Read the knowledge-base version from metadata."""

    metadata = raw_entries.get("metadata", {})
    if isinstance(metadata, dict):
        return str(metadata.get("knowledge_version", DEFAULT_KNOWLEDGE_VERSION))
    return DEFAULT_KNOWLEDGE_VERSION


def _read_entries(raw_entries: dict[str, Any]) -> dict[str, Any]:
    """Read knowledge entries while supporting the previous flat format."""

    entries = raw_entries.get("entries")
    if isinstance(entries, dict):
        return entries
    return raw_entries


def _build_knowledge(
    rule_id: str,
    payload: dict[str, Any],
    knowledge_version: str,
) -> Knowledge:
    """Build a Knowledge object from a JSON payload."""

    return Knowledge(
        id=rule_id,
        title=str(payload.get("title", UNKNOWN_TEXT)),
        description=str(payload.get("description", UNKNOWN_TEXT)),
        risk=str(payload.get("risk", UNKNOWN_TEXT)),
        recommendation=str(payload.get("recommendation", UNKNOWN_TEXT)),
        frameworks=_coerce_frameworks(payload.get("frameworks", {})),
        references=_coerce_references(payload.get("references", [])),
        knowledge_version=knowledge_version,
    )


def _coerce_frameworks(value: Any) -> dict[str, list[str]]:
    """Normalize framework references into a mapping of identifier lists."""

    if not isinstance(value, dict):
        return {}
    frameworks: dict[str, list[str]] = {}
    for framework, identifiers in value.items():
        if isinstance(identifiers, list):
            frameworks[str(framework)] = [str(identifier) for identifier in identifiers]
        else:
            frameworks[str(framework)] = [str(identifiers)]
    return frameworks


def _coerce_references(value: Any) -> list[Reference]:
    """Normalize references into structured Reference objects."""

    if not isinstance(value, list):
        return []

    references: list[Reference] = []
    for reference in value:
        if isinstance(reference, dict):
            references.append(
                Reference(
                    title=str(reference.get("title", UNKNOWN_TEXT)),
                    url=str(reference.get("url", "")),
                    vendor=str(reference.get("vendor", UNKNOWN_TEXT)),
                    type=str(reference.get("type", UNKNOWN_TEXT)),
                )
            )
        else:
            references.append(
                Reference(
                    title=str(reference),
                    url=str(reference),
                    vendor=UNKNOWN_TEXT,
                    type=UNKNOWN_TEXT,
                )
            )
    return references
