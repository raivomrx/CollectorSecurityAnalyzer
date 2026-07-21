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
    category_defaults = _read_category_defaults(raw_entries)
    entries = {
        rule_id: _build_knowledge(rule_id, payload, version, category_defaults)
        for rule_id, payload in raw_knowledge_entries.items()
        if isinstance(payload, dict)
    }
    for include_path in _read_includes(raw_entries, knowledge_path):
        included = _load_included_entries(include_path, version)
        entries.update(included)
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


def _read_category_defaults(raw_entries: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return optional category-level defaults for compact knowledge catalogs."""

    value = raw_entries.get("category_defaults", {})
    if not isinstance(value, dict):
        return {}
    return {
        str(category): payload
        for category, payload in value.items()
        if isinstance(payload, dict)
    }


def _read_includes(raw_entries: dict[str, Any], source_path: Path) -> list[Path]:
    """Resolve explicitly included knowledge catalogs next to the root file."""

    metadata = raw_entries.get("metadata", {})
    if not isinstance(metadata, dict) or not isinstance(metadata.get("includes"), list):
        return []
    return [source_path.parent / str(item) for item in metadata["includes"]]


def _load_included_entries(path: Path, knowledge_version: str) -> dict[str, Knowledge]:
    """Load one included knowledge catalog without recursive includes."""

    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        LOGGER.exception("Unable to load included knowledge catalog: %s", path)
        return {}
    if not isinstance(payload, dict):
        LOGGER.warning("Included knowledge catalog root is not an object: %s", path)
        return {}
    defaults = _read_category_defaults(payload)
    return {
        rule_id: _build_knowledge(rule_id, entry, knowledge_version, defaults)
        for rule_id, entry in _read_entries(payload).items()
        if isinstance(entry, dict)
    }


def _build_knowledge(
    rule_id: str,
    payload: dict[str, Any],
    knowledge_version: str,
    category_defaults: dict[str, dict[str, Any]] | None = None,
) -> Knowledge:
    """Build a Knowledge object from a JSON payload."""

    category = str(payload.get("category", "General"))
    defaults = (category_defaults or {}).get(category, {})

    def value(name: str, fallback: Any = UNKNOWN_TEXT) -> Any:
        return payload.get(name, defaults.get(name, fallback))

    remediation = str(value("remediation", value("recommendation")))

    return Knowledge(
        id=rule_id,
        title=str(value("title")),
        description=str(value("description")),
        risk=str(value("risk")),
        recommendation=str(value("recommendation", remediation)),
        frameworks=_coerce_frameworks(value("frameworks", {})),
        references=_coerce_references(value("references", [])),
        knowledge_version=knowledge_version,
        impact=str(value("impact", value("risk"))),
        remediation=remediation,
        category=category,
        framework_context=str(value("framework_context", "Security control evidence.")),
        policy_caveat=(str(value("policy_caveat", "")) or None),
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
