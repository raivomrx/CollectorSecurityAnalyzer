"""Knowledge-base loading helpers."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from knowledge.models import Knowledge

LOGGER = logging.getLogger(__name__)
DEFAULT_KNOWLEDGE_PATH = Path(__file__).resolve().parent / "knowledge.json"


def load_knowledge(path: str | Path = DEFAULT_KNOWLEDGE_PATH) -> dict[str, Knowledge]:
    """Load knowledge entries from a JSON file."""

    knowledge_path = Path(path)
    try:
        with knowledge_path.open("r", encoding="utf-8") as handle:
            raw_entries = json.load(handle)
    except FileNotFoundError:
        LOGGER.warning("Knowledge base file not found: %s", knowledge_path)
        return {}
    except json.JSONDecodeError:
        LOGGER.exception("Knowledge base contains invalid JSON: %s", knowledge_path)
        raise
    except OSError:
        LOGGER.exception("Unable to read knowledge base: %s", knowledge_path)
        raise

    if not isinstance(raw_entries, dict):
        raise ValueError(f"Knowledge base root must be an object: {knowledge_path}")

    entries = {
        rule_id: _build_knowledge(rule_id, payload)
        for rule_id, payload in raw_entries.items()
        if isinstance(payload, dict)
    }
    LOGGER.info("Knowledge Base loaded")
    LOGGER.info("Entries: %s", len(entries))
    return entries


def _build_knowledge(rule_id: str, payload: dict[str, Any]) -> Knowledge:
    """Build a Knowledge object from a JSON payload."""

    return Knowledge(
        id=rule_id,
        title=str(payload.get("title", "Unknown")),
        description=str(payload.get("description", "Unknown")),
        risk=str(payload.get("risk", "Unknown")),
        recommendation=str(payload.get("recommendation", "Unknown")),
        frameworks=_coerce_frameworks(payload.get("frameworks", {})),
        references=_coerce_references(payload.get("references", [])),
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


def _coerce_references(value: Any) -> list[str]:
    """Normalize reference URLs into a list of strings."""

    if not isinstance(value, list):
        return []
    return [str(reference) for reference in value]
