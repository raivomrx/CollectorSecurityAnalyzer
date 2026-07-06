"""Repository access for knowledge-base entries."""

from __future__ import annotations

import logging
from pathlib import Path

from knowledge.loader import DEFAULT_KNOWLEDGE_PATH, load_knowledge
from knowledge.models import Knowledge

LOGGER = logging.getLogger(__name__)


class KnowledgeRepository:
    """Singleton repository for knowledge-base entries."""

    _instance: "KnowledgeRepository | None" = None

    def __new__(cls, path: str | Path = DEFAULT_KNOWLEDGE_PATH) -> "KnowledgeRepository":
        """Return the single repository instance."""

        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, path: str | Path = DEFAULT_KNOWLEDGE_PATH) -> None:
        """Initialize the repository once."""

        if self._initialized:
            return
        self._entries = load_knowledge(path)
        self._initialized = True

    def get(self, rule_id: str) -> Knowledge:
        """Return knowledge for a rule id or an Unknown placeholder."""

        knowledge = self._entries.get(rule_id)
        if knowledge is None:
            LOGGER.warning("Knowledge missing: %s", rule_id)
            return Knowledge(
                id=rule_id,
                title="Unknown",
                description="Unknown",
                risk="Unknown",
                recommendation="Unknown",
                frameworks={},
                references=[],
            )
        return knowledge
