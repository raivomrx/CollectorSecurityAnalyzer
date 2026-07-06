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
        knowledge_base = load_knowledge(path)
        self._version = knowledge_base.version
        self._entries = knowledge_base.entries
        self._initialized = True

    @property
    def version(self) -> str:
        """Return the loaded knowledge-base version."""

        return self._version

    def get(self, rule_id: str) -> Knowledge:
        """Return knowledge for a rule id or an Unknown placeholder."""

        knowledge = self._entries.get(rule_id)
        if knowledge is None:
            LOGGER.warning("Knowledge missing: %s", rule_id)
            return Knowledge.unknown(rule_id, self._version)
        return knowledge
