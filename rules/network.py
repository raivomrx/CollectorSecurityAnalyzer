"""Network profile security rule."""

from __future__ import annotations

import logging
from typing import Any

from risk import Finding
from rules.base import BaseRule
from utils import safe_get

LOGGER = logging.getLogger(__name__)


class NetworkRule(BaseRule):
    """Check whether the active network category is Public."""

    id = "NET-001"

    def check(self, data: dict[str, Any]) -> list[Finding]:
        """Return a network profile finding for collector data."""

        LOGGER.info("Running NetworkRule")
        try:
            category = str(
                safe_get(data, "Net_connection_profile.NetworkCategory", "")
            ).strip()
            is_public = category.casefold() == "public"
            return [
                Finding(
                    rule_id=self.id,
                    severity="MEDIUM" if is_public else "LOW",
                    status="FAIL" if is_public else "PASS",
                    evidence={"NetworkCategory": category},
                    score=10 if is_public else 0,
                )
            ]
        except Exception:
            LOGGER.exception("NetworkRule failed")
            return []
