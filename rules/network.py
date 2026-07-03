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
    title = "Network profile category"
    description = "Public profile should only be used where appropriate."

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
                    title=self.title,
                    severity="MEDIUM" if is_public else "LOW",
                    status="FAIL" if is_public else "PASS",
                    description=(
                        "Network profile is Public."
                        if is_public
                        else "Network profile is not Public."
                    ),
                    recommendation=(
                        "Use Private or Domain profile when appropriate."
                        if is_public
                        else "No action required."
                    ),
                    category="network",
                    evidence={"NetworkCategory": category},
                    score=10 if is_public else 0,
                )
            ]
        except Exception:
            LOGGER.exception("NetworkRule failed")
            return []
