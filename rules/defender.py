"""Windows Defender security rule."""

from __future__ import annotations

import logging
from typing import Any

from risk import Finding
from rules.base import BaseRule
from utils import safe_get

LOGGER = logging.getLogger(__name__)


class DefenderRule(BaseRule):
    """Check whether Windows Defender is enabled."""

    id = "DEF-001"
    title = "Windows Defender status"
    description = "Windows Defender should be switched on."

    def check(self, data: dict[str, Any]) -> list[Finding]:
        """Return a Defender finding for collector data."""

        LOGGER.info("Running DefenderRule")
        try:
            product_state = str(safe_get(data, "Windows Defender.ProductState", "")).strip()
            enabled = product_state.casefold() == "on"
            return [
                Finding(
                    rule_id=self.id,
                    title=self.title,
                    severity="LOW" if enabled else "HIGH",
                    status="PASS" if enabled else "FAIL",
                    description=(
                        "Windows Defender is on."
                        if enabled
                        else "Windows Defender is off or its state is unknown."
                    ),
                    recommendation="No action required." if enabled else "Turn on Windows Defender.",
                    category="endpoint_protection",
                    evidence={"ProductState": product_state},
                    score=0 if enabled else 20,
                )
            ]
        except Exception:
            LOGGER.exception("DefenderRule failed")
            return []
