"""Windows Firewall security rule."""

from __future__ import annotations

import logging
from typing import Any

from risk import Finding
from rules.base import BaseRule
from utils import safe_get

LOGGER = logging.getLogger(__name__)
PROFILES = ("Domain", "Private", "Public")


class FirewallRule(BaseRule):
    """Check whether Domain, Private, and Public firewall profiles are enabled."""

    id = "FW-001"
    title = "Windows Firewall profiles"
    description = "All Windows Firewall profiles should be enabled."

    def check(self, data: dict[str, Any]) -> list[Finding]:
        """Return a firewall finding for collector data."""

        LOGGER.info("Running FirewallRule")
        try:
            states = {
                profile: bool(safe_get(data, f"Firewall.{profile}.Enabled", False))
                for profile in PROFILES
            }
            enabled = all(states.values())
            return [
                Finding(
                    rule_id=self.id,
                    title=self.title,
                    severity="LOW" if enabled else "HIGH",
                    status="PASS" if enabled else "FAIL",
                    description=(
                        "All Windows Firewall profiles are enabled."
                        if enabled
                        else "One or more Windows Firewall profiles are disabled."
                    ),
                    recommendation=(
                        "No action required."
                        if enabled
                        else "Enable Domain, Private, and Public firewall profiles."
                    ),
                    category="firewall",
                    evidence=states,
                    score=0 if enabled else 20,
                )
            ]
        except Exception:
            LOGGER.exception("FirewallRule failed")
            return []
