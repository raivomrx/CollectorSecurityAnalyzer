"""Windows Firewall security rule."""

from __future__ import annotations

import logging
from typing import Any

from analysis_context import AnalysisContext
from risk import Finding, Severity, Status
from rules.base import BaseRule
from rules.categories import RuleCategory
from rules.metadata import RuleMetadata
from utils import safe_get

LOGGER = logging.getLogger(__name__)
PROFILES = ("Domain", "Private", "Public")


class FirewallRule(BaseRule):
    """Check whether Domain, Private, and Public firewall profiles are enabled."""

    metadata = RuleMetadata(
        id="FW-001",
        title="Windows Firewall Profiles Enabled",
        version="1.0",
        author="CSA",
        category=RuleCategory.FIREWALL,
        severity=Severity.HIGH,
        enabled=True,
        description="Checks whether all Windows Firewall profiles are enabled.",
    )

    def check(
        self,
        data: dict[str, Any],
        context: AnalysisContext | None = None,
    ) -> list[Finding]:
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
                    severity=Severity.LOW if enabled else Severity.HIGH,
                    status=Status.PASS if enabled else Status.FAIL,
                    evidence=states,
                    score=0 if enabled else 20,
                )
            ]
        except Exception:
            LOGGER.exception("FirewallRule failed")
            return []
