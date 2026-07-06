"""Network profile security rule."""

from __future__ import annotations

import logging
from typing import Any

from risk import Finding, Severity, Status
from rules.base import BaseRule
from rules.categories import RuleCategory
from rules.metadata import RuleMetadata
from utils import safe_get

LOGGER = logging.getLogger(__name__)


class NetworkRule(BaseRule):
    """Check whether the active network category is Public."""

    metadata = RuleMetadata(
        id="NET-001",
        title="Network Profile Category",
        version="1.0",
        author="CSA",
        category=RuleCategory.NETWORK,
        severity=Severity.MEDIUM,
        enabled=True,
        description="Checks whether the active network profile is Public.",
    )

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
                    severity=Severity.MEDIUM if is_public else Severity.LOW,
                    status=Status.FAIL if is_public else Status.PASS,
                    evidence={"NetworkCategory": category},
                    score=10 if is_public else 0,
                )
            ]
        except Exception:
            LOGGER.exception("NetworkRule failed")
            return []
