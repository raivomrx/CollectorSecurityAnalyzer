"""Local administrator account rule."""

from __future__ import annotations

import logging
from collections.abc import Sized
from typing import Any

from risk import Finding
from rules.base import BaseRule
from utils import safe_get

LOGGER = logging.getLogger(__name__)


class AdminRule(BaseRule):
    """Check whether the local administrators list is small and present."""

    id = "ADM-001"
    title = "Local administrators"
    description = "Local administrator membership should be known and limited."

    def check(self, data: dict[str, Any]) -> list[Finding]:
        """Return a local administrators finding for collector data."""

        LOGGER.info("Running AdminRule")
        try:
            admins = safe_get(data, "All_local_admins")
            if admins is None:
                return [
                    Finding(
                        rule_id=self.id,
                        title=self.title,
                        severity="INFO",
                        status="FAIL",
                        description="Local administrators data is missing.",
                        recommendation="Collect and review local administrators.",
                        category="identity",
                        score=0,
                    )
                ]

            count = _count_admins(admins)
            elevated = count > 2
            return [
                Finding(
                    rule_id=self.id,
                    title=self.title,
                    severity="MEDIUM" if elevated else "LOW",
                    status="FAIL" if elevated else "PASS",
                    description=(
                        f"{count} local administrators were found."
                        if elevated
                        else "Local administrators count is acceptable."
                    ),
                    recommendation=(
                        "Reduce local administrator membership to required accounts only."
                        if elevated
                        else "No action required."
                    ),
                    category="identity",
                    evidence={"count": count},
                    score=10 if elevated else 0,
                )
            ]
        except Exception:
            LOGGER.exception("AdminRule failed")
            return []


def _count_admins(admins: Any) -> int:
    """Return the number of local administrators from supported shapes."""

    if isinstance(admins, int):
        return admins
    if isinstance(admins, str):
        return len([item for item in admins.splitlines() if item.strip()])
    if isinstance(admins, Sized):
        return len(admins)
    return 0
