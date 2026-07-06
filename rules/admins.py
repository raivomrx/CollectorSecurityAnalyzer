"""Local administrator account rule."""

from __future__ import annotations

import logging
from collections.abc import Sized
from typing import Any

from risk import Finding, Severity, Status
from rules.base import BaseRule
from rules.categories import RuleCategory
from rules.metadata import RuleMetadata
from utils import safe_get

LOGGER = logging.getLogger(__name__)


class AdminRule(BaseRule):
    """Check whether the local administrators list is small and present."""

    metadata = RuleMetadata(
        id="ADM-001",
        title="Local Administrators Reviewed",
        version="1.0",
        author="CSA",
        category=RuleCategory.LOCAL_ADMINS,
        severity=Severity.MEDIUM,
        enabled=True,
        description="Checks whether local administrator membership is present and limited.",
    )

    def check(self, data: dict[str, Any]) -> list[Finding]:
        """Return a local administrators finding for collector data."""

        LOGGER.info("Running AdminRule")
        try:
            admins = safe_get(data, "All_local_admins")
            if admins is None:
                return [
                    Finding(
                        rule_id=self.id,
                        severity=Severity.INFO,
                        status=Status.FAIL,
                        evidence={"All_local_admins": None},
                        score=0,
                    )
                ]

            count = _count_admins(admins)
            elevated = count > 2
            return [
                Finding(
                    rule_id=self.id,
                    severity=Severity.MEDIUM if elevated else Severity.LOW,
                    status=Status.FAIL if elevated else Status.PASS,
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
