"""BitLocker security rule."""

from __future__ import annotations

import logging
from typing import Any

from risk import Finding
from rules.base import BaseRule
from utils import safe_get

LOGGER = logging.getLogger(__name__)


class BitLockerRule(BaseRule):
    """Check whether BitLocker is enabled for the system drive."""

    id = "BIT-001"
    title = "BitLocker system drive protection"
    description = "System drive should be protected by BitLocker."

    def check(self, data: dict[str, Any]) -> list[Finding]:
        """Return a BitLocker finding for collector data."""

        LOGGER.info("Running BitLockerRule")
        try:
            enabled = bool(safe_get(data, "Bitlocker-C", False))
            if enabled:
                return [
                    Finding(
                        rule_id=self.id,
                        title=self.title,
                        severity="LOW",
                        status="PASS",
                        description="BitLocker is enabled on the system drive.",
                        recommendation="No action required.",
                        category="disk_encryption",
                        score=0,
                    )
                ]

            return [
                Finding(
                    rule_id=self.id,
                    title=self.title,
                    severity="HIGH",
                    status="FAIL",
                    description="BitLocker is not enabled on the system drive.",
                    recommendation="Enable BitLocker on system drive.",
                    category="disk_encryption",
                    score=20,
                )
            ]
        except Exception:
            LOGGER.exception("BitLockerRule failed")
            return []
