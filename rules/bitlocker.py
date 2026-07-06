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

    def check(self, data: dict[str, Any]) -> list[Finding]:
        """Return a BitLocker finding for collector data."""

        LOGGER.info("Running BitLockerRule")
        try:
            enabled = bool(safe_get(data, "Bitlocker-C", False))
            if enabled:
                return [
                    Finding(
                        rule_id=self.id,
                        severity="LOW",
                        status="PASS",
                        evidence={"Bitlocker-C": enabled},
                        score=0,
                    )
                ]

            return [
                Finding(
                    rule_id=self.id,
                    severity="HIGH",
                    status="FAIL",
                    evidence={"Bitlocker-C": enabled},
                    affected_asset="system_drive",
                    score=20,
                )
            ]
        except Exception:
            LOGGER.exception("BitLockerRule failed")
            return []
