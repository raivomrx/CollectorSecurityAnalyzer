"""BitLocker security rule."""

from __future__ import annotations

import logging
from typing import Any

from risk import Finding, Severity, Status
from rules.base import BaseRule
from rules.categories import RuleCategory
from rules.metadata import RuleMetadata
from utils import safe_get

LOGGER = logging.getLogger(__name__)


class BitLockerRule(BaseRule):
    """Check whether BitLocker is enabled for the system drive."""

    metadata = RuleMetadata(
        id="BIT-001",
        title="BitLocker Enabled",
        version="1.0",
        author="CSA",
        category=RuleCategory.ENCRYPTION,
        severity=Severity.HIGH,
        enabled=True,
        description="Checks whether BitLocker protects the system drive.",
    )

    def check(self, data: dict[str, Any]) -> list[Finding]:
        """Return a BitLocker finding for collector data."""

        LOGGER.info("Running BitLockerRule")
        try:
            enabled = bool(safe_get(data, "Bitlocker-C", False))
            if enabled:
                return [
                    Finding(
                        rule_id=self.id,
                        severity=Severity.LOW,
                        status=Status.PASS,
                        evidence={"Bitlocker-C": enabled},
                        score=0,
                    )
                ]

            return [
                Finding(
                    rule_id=self.id,
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    evidence={"Bitlocker-C": enabled},
                    affected_asset="system_drive",
                    score=20,
                )
            ]
        except Exception:
            LOGGER.exception("BitLockerRule failed")
            return []
