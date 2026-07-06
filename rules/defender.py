"""Windows Defender security rule."""

from __future__ import annotations

import logging
from typing import Any

from risk import Finding, Severity, Status
from rules.base import BaseRule
from rules.categories import RuleCategory
from rules.metadata import RuleMetadata
from utils import safe_get

LOGGER = logging.getLogger(__name__)


class DefenderRule(BaseRule):
    """Check whether Windows Defender is enabled."""

    metadata = RuleMetadata(
        id="DEF-001",
        title="Windows Defender Enabled",
        version="1.0",
        author="CSA",
        category=RuleCategory.DEFENDER,
        severity=Severity.HIGH,
        enabled=True,
        description="Checks whether Microsoft Defender Antivirus is enabled.",
    )

    def check(self, data: dict[str, Any]) -> list[Finding]:
        """Return a Defender finding for collector data."""

        LOGGER.info("Running DefenderRule")
        try:
            product_state = str(safe_get(data, "Windows Defender.ProductState", "")).strip()
            enabled = product_state.casefold() == "on"
            return [
                Finding(
                    rule_id=self.id,
                    severity=Severity.LOW if enabled else Severity.HIGH,
                    status=Status.PASS if enabled else Status.FAIL,
                    evidence={"ProductState": product_state},
                    score=0 if enabled else 20,
                )
            ]
        except Exception:
            LOGGER.exception("DefenderRule failed")
            return []
