"""Windows Updates freshness rule."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from risk import Finding, Severity, Status
from rules.base import BaseRule
from rules.categories import RuleCategory
from rules.metadata import RuleMetadata
from utils import parse_date, safe_get

LOGGER = logging.getLogger(__name__)
MAX_UPDATE_AGE_DAYS = 45


class UpdatesRule(BaseRule):
    """Check whether the last successful update installation is recent."""

    metadata = RuleMetadata(
        id="UPD-001",
        title="Windows Updates Freshness",
        version="1.0",
        author="CSA",
        category=RuleCategory.UPDATES,
        severity=Severity.HIGH,
        enabled=True,
        description="Checks whether Windows updates were installed in the last 45 days.",
    )

    def check(self, data: dict[str, Any]) -> list[Finding]:
        """Return an updates freshness finding for collector data."""

        LOGGER.info("Running UpdatesRule")
        try:
            value = safe_get(data, "Updates_lastInstallationSuccessDate")
            parsed = parse_date(value)
            if parsed is None:
                return [
                    Finding(
                        rule_id=self.id,
                        severity=Severity.HIGH,
                        status=Status.FAIL,
                        evidence={"Updates_lastInstallationSuccessDate": value},
                        score=20,
                    )
                ]

            now = datetime.now(parsed.tzinfo) if parsed.tzinfo else datetime.now()
            age_days = (now - parsed).days
            stale = age_days > MAX_UPDATE_AGE_DAYS
            return [
                Finding(
                    rule_id=self.id,
                    severity=Severity.MEDIUM if stale else Severity.LOW,
                    status=Status.FAIL if stale else Status.PASS,
                    evidence={"lastInstallationSuccessDate": str(value), "age_days": age_days},
                    score=10 if stale else 0,
                )
            ]
        except Exception:
            LOGGER.exception("UpdatesRule failed")
            return []
