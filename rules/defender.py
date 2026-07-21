"""Windows Defender security rule."""

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

    def check(
        self,
        data: dict[str, Any],
        context: AnalysisContext | None = None,
    ) -> list[Finding]:
        """Return a Defender finding for collector data."""

        LOGGER.info("Running DefenderRule")
        try:
            setting = (
                context.evidence_registry.get("DEFENDER_ENABLED")
                if context and context.evidence_registry
                else None
            )
            if setting is not None:
                if setting.collection_status.value != "SUCCESS":
                    return [
                        Finding(
                            rule_id=self.id,
                            severity=Severity.INFO,
                            status=Status.NOT_EVALUATED,
                            evidence={
                                "setting_id": setting.setting_id,
                                "collection_status": setting.collection_status.value,
                            },
                            score=0,
                        )
                    ]
                enabled = bool(setting.effective_value)
                return [
                    Finding(
                        rule_id=self.id,
                        severity=Severity.LOW if enabled else Severity.HIGH,
                        status=Status.PASS if enabled else Status.FAIL,
                        evidence={
                            "setting_id": setting.setting_id,
                            "effective_value": setting.effective_value,
                        },
                        score=0 if enabled else 20,
                    )
                ]
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
