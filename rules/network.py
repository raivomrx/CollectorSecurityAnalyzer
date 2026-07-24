"""Network profile security rule."""

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

    def check(
        self,
        data: dict[str, Any],
        context: AnalysisContext | None = None,
    ) -> list[Finding]:
        """Return a network profile finding for collector data."""

        LOGGER.info("Running NetworkRule")
        try:
            setting = (
                context.evidence_registry.get("ACTIVE_NETWORK_CATEGORY")
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
                categories = (
                    setting.effective_value
                    if isinstance(setting.effective_value, list)
                    else [setting.effective_value]
                )
                is_public = any(str(item).casefold() == "public" for item in categories)
                return [
                    Finding(
                        rule_id=self.id,
                        severity=Severity.MEDIUM if is_public else Severity.LOW,
                        status=Status.FAIL if is_public else Status.PASS,
                        evidence={"NetworkCategory": categories},
                        score=10 if is_public else 0,
                    )
                ]
            if context and context.evidence_registry:
                return self.not_evaluated(["ACTIVE_NETWORK_CATEGORY"])
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
