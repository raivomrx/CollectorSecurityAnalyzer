"""Software inventory quality rule."""

from __future__ import annotations

import logging
from typing import Any

from analysis_context import AnalysisContext
from risk import Finding, Severity, Status
from rules.base import BaseRule
from rules.categories import RuleCategory
from rules.metadata import RuleMetadata
from software.inventory import build_inventory

LOGGER = logging.getLogger(__name__)


class SoftwareInventoryRule(BaseRule):
    """Check whether software inventory contains unknown products."""

    metadata = RuleMetadata(
        id="SW-001",
        title="Unknown Software Detected",
        version="1.0",
        author="CSA",
        category=RuleCategory.SOFTWARE,
        severity=Severity.MEDIUM,
        enabled=True,
        description="Checks whether software inventory contains unknown products.",
    )

    def check(
        self,
        data: dict[str, Any],
        context: AnalysisContext | None = None,
    ) -> list[Finding]:
        """Return a finding for unknown software products."""

        LOGGER.info("Running SoftwareInventoryRule")
        try:
            if context is not None:
                inventory = context.software_inventory
            else:
                software_items = data.get("Software", [])
                if not isinstance(software_items, list):
                    software_items = []
                inventory = build_inventory(software_items)
            unknown_names = [
                product.product for product in inventory.unknown_products
            ]
            has_unknown = len(unknown_names) > 0
            return [
                Finding(
                    rule_id=self.id,
                    severity=Severity.MEDIUM if has_unknown else Severity.INFO,
                    status=Status.WARNING if has_unknown else Status.PASS,
                    evidence={
                        "unknown_product_count": len(unknown_names),
                        "unknown_product_names": unknown_names,
                    },
                    score=10 if has_unknown else 0,
                )
            ]
        except Exception:
            LOGGER.exception("SoftwareInventoryRule failed")
            return []
