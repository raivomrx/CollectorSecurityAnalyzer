"""BitLocker security rule."""

from __future__ import annotations

import logging
from typing import Any

from analysis_context import AnalysisContext
from collector_schema.enums import CollectionStatus
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

    def check(
        self,
        data: dict[str, Any],
        context: AnalysisContext | None = None,
    ) -> list[Finding]:
        """Return a BitLocker finding for collector data."""

        LOGGER.info("Running BitLockerRule")
        try:
            setting = (
                context.evidence_registry.get("BITLOCKER_OS_PROTECTION")
                if context and context.evidence_registry
                else None
            )
            if setting is not None:
                detail = {
                    "setting_id": setting.setting_id,
                    "collection_status": setting.collection_status.value,
                    "provider": setting.provider,
                    "configured_value": setting.configured_value,
                    "effective_value": setting.effective_value,
                    "confidence": setting.confidence,
                    "mount_point": setting.metadata.get("mountPoint"),
                    "encryption_state": setting.metadata.get("encryptionState"),
                    "encryption_percentage": setting.metadata.get("encryptionPercentage"),
                    "fallbacks_attempted": setting.metadata.get("fallbacksAttempted", []),
                    "raw_evidence": setting.metadata.get("rawEvidence"),
                }
                if setting.collection_status == CollectionStatus.PARTIAL:
                    return [
                        Finding(
                            rule_id=self.id,
                            severity=Severity.INFO,
                            status=Status.PARTIAL,
                            evidence=detail,
                            score=0,
                        )
                    ]
                if setting.collection_status == CollectionStatus.FAILED:
                    return self.error("BitLocker evidence collection failed")
                if setting.collection_status != CollectionStatus.SUCCESS:
                    return [
                        Finding(
                            rule_id=self.id,
                            severity=Severity.INFO,
                            status=Status.NOT_EVALUATED,
                            evidence=detail,
                            score=0,
                        )
                    ]
                enabled = bool(setting.effective_value)
                return [
                    Finding(
                        rule_id=self.id,
                        severity=Severity.LOW if enabled else Severity.HIGH,
                        status=Status.PASS if enabled else Status.FAIL,
                        evidence=detail,
                        affected_asset="system_drive",
                        score=0 if enabled else 20,
                    )
                ]
            if context and context.evidence_registry:
                return self.not_evaluated(["BITLOCKER_OS_PROTECTION"])
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
        except Exception as error:
            LOGGER.exception("BitLockerRule failed")
            return self.error(str(error))
