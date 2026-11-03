"""BitLocker security rule."""

from __future__ import annotations

import logging
from typing import Any

from analysis_context import AnalysisContext
from evidence.bitlocker import resolve_bitlocker
from risk import Finding, Severity, Status
from rules.base import BaseRule
from rules.categories import RuleCategory
from rules.metadata import RuleMetadata

LOGGER = logging.getLogger(__name__)


class BitLockerRule(BaseRule):
    """Check whether BitLocker is enabled for the system drive."""

    metadata = RuleMetadata(
        id="BIT-001",
        title="BitLocker protection",
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
                    "confidence": setting.confidence,
                    "mount_point": setting.metadata.get("mountPoint"),
                    "encryption_state": setting.metadata.get("encryptionState"),
                    "encryption_percentage": setting.metadata.get("encryptionPercentage"),
                    "fallbacks_attempted": setting.metadata.get("fallbacksAttempted", []),
                    "raw_evidence": setting.metadata.get("rawEvidence"),
                }
                conclusion = resolve_bitlocker({
                    "settingId": setting.setting_id,
                    "collectionStatus": setting.collection_status.value,
                    "effectiveValue": setting.effective_value,
                    "provider": setting.provider,
                    "collectedAt": setting.collected_at.isoformat() if setting.collected_at else None,
                    "metadata": setting.metadata,
                })
                detail["encryption_percentage"] = conclusion["encryptionPercentage"]
                detail["effective_value"] = conclusion["protectionEnabled"]
                detail["encryption_state"] = conclusion["encryptionState"]
                detail["authority"] = conclusion["authority"]
                detail["fallbacks_attempted"] = conclusion["providerAttempts"]
                detail["observed_at"] = conclusion["observedAt"]
                detail["reason_code"] = conclusion["reasonCode"]
                detail["bitlocker_state"] = conclusion["state"]
                detail["reason"] = conclusion["reason"]
                detail["shell_raw_value"] = conclusion["shellRawValue"]
                detail["shell_read_status"] = conclusion["shellReadStatus"]
                detail["shell_protection_indication"] = conclusion["shellProtectionIndication"]
                detail["shell_interpretation_method"] = conclusion["shellInterpretationMethod"]
                detail["authoritative_protection_status"] = conclusion["authoritativeProtectionStatus"]
                detail["authoritative_volume_status"] = conclusion["authoritativeVolumeStatus"]
                status = Status(conclusion["status"])
                return [
                    Finding(
                        rule_id=self.id,
                        severity=Severity.HIGH if status == Status.FAIL else Severity.LOW if status == Status.PASS else Severity.INFO,
                        status=status,
                        evidence=detail,
                        affected_asset="system_drive",
                        score=20 if status == Status.FAIL else 0,
                    )
                ]
            return self.not_evaluated(["BITLOCKER_OS_PROTECTION"])
        except Exception as error:
            LOGGER.exception("BitLockerRule failed")
            return self.error(str(error))
