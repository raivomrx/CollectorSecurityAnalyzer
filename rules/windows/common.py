"""Shared helpers for Windows evidence-backed rules."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any

from analysis_context import AnalysisContext
from collector_schema.enums import CollectionStatus
from evidence.windows_models import SecuritySettingEvidence
from risk import Finding, Severity, Status
from rules.base import BaseRule
from rules.categories import RuleCategory
from rules.metadata import RuleMetadata

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SettingRuleSpec:
    """Describe a single evidence-backed rule."""

    rule_id: str
    title: str
    category: RuleCategory
    setting_id: str
    expected_value: Any = True
    severity: Severity = Severity.MEDIUM
    description: str = ""
    threshold_key: str | None = None
    maximum_value: int | float | None = None
    minimum_value: int | float | None = None
    fail_when_equal: Any = None
    only_when_setting_id: str | None = None
    only_when_value: Any = True
    approved_remote_products: bool = False


def create_setting_rule(spec: SettingRuleSpec) -> type[BaseRule]:
    """Create a concrete BaseRule subclass for one Windows evidence setting."""

    class WindowsSettingRule(BaseRule):
        """Evaluate one normalized Windows security setting."""

        metadata = RuleMetadata(
            id=spec.rule_id,
            title=spec.title,
            version="1.0",
            author="CSA",
            category=spec.category,
            severity=spec.severity,
            enabled=True,
            description=spec.description or spec.title,
        )

        def check(
            self,
            data: dict[str, Any],
            context: AnalysisContext | None = None,
        ) -> list[Finding]:
            """Evaluate the configured evidence setting."""

            LOGGER.info("Running %s", self.__class__.__name__)
            try:
                if context and spec.category.value in (context.skipped_categories or []):
                    return [_not_evaluated(spec, "Category was skipped by CLI.", None)]
                registry = context.evidence_registry if context else None
                if registry is None:
                    return [_not_evaluated(spec, "Normalized evidence registry is unavailable.", None)]
                if spec.only_when_setting_id:
                    gate = registry.get(spec.only_when_setting_id)
                    if gate is None or gate.effective_value != spec.only_when_value:
                        return [_pass(spec, {"reason": "Prerequisite setting is not active."})]
                setting = registry.get(spec.setting_id)
                if setting is None:
                    return [_not_evaluated(spec, "Required evidence was not collected.", None)]
                status_finding = _status_finding(spec, setting)
                if status_finding is not None:
                    return [status_finding]
                passed, reason = _evaluate_setting(spec, setting, context)
                evidence = _evidence(setting, reason)
                return [
                    Finding(
                        rule_id=spec.rule_id,
                        severity=Severity.LOW if passed else spec.severity,
                        status=Status.PASS if passed else Status.FAIL,
                        score=0 if passed else _score(spec.severity),
                        evidence=evidence,
                    )
                ]
            except Exception as error:
                LOGGER.exception("%s failed", self.__class__.__name__)
                return [
                    Finding(
                        rule_id=spec.rule_id,
                        severity=Severity.INFO,
                        status=Status.ERROR,
                        score=0,
                        evidence={"error": str(error)},
                    )
                ]

    WindowsSettingRule.__name__ = _class_name(spec.rule_id)
    WindowsSettingRule.__qualname__ = WindowsSettingRule.__name__
    setattr(WindowsSettingRule, "spec", spec)
    return WindowsSettingRule


def _evaluate_setting(
    spec: SettingRuleSpec,
    setting: SecuritySettingEvidence,
    context: AnalysisContext | None,
) -> tuple[bool, str]:
    """Evaluate an evidence setting against a rule spec."""

    value = setting.effective_value
    if spec.approved_remote_products:
        approved = set(
            context.policy_profile.approved_remote_access_products
            if context and context.policy_profile
            else []
        )
        products = value if isinstance(value, list) else []
        unknown = [str(product) for product in products if str(product) not in approved]
        return not unknown, f"Unapproved remote products: {unknown}"
    if spec.threshold_key:
        threshold = _threshold(context, spec.threshold_key)
        numeric = _numeric_age_or_value(value)
        return numeric is not None and numeric <= threshold, f"Value {numeric}; threshold {threshold}"
    if spec.maximum_value is not None:
        numeric = _to_number(value)
        return numeric is not None and numeric <= spec.maximum_value, f"Value {numeric}; maximum {spec.maximum_value}"
    if spec.minimum_value is not None:
        numeric = _to_number(value)
        return numeric is not None and numeric >= spec.minimum_value, f"Value {numeric}; minimum {spec.minimum_value}"
    if spec.fail_when_equal is not None:
        return value != spec.fail_when_equal, f"Value {value}; must not equal {spec.fail_when_equal}"
    return value == spec.expected_value, f"Value {value}; expected {spec.expected_value}"


def _status_finding(spec: SettingRuleSpec, setting: SecuritySettingEvidence) -> Finding | None:
    """Convert collection status into conservative rule status."""

    if setting.collection_status == CollectionStatus.SUCCESS:
        return None
    if setting.collection_status == CollectionStatus.NOT_SUPPORTED:
        return Finding(
            rule_id=spec.rule_id,
            severity=Severity.INFO,
            status=Status.NOT_APPLICABLE,
            score=0,
            evidence=_evidence(setting, "Setting is not supported on this device."),
        )
    return _not_evaluated(spec, "Setting could not be collected.", setting)


def _not_evaluated(
    spec: SettingRuleSpec,
    reason: str,
    setting: SecuritySettingEvidence | None,
) -> Finding:
    """Return a NOT_EVALUATED finding."""

    return Finding(
        rule_id=spec.rule_id,
        severity=Severity.INFO,
        status=Status.NOT_EVALUATED,
        score=0,
        evidence=_evidence(setting, reason) if setting else {"reason": reason},
    )


def _pass(spec: SettingRuleSpec, evidence: dict[str, Any]) -> Finding:
    """Return a PASS finding."""

    return Finding(rule_id=spec.rule_id, severity=Severity.LOW, status=Status.PASS, score=0, evidence=evidence)


def _evidence(setting: SecuritySettingEvidence | None, reason: str) -> dict[str, Any]:
    """Return sanitized evidence details for a finding."""

    if setting is None:
        return {"reason": reason}
    return {
        "setting_id": setting.setting_id,
        "category": setting.category,
        "configured_value": setting.configured_value,
        "effective_value": setting.effective_value,
        "source": setting.source.value,
        "collection_status": setting.collection_status.value,
        "confidence": setting.confidence,
        "provider": setting.provider,
        "source_path": setting.source_path,
        "error_code": setting.error_code,
        "reason": reason,
    }


def _threshold(context: AnalysisContext | None, key: str) -> int:
    """Return policy threshold or a conservative default."""

    if context and context.policy_profile:
        return int(context.policy_profile.thresholds.get(key, 0))
    defaults = {
        "MaximumSignatureAgeDays": 3,
        "MaximumUpdateScanAgeDays": 14,
        "MaximumUpdateInstallAgeDays": 45,
        "MaximumPendingRebootAgeDays": 7,
        "MaximumLocalAdministrators": 3,
        "MaximumStaleAccountAgeDays": 90,
    }
    return defaults.get(key, 0)


def _numeric_age_or_value(value: Any) -> int | float | None:
    """Return a numeric age from a number or ISO date string."""

    numeric = _to_number(value)
    if numeric is not None:
        return numeric
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return (datetime.now(timezone.utc) - parsed).days
        except ValueError:
            try:
                parsed_date = date.fromisoformat(value[:10])
                return (date.today() - parsed_date).days
            except ValueError:
                return None
    return None


def _to_number(value: Any) -> int | float | None:
    """Convert a value to a number when possible."""

    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return value
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None


def _score(severity: Severity) -> int:
    """Return rule score impact for severity."""

    return {
        Severity.CRITICAL: 30,
        Severity.HIGH: 20,
        Severity.MEDIUM: 10,
        Severity.LOW: 5,
        Severity.INFO: 0,
    }.get(severity, 0)


def _class_name(rule_id: str) -> str:
    """Return a stable rule class name from a rule ID."""

    return "".join(part.capitalize() for part in rule_id.replace("-", "_").split("_")) + "Rule"
