"""Compliance scoring helpers."""

from __future__ import annotations

from compliance.enums import ComplianceStatus
from compliance.models import ControlAssessment


def weighted_score(controls: list[ControlAssessment]) -> float | None:
    """Calculate weighted compliance score separately from evidence coverage."""

    scored = [
        control for control in controls
        if control.status
        in {
            ComplianceStatus.COMPLIANT,
            ComplianceStatus.PARTIALLY_COMPLIANT,
            ComplianceStatus.NON_COMPLIANT,
        }
    ]
    if not scored:
        return None
    value = sum(_score_value(control.status) for control in scored) / len(scored)
    return round(value * 100, 1)


def _score_value(status: ComplianceStatus) -> float:
    """Return numeric score for one status."""

    if status == ComplianceStatus.COMPLIANT:
        return 1.0
    if status == ComplianceStatus.PARTIALLY_COMPLIANT:
        return 0.5
    return 0.0
