"""Passive and active result correlation."""

from __future__ import annotations

from active_validation.enums import ActiveValidationStatus, CorrelatedRuleStatus

NOT_VALIDATED = {
    ActiveValidationStatus.NOT_REQUESTED,
    ActiveValidationStatus.PLANNED,
    ActiveValidationStatus.SKIPPED,
    ActiveValidationStatus.NOT_APPLICABLE,
    ActiveValidationStatus.NOT_SUPPORTED,
    ActiveValidationStatus.ACCESS_DENIED,
    ActiveValidationStatus.BLOCKED_BY_SAFETY_POLICY,
    ActiveValidationStatus.BLOCKED_BY_AUTHORIZATION,
    ActiveValidationStatus.INCONCLUSIVE,
    ActiveValidationStatus.ERROR,
    ActiveValidationStatus.TIMED_OUT,
    ActiveValidationStatus.ROLLBACK_FAILED,
}


def correlate(
    passive_status: str | None,
    active_status: ActiveValidationStatus,
) -> CorrelatedRuleStatus:
    """Correlate results without overwriting either original outcome."""

    passive = passive_status.upper() if passive_status else None
    if passive == "PASS" and active_status == ActiveValidationStatus.PASSED:
        return CorrelatedRuleStatus.CONFIRMED_PASS
    if (
        passive in {"FAIL", "WARNING"}
        and active_status == ActiveValidationStatus.FAILED
    ):
        return CorrelatedRuleStatus.CONFIRMED_FAIL
    if passive in {"PASS", "FAIL", "WARNING"} and active_status in {
        ActiveValidationStatus.PASSED,
        ActiveValidationStatus.FAILED,
    }:
        return CorrelatedRuleStatus.CONFIGURATION_RUNTIME_MISMATCH
    if passive is None and active_status == ActiveValidationStatus.PASSED:
        return CorrelatedRuleStatus.ACTIVE_ONLY_PASS
    if passive is None and active_status == ActiveValidationStatus.FAILED:
        return CorrelatedRuleStatus.ACTIVE_ONLY_FAIL
    if passive == "PASS" and active_status in NOT_VALIDATED:
        return CorrelatedRuleStatus.PASS_NOT_VALIDATED
    if passive in {"FAIL", "WARNING"} and active_status in NOT_VALIDATED:
        return CorrelatedRuleStatus.FAIL_NOT_VALIDATED
    if active_status in {
        ActiveValidationStatus.INCONCLUSIVE,
        ActiveValidationStatus.ERROR,
        ActiveValidationStatus.TIMED_OUT,
    }:
        return CorrelatedRuleStatus.INCONCLUSIVE
    return CorrelatedRuleStatus.NOT_EVALUATED
