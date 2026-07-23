"""Active validation orchestration with authorization and safety gates."""

from __future__ import annotations

import platform as runtime_platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from active_validation.audit import AuditLog
from active_validation.correlation import correlate
from active_validation.digest import sha256_digest
from active_validation.enums import ResponderExposureStatus, ResponderRiskLevel
from active_validation.executor import ValidationExecutor
from active_validation.models import (
    ActiveValidationRun,
    ActiveValidationSummary,
    CorrelatedRuleResult,
    ResponderExposureAssessment,
    SafetyPolicy,
    ValidationAuthorization,
    ValidationContext,
)
from active_validation.planner import ValidationPlanner
from active_validation.registry import ValidatorRegistry
from active_validation.serialization import active_result_to_dict
from risk import Finding


def disabled_run() -> ActiveValidationRun:
    """Return an explicit disabled result for normal passive analysis."""

    return ActiveValidationRun(
        run_id="",
        enabled=False,
        state="DISABLED",
        formal_authorization_verified=False,
    )


def execute_active_validation(
    data: dict[str, Any],
    findings: list[Finding],
    policy: SafetyPolicy,
    authorization: ValidationAuthorization,
    requested_validator_ids: list[str],
    audit_path: str | Path,
    assessment_id: str | None = None,
    profile: str | None = None,
    registry: ValidatorRegistry | None = None,
    executor: ValidationExecutor | None = None,
    require_related_rule: bool = True,
) -> ActiveValidationRun:
    """Plan and execute an explicitly authorized active validation run."""

    validator_registry = registry or ValidatorRegistry()
    validation_executor = executor or ValidationExecutor()
    planner = ValidationPlanner(validator_registry)
    run_id = uuid4().hex
    device_identifier = _device_identifier(data)
    plans = planner.plan(
        run_id=run_id,
        requested_validator_ids=requested_validator_ids,
        policy=policy,
        authorization=authorization,
        device_identifier=device_identifier,
        assessment_id=assessment_id,
        profile=profile,
        platform=_target_platform(data),
        observed_privileges=_observed_privileges(data),
        available_rule_ids=(
            {finding.rule_id for finding in findings}
            if require_related_rule
            else None
        ),
    )
    audit = AuditLog(audit_path)
    audit.append(
        "authorization_loaded",
        {
            "runId": run_id,
            "assessmentId": authorization.assessment_id,
            "authorizationDigest": authorization.digest,
        },
    )
    audit.append(
        "policy_loaded",
        {"runId": run_id, "policyDigest": policy.digest},
    )
    audit.append(
        "plan_created",
        {
            "runId": run_id,
            "validatorIds": [plan.validator_id for plan in plans],
        },
    )
    started_at = datetime.now(timezone.utc).isoformat()
    passive_results = {
        finding.rule_id: finding.status.value for finding in findings
    }
    results = []
    for plan in plans:
        entry = validator_registry.get(plan.validator_id)
        assert entry is not None
        audit.append(
            "validator_started",
            {"runId": run_id, "validatorId": plan.validator_id},
        )
        context = ValidationContext(
            schema_version="1.0",
            run_id=run_id,
            validator_id=plan.validator_id,
            timeout_seconds=plan.timeout_seconds,
            temporary_directory="",
            host_identifier_hash=sha256_digest(device_identifier),
            authorization_digest=authorization.digest,
            policy_digest=policy.digest,
            platform=_target_platform(data),
            observed_privileges=_observed_privileges(data),
            passive_data=_minimal_passive_data(data),
            passive_results=passive_results,
            prior_results=[active_result_to_dict(item) for item in results],
            policy=_policy_context(policy),
        )
        result = validation_executor.execute(entry, plan, context)
        definition = validator_registry.definition(entry)
        result.rule_ids = list(entry.supported_rule_ids)
        result.risk_level = definition.risk_level
        result.required_privileges = list(definition.required_privileges)
        results.append(result)
        if result.status.value == "TIMED_OUT":
            audit.append(
                "validator_timed_out",
                {"runId": run_id, "validatorId": result.validator_id},
            )
        audit.append(
            "validator_completed",
            {
                "runId": run_id,
                "validatorId": result.validator_id,
                "status": result.status.value,
                "durationMs": result.duration_ms,
                "cleanupCompleted": result.cleanup.completed,
            },
        )
        if result.cleanup.required:
            audit.append(
                "cleanup_started",
                {"runId": run_id, "validatorId": result.validator_id},
            )
            audit.append(
                "cleanup_completed" if result.cleanup.completed else "cleanup_failed",
                {
                    "runId": run_id,
                    "validatorId": result.validator_id,
                    "manualCleanupRequired": result.cleanup.manual_cleanup_required,
                },
            )
    correlations: list[CorrelatedRuleResult] = []
    for result in results:
        entry = validator_registry.get(result.validator_id)
        assert entry is not None
        for rule_id in entry.supported_rule_ids:
            correlations.append(
                CorrelatedRuleResult(
                    rule_id=rule_id,
                    passive_status=passive_results.get(rule_id),
                    validator_id=result.validator_id,
                    active_status=result.status,
                    correlated_status=correlate(
                        passive_results.get(rule_id),
                        result.status,
                    ),
                )
            )
    completed_at = datetime.now(timezone.utc).isoformat()
    audit.append(
        "run_completed",
        {
            "runId": run_id,
            "resultCount": len(results),
            "manualCleanupRequired": any(
                item.cleanup.manual_cleanup_required for item in results
            ),
        },
    )
    return ActiveValidationRun(
        run_id=run_id,
        enabled=True,
        state="COMPLETED",
        assessment_id=authorization.assessment_id,
        started_at=started_at,
        completed_at=completed_at,
        policy_digest=policy.digest,
        authorization_digest=authorization.digest,
        formal_authorization_verified=True,
        requested_validator_ids=sorted(requested_validator_ids),
        planned_validator_ids=[plan.validator_id for plan in plans],
        summary=_build_summary(plans, results),
        results=results,
        correlations=correlations,
        responder_exposure=_extract_responder_assessment(results),
        audit_log_path=Path(audit_path).name,
    )


def _build_summary(
    plans: list[Any],
    results: list[Any],
) -> ActiveValidationSummary:
    """Build deterministic report counters from exact statuses."""

    statuses = [item.status.value for item in results]
    return ActiveValidationSummary(
        planned=len(plans),
        executed=len(results),
        passed=statuses.count("PASSED"),
        failed=statuses.count("FAILED"),
        inconclusive=statuses.count("INCONCLUSIVE"),
        skipped=sum(
            statuses.count(status)
            for status in (
                "SKIPPED",
                "NOT_APPLICABLE",
                "NOT_SUPPORTED",
                "ACCESS_DENIED",
                "BLOCKED_BY_SAFETY_POLICY",
                "BLOCKED_BY_AUTHORIZATION",
            )
        ),
        errors=statuses.count("ERROR"),
        timeouts=statuses.count("TIMED_OUT"),
        rollback_failures=statuses.count("ROLLBACK_FAILED"),
    )


def _minimal_passive_data(data: dict[str, Any]) -> dict[str, Any]:
    """Return only canonical security settings needed for correlation."""

    security = data.get("security", {})
    settings = security.get("settings", []) if isinstance(security, dict) else []
    safe_settings = []
    for setting in settings if isinstance(settings, list) else []:
        if not isinstance(setting, dict):
            continue
        safe_settings.append({
            key: setting.get(key)
            for key in (
                "settingId",
                "effectiveValue",
                "configuredValue",
                "source",
                "collectionStatus",
                "provider",
            )
        })
    operating_system = data.get("operatingSystem", {})
    return {
        "security": {"settings": safe_settings},
        "operatingSystem": {
            "name": (
                operating_system.get("name")
                if isinstance(operating_system, dict)
                else None
            ),
            "version": (
                operating_system.get("version")
                if isinstance(operating_system, dict)
                else None
            ),
            "architecture": (
                operating_system.get("architecture")
                if isinstance(operating_system, dict)
                else None
            ),
        },
    }


def _device_identifier(data: dict[str, Any]) -> str:
    """Return the explicit collector device identifier."""

    device = data.get("device", {})
    value = device.get("hostname") if isinstance(device, dict) else None
    value = value or data.get("ComputerName")
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Collector device identifier is required for authorization")
    return value


def _target_platform(data: dict[str, Any]) -> str:
    """Return the collector target platform without guessing from software names."""

    operating_system = data.get("operatingSystem", {})
    name = (
        operating_system.get("name", "")
        if isinstance(operating_system, dict)
        else ""
    )
    if not name:
        name = str(data.get("OS", ""))
    if "windows" in str(name).casefold():
        return "windows"
    if "linux" in str(name).casefold():
        return "linux"
    return runtime_platform.system().casefold()


def _observed_privileges(data: dict[str, Any]) -> tuple[str, ...]:
    """Return collected privilege state without attempting elevation."""

    device = data.get("device", {})
    elevated = device.get("elevated") if isinstance(device, dict) else False
    if elevated is True:
        return ("STANDARD_USER", "LOCAL_ADMIN")
    return ("STANDARD_USER",)


def _policy_context(policy: SafetyPolicy) -> dict[str, Any]:
    """Return a small policy subset for isolated validators."""

    return {
        "allowTemporarySystemChanges": policy.allow_temporary_system_changes,
        "allowNetworkListeners": policy.allow_network_listeners,
        "allowOutboundNetworkTests": policy.allow_outbound_network_tests,
        "allowLoopbackNetworkTests": policy.allow_loopback_network_tests,
        "retainRawEventData": policy.retain_raw_event_data,
    }


def _extract_responder_assessment(
    results: list[Any],
) -> ResponderExposureAssessment | None:
    """Extract the typed responder aggregate from minimized evidence."""

    aggregate = next(
        (
            item
            for item in results
            if item.validator_id == "VAL-RESPONDER-EXPOSURE-001"
        ),
        None,
    )
    if aggregate is None or not aggregate.evidence:
        return None
    evidence = aggregate.evidence[0]
    try:
        return ResponderExposureAssessment(
            status=ResponderExposureStatus(evidence["exposureStatus"]),
            risk_level=ResponderRiskLevel(evidence["riskLevel"]),
            confidence=int(evidence["confidence"]),
            attack_prerequisites=list(evidence.get("attackPrerequisites", [])),
            observed_attack_paths=list(evidence.get("observedAttackPaths", [])),
            mitigating_controls=list(evidence.get("mitigatingControls", [])),
            missing_evidence=list(evidence.get("missingEvidence", [])),
            limitations=list(aggregate.limitations),
        )
    except (KeyError, TypeError, ValueError):
        return ResponderExposureAssessment(
            status=ResponderExposureStatus.ERROR,
            limitations=["Responder aggregate result was invalid."],
        )
