"""Active validation orchestration with authorization and safety gates."""

from __future__ import annotations

import platform as runtime_platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from active_validation.audit import AuditLog, audit_verification_summary
from active_validation.correlation import correlate
from active_validation.digest import sha256_digest
from active_validation.deep_protocol import build_run_marker
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
from active_validation.planner import ValidationPlanner, plan_digest
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
    required_plan_digest: str | None = None,
    transport_observations: dict[str, dict[str, Any]] | None = None,
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
    current_plan_digest = plan_digest(plans)
    if (
        required_plan_digest is not None
        and required_plan_digest != current_plan_digest
    ):
        raise ValueError("Required plan digest does not match the execution plan")
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
            {
                "runId": run_id,
                "validatorId": plan.validator_id,
                "executionPolicyBypassUsed": (
                    "POWERSHELL"
                    in validator_registry.definition(entry).required_capabilities
                ),
            },
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
            authorization_scope=_authorization_scope_context(authorization),
            authorization_permissions=_authorization_permissions_context(
                authorization
            ),
            test_identity=_test_identity_context(authorization),
            profile=profile,
            transport_observation=_transport_context(
                (transport_observations or {}).get(plan.validator_id),
                run_id,
            ),
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
    final_hash = audit.append(
        "run_completed",
        {
            "runId": run_id,
            "resultCount": len(results),
            "manualCleanupRequired": any(
                item.cleanup.manual_cleanup_required for item in results
            ),
        },
    )
    verification = audit_verification_summary(audit_path)
    if verification["finalAuditEntryHash"] != final_hash:
        raise RuntimeError("Audit terminal hash verification failed")
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
        plan_digest=current_plan_digest,
        assessment_depth=(
            "DEEP_VALIDATION"
            if profile == "deep-responder-validation"
            else "SAFE_OBSERVATION"
        ),
        final_audit_entry_hash=verification["finalAuditEntryHash"],
        audit_entry_count=verification["auditEntryCount"],
        audit_verification_status=verification["auditVerificationStatus"],
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
        "allowDeepResponderValidation":
            policy.allow_deep_responder_validation,
        "allowNameResolutionResponses":
            policy.allow_name_resolution_responses,
        "allowAuthenticationChallenges":
            policy.allow_authentication_challenges,
        "allowTemporaryNetworkListeners":
            policy.allow_temporary_network_listeners,
        "allowTemporaryFirewallChanges":
            policy.allow_temporary_firewall_changes,
        "allowSyntheticCredentialFlow":
            policy.allow_synthetic_credential_flow,
        "allowRealCredentialObservation":
            policy.allow_real_credential_observation,
        "allowCredentialMaterialRetention":
            policy.allow_credential_material_retention,
        "allowCredentialRelay": policy.allow_credential_relay,
        "allowHashCracking": policy.allow_hash_cracking,
        "allowExternalTargets": policy.allow_external_targets,
    }


def _authorization_scope_context(
    authorization: ValidationAuthorization,
) -> dict[str, Any]:
    """Return explicit network scope for an isolated validator."""

    return {
        "networkInterfaces": list(authorization.scope.network_interfaces),
        "allowedSourceAddresses": list(
            authorization.scope.allowed_source_addresses
        ),
        "allowedTargetAddresses": list(
            authorization.scope.allowed_target_addresses
        ),
        "allowedProtocols": list(authorization.scope.allowed_protocols),
    }


def _authorization_permissions_context(
    authorization: ValidationAuthorization,
) -> dict[str, bool]:
    """Return operation booleans without authorization prose or identities."""

    permissions = authorization.permissions
    return {
        "nameResolutionSpoofing": permissions.name_resolution_spoofing,
        "authenticationChallenge": permissions.authentication_challenge,
        "temporaryListener": permissions.temporary_listener,
        "temporaryFirewallChange": permissions.temporary_firewall_change,
        "credentialMaterialRetention": permissions.credential_material_retention,
        "credentialRelay": permissions.credential_relay,
        "hashCracking": permissions.hash_cracking,
    }


def _test_identity_context(
    authorization: ValidationAuthorization,
) -> dict[str, Any] | None:
    """Return a hashed test-identity descriptor without its secret reference."""

    identity = authorization.test_identity
    if identity is None:
        return None
    return {
        "mode": identity.mode.value,
        "identityHash": f"sha256:{sha256_digest(identity.identifier)}",
        "authorizedForAuthenticationTest":
            identity.authorized_for_authentication_test,
    }


def _transport_context(
    observation: dict[str, Any] | None,
    run_id: str,
) -> dict[str, Any] | None:
    """Bind a controlled integration transport signal to the actual run marker."""

    if observation is None:
        return None
    bounded = dict(observation)
    if bounded.get("queryMarker") == "$CSA_RUN_MARKER":
        bounded["queryMarker"] = build_run_marker(run_id)
    return bounded


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
