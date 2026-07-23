"""Isolated active validator worker process."""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from time import monotonic
from typing import Any

from active_validation.enums import ActiveValidationStatus, RiskLevel
from active_validation.evidence import SensitiveEvidenceError, validate_evidence
from active_validation.models import (
    ActiveValidationResult,
    RollbackResult,
    ValidationContext,
    ValidationPlan,
)
from active_validation.serialization import active_result_to_dict


def main() -> None:
    """Execute exactly one validator contract from a bounded input file."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--rollback-only", action="store_true")
    args = parser.parse_args()
    payload = json.loads(open(args.input, encoding="utf-8").read())
    validator = _load_validator(payload["entry"])
    context = _context_from_dict(payload["context"])
    plan = _plan_from_dict(payload["plan"])
    if args.rollback_only:
        cleanup = validator.rollback(context, plan)
        sys.stdout.write(json.dumps({"cleanup": _normalize_cleanup(cleanup)}))
        return
    result = _execute_validator(validator, context, plan)
    sys.stdout.write(
        json.dumps(active_result_to_dict(result), separators=(",", ":"))
    )


def _execute_validator(
    validator: Any,
    context: ValidationContext,
    plan: ValidationPlan,
) -> ActiveValidationResult:
    """Execute and rollback one validator while containing failures."""

    started_at = datetime.now(timezone.utc).isoformat()
    started_clock = monotonic()
    try:
        applicability = validator.check_applicability(context)
        if not applicability.applicable:
            result = _basic_result(
                context,
                plan,
                applicability.status,
                started_at,
                started_clock,
                limitations=[applicability.reason] if applicability.reason else [],
            )
        else:
            validator_plan = validator.plan(context)
            result = validator.execute(context, validator_plan)
            validate_evidence(result.evidence)
    except SensitiveEvidenceError:
        result = _basic_result(
            context,
            plan,
            ActiveValidationStatus.ERROR,
            started_at,
            started_clock,
            error_code="SENSITIVE_EVIDENCE_BLOCKED",
            error_summary="Validator evidence violated the sensitive-data policy",
        )
    except Exception:
        result = _basic_result(
            context,
            plan,
            ActiveValidationStatus.ERROR,
            started_at,
            started_clock,
            error_code="VALIDATOR_EXCEPTION",
            error_summary="Validator execution failed",
        )
    try:
        cleanup = validator.rollback(context, plan)
    except Exception:
        cleanup = RollbackResult(
            required=plan.requires_rollback,
            completed=False,
            manual_cleanup_required=True,
            error_code="ROLLBACK_EXCEPTION",
        )
    result.cleanup = cleanup
    if cleanup.required and not cleanup.completed:
        result.status = ActiveValidationStatus.ROLLBACK_FAILED
    try:
        _validate_cleanup_names(result.cleanup)
        validate_evidence([{
            "evidence": result.evidence,
            "limitations": result.limitations,
            "cleanup": asdict(result.cleanup),
            "errorSummary": result.error_summary,
        }])
    except SensitiveEvidenceError:
        result = _basic_result(
            context,
            plan,
            ActiveValidationStatus.ERROR,
            started_at,
            started_clock,
            error_code="SENSITIVE_EVIDENCE_BLOCKED",
            error_summary="Validator output violated the sensitive-data policy",
        )
        result.cleanup = cleanup
        if cleanup.required and not cleanup.completed:
            result.status = ActiveValidationStatus.ROLLBACK_FAILED
    return result


def _validate_cleanup_names(cleanup: RollbackResult) -> None:
    """Require redacted CSA namespace names for remaining objects."""

    for item in cleanup.remaining_objects:
        name = item.get("redactedName", "")
        if (
            not isinstance(name, str)
            or not name.startswith(("CSA-VALIDATION-", "CSA_VALIDATION_"))
            or "/" in name
            or "\\" in name
        ):
            raise SensitiveEvidenceError(
                "Cleanup object name violated the redaction contract"
            )


def _basic_result(
    context: ValidationContext,
    plan: ValidationPlan,
    status: ActiveValidationStatus,
    started_at: str,
    started_clock: float,
    limitations: list[str] | None = None,
    error_code: str | None = None,
    error_summary: str | None = None,
) -> ActiveValidationResult:
    """Build a failure-contained result without implementation details."""

    return ActiveValidationResult(
        schema_version="1.0",
        run_id=context.run_id,
        validator_id=context.validator_id,
        validator_version=plan.validator_version,
        status=status,
        started_at=started_at,
        completed_at=datetime.now(timezone.utc).isoformat(),
        duration_ms=max(0, round((monotonic() - started_clock) * 1000)),
        host_identifier_hash=context.host_identifier_hash,
        authorization_digest=context.authorization_digest,
        policy_digest=context.policy_digest,
        limitations=limitations or [],
        cleanup=RollbackResult(
            required=plan.requires_rollback,
            completed=not plan.requires_rollback,
        ),
        error_code=error_code,
        error_summary=error_summary,
    )


def _load_validator(entry: dict[str, str]) -> Any:
    """Load the exact implementation approved by the parent process."""

    module = importlib.import_module(entry["module"])
    return getattr(module, entry["className"])()


def _context_from_dict(data: dict[str, Any]) -> ValidationContext:
    """Deserialize an isolated validation context."""

    return ValidationContext(
        schema_version=data["schemaVersion"],
        run_id=data["runId"],
        validator_id=data["validatorId"],
        timeout_seconds=int(data["timeoutSeconds"]),
        temporary_directory=data["temporaryDirectory"],
        host_identifier_hash=data["hostIdentifierHash"],
        authorization_digest=data["authorizationDigest"],
        policy_digest=data["policyDigest"],
        platform=data["platform"],
        observed_privileges=tuple(data.get("observedPrivileges", [])),
        passive_data=data.get("passiveData", {}),
        passive_results=data.get("passiveResults", {}),
        prior_results=data.get("priorResults", []),
        policy=data.get("policy", {}),
        authorization_scope=data.get("authorizationScope", {}),
        authorization_permissions=data.get("authorizationPermissions", {}),
        test_identity=data.get("testIdentity"),
        profile=data.get("profile"),
        transport_observation=data.get("transportObservation"),
    )


def _plan_from_dict(data: dict[str, Any]) -> ValidationPlan:
    """Deserialize a reviewed execution plan."""

    return ValidationPlan(
        run_id=data["runId"],
        validator_id=data["validatorId"],
        validator_version=data["validatorVersion"],
        timeout_seconds=int(data["timeoutSeconds"]),
        risk_level=RiskLevel(data["riskLevel"]),
        requires_rollback=bool(data["requiresRollback"]),
        temporary_object_prefix=data["temporaryObjectPrefix"],
        sequence=int(data["sequence"]),
        profile=data.get("profile"),
    )


def _normalize_cleanup(cleanup: RollbackResult) -> dict[str, Any]:
    """Return cleanup data using the worker JSON contract."""

    data = asdict(cleanup)
    return {
        "required": data["required"],
        "completed": data["completed"],
        "manualCleanupRequired": data["manual_cleanup_required"],
        "remainingObjects": data["remaining_objects"],
        "errorCode": data["error_code"],
    }


if __name__ == "__main__":
    main()
