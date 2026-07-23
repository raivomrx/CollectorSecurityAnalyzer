"""Subprocess-isolated active validation execution."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import ctypes
from ctypes import (
    Structure,
    byref,
    c_int64,
    c_size_t,
    c_uint32,
    c_uint64,
    c_void_p,
    sizeof,
)
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
from typing import Any

from active_validation.cleanup import (
    DEFAULT_STATE_PATH,
    DEFAULT_TEMPORARY_ROOT,
    CleanupRegistry,
)
from active_validation.enums import ActiveValidationStatus, RiskLevel
from active_validation.models import (
    ActiveValidationResult,
    RegistryEntry,
    RollbackResult,
    ValidationContext,
    ValidationPlan,
)

MAX_STDOUT_BYTES = 262_144
MAX_STDERR_BYTES = 65_536


class ValidationExecutor:
    """Run each validator in a bounded, minimally privileged subprocess."""

    def __init__(
        self,
        temporary_root: str | Path | None = None,
        cleanup_state_path: str | Path | None = None,
    ) -> None:
        """Create an executor using a dedicated temporary root."""

        self.temporary_root = Path(temporary_root) if temporary_root else None
        state_path = (
            Path(cleanup_state_path)
            if cleanup_state_path
            else (
                self.temporary_root / "cleanup-state.json"
                if self.temporary_root
                else DEFAULT_STATE_PATH
            )
        )
        self.cleanup_registry = CleanupRegistry(
            state_path,
            self.temporary_root or DEFAULT_TEMPORARY_ROOT,
        )

    def execute(
        self,
        entry: RegistryEntry,
        plan: ValidationPlan,
        context: ValidationContext,
    ) -> ActiveValidationResult:
        """Execute one plan and contain timeout, output, and process failures."""

        run_dir = Path(
            tempfile.mkdtemp(
                prefix=f"CSA-VALIDATION-{plan.run_id}-",
                dir=self.temporary_root,
            )
        )
        context.temporary_directory = str(run_dir)
        self.cleanup_registry.track({
            "objectType": "temporary_directory",
            "name": run_dir.name,
            "path": str(run_dir),
            "runId": plan.run_id,
            "createdAt": datetime.now(timezone.utc).isoformat(),
        })
        payload_path = run_dir / "worker-input.json"
        stdout_path = run_dir / "stdout.json"
        stderr_path = run_dir / "stderr.log"
        payload_path.write_text(
            json.dumps(
                {
                    "entry": {
                        "module": entry.module,
                        "className": entry.class_name,
                    },
                    "context": _context_to_dict(context),
                    "plan": _plan_to_dict(plan),
                },
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        started_at = datetime.now(timezone.utc).isoformat()
        started_clock = monotonic()
        timed_out = False
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "active_validation.worker",
                    "--input",
                    str(payload_path),
                ],
                cwd=Path(__file__).resolve().parent.parent,
                env=_minimal_environment(),
                stdout=stdout,
                stderr=stderr,
                creationflags=(
                    subprocess.CREATE_NEW_PROCESS_GROUP
                    if os.name == "nt"
                    else 0
                ),
            )
            job = _WindowsJob(process)
            try:
                process.wait(timeout=plan.timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate_process_tree(process, job)
            finally:
                job.close()
        if timed_out:
            cleanup = self._rollback_in_recovery(payload_path, run_dir, plan)
            result = _failure_result(
                context,
                plan,
                ActiveValidationStatus.TIMED_OUT,
                started_at,
                started_clock,
                cleanup,
                "VALIDATOR_TIMEOUT",
                "Validator exceeded its approved timeout",
            )
        elif (
            stdout_path.stat().st_size > MAX_STDOUT_BYTES
            or stderr_path.stat().st_size > MAX_STDERR_BYTES
        ):
            cleanup = self._rollback_in_recovery(payload_path, run_dir, plan)
            result = _failure_result(
                context,
                plan,
                ActiveValidationStatus.ERROR,
                started_at,
                started_clock,
                cleanup,
                "OUTPUT_LIMIT_EXCEEDED",
                "Validator output exceeded the configured limit",
            )
        elif process.returncode != 0:
            cleanup = self._rollback_in_recovery(payload_path, run_dir, plan)
            result = _failure_result(
                context,
                plan,
                ActiveValidationStatus.ERROR,
                started_at,
                started_clock,
                cleanup,
                "WORKER_EXIT_ERROR",
                "Validator worker returned a non-zero exit code",
            )
        else:
            try:
                result = _result_from_dict(
                    json.loads(
                        stdout_path.read_text(encoding="utf-8"),
                        object_pairs_hook=_reject_duplicates,
                    )
                )
                if (
                    result.run_id != plan.run_id
                    or result.validator_id != plan.validator_id
                    or result.validator_version != plan.validator_version
                ):
                    raise ValueError("Worker result identity mismatch")
            except (OSError, UnicodeError, ValueError, KeyError, TypeError):
                cleanup = self._rollback_in_recovery(payload_path, run_dir, plan)
                result = _failure_result(
                    context,
                    plan,
                    ActiveValidationStatus.ERROR,
                    started_at,
                    started_clock,
                    cleanup,
                    "INVALID_WORKER_OUTPUT",
                    "Validator worker output did not match the result contract",
                )
        if not result.cleanup.manual_cleanup_required:
            shutil.rmtree(run_dir, ignore_errors=True)
            if not run_dir.exists():
                self.cleanup_registry.forget(run_dir)
        return result

    def _rollback_in_recovery(
        self,
        payload_path: Path,
        run_dir: Path,
        plan: ValidationPlan,
    ) -> RollbackResult:
        """Attempt rollback in a fresh worker after killing a timed-out tree."""

        if not plan.requires_rollback:
            return RollbackResult(required=False, completed=True)
        output_path = run_dir / "rollback.json"
        error_path = run_dir / "rollback-error.log"
        with output_path.open("wb") as stdout, error_path.open("wb") as stderr:
            try:
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "active_validation.worker",
                        "--input",
                        str(payload_path),
                        "--rollback-only",
                    ],
                    cwd=Path(__file__).resolve().parent.parent,
                    env=_minimal_environment(),
                    stdout=stdout,
                    stderr=stderr,
                    timeout=min(10, plan.timeout_seconds),
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return RollbackResult(
                    required=True,
                    completed=False,
                    manual_cleanup_required=True,
                    error_code="ROLLBACK_TIMEOUT",
                )
        try:
            data = json.loads(output_path.read_text(encoding="utf-8"))["cleanup"]
            return _cleanup_from_dict(data)
        except (OSError, ValueError, KeyError, TypeError):
            return RollbackResult(
                required=True,
                completed=False,
                manual_cleanup_required=True,
                error_code=(
                    "ROLLBACK_WORKER_ERROR"
                    if completed.returncode
                    else "INVALID_ROLLBACK_OUTPUT"
                ),
            )


def _minimal_environment() -> dict[str, str]:
    """Return a minimal environment without inherited credentials or proxies."""

    allowed = ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT")
    environment = {
        key: os.environ[key]
        for key in allowed
        if key in os.environ
    }
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
    environment["PYTHONIOENCODING"] = "utf-8"
    return environment


def _terminate_process_tree(
    process: subprocess.Popen[Any],
    job: "_WindowsJob",
) -> None:
    """Terminate a validator and its descendants."""

    if os.name == "nt":
        job.close()
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        process.kill()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


class _JobBasicLimitInformation(Structure):
    """Windows job limits used by the extended limit structure."""

    _fields_ = [
        ("PerProcessUserTimeLimit", c_int64),
        ("PerJobUserTimeLimit", c_int64),
        ("LimitFlags", c_uint32),
        ("MinimumWorkingSetSize", c_size_t),
        ("MaximumWorkingSetSize", c_size_t),
        ("ActiveProcessLimit", c_uint32),
        ("Affinity", c_size_t),
        ("PriorityClass", c_uint32),
        ("SchedulingClass", c_uint32),
    ]


class _IoCounters(Structure):
    """Windows job I/O counters required by the native structure."""

    _fields_ = [
        ("ReadOperationCount", c_uint64),
        ("WriteOperationCount", c_uint64),
        ("OtherOperationCount", c_uint64),
        ("ReadTransferCount", c_uint64),
        ("WriteTransferCount", c_uint64),
        ("OtherTransferCount", c_uint64),
    ]


class _JobExtendedLimitInformation(Structure):
    """Windows extended job limits with kill-on-close support."""

    _fields_ = [
        ("BasicLimitInformation", _JobBasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", c_size_t),
        ("JobMemoryLimit", c_size_t),
        ("PeakProcessMemoryUsed", c_size_t),
        ("PeakJobMemoryUsed", c_size_t),
    ]


class _WindowsJob:
    """Own a Windows kill-on-close job for one validator process tree."""

    _KILL_ON_JOB_CLOSE = 0x00002000
    _EXTENDED_LIMIT_INFORMATION = 9

    def __init__(self, process: subprocess.Popen[Any]) -> None:
        """Create and assign the worker to a kill-on-close job when supported."""

        self._handle: int | None = None
        if os.name != "nt":
            return
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.restype = c_void_p
        kernel32.CreateJobObjectW.argtypes = (c_void_p, c_void_p)
        kernel32.SetInformationJobObject.argtypes = (
            c_void_p,
            c_uint32,
            c_void_p,
            c_uint32,
        )
        kernel32.AssignProcessToJobObject.argtypes = (c_void_p, c_void_p)
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            return
        limits = _JobExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = self._KILL_ON_JOB_CLOSE
        configured = kernel32.SetInformationJobObject(
            handle,
            self._EXTENDED_LIMIT_INFORMATION,
            byref(limits),
            sizeof(limits),
        )
        assigned = configured and kernel32.AssignProcessToJobObject(
            handle,
            c_void_p(int(process._handle)),
        )
        if not assigned:
            kernel32.CloseHandle(handle)
            return
        self._handle = int(handle)

    def close(self) -> None:
        """Close the job exactly once, terminating any remaining descendants."""

        if self._handle is None:
            return
        ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(
            c_void_p(self._handle)
        )
        self._handle = None


def _context_to_dict(context: ValidationContext) -> dict[str, Any]:
    """Serialize context using the worker contract."""

    return {
        "schemaVersion": context.schema_version,
        "runId": context.run_id,
        "validatorId": context.validator_id,
        "timeoutSeconds": context.timeout_seconds,
        "temporaryDirectory": context.temporary_directory,
        "hostIdentifierHash": context.host_identifier_hash,
        "authorizationDigest": context.authorization_digest,
        "policyDigest": context.policy_digest,
        "platform": context.platform,
        "observedPrivileges": list(context.observed_privileges),
        "passiveData": context.passive_data,
        "passiveResults": context.passive_results,
        "priorResults": context.prior_results,
        "policy": context.policy,
    }


def _plan_to_dict(plan: ValidationPlan) -> dict[str, Any]:
    """Serialize a plan using the worker contract."""

    return {
        "runId": plan.run_id,
        "validatorId": plan.validator_id,
        "validatorVersion": plan.validator_version,
        "timeoutSeconds": plan.timeout_seconds,
        "riskLevel": plan.risk_level.value,
        "requiresRollback": plan.requires_rollback,
        "temporaryObjectPrefix": plan.temporary_object_prefix,
        "sequence": plan.sequence,
    }


def _result_from_dict(data: dict[str, Any]) -> ActiveValidationResult:
    """Parse a strict worker result."""

    cleanup = _cleanup_from_dict(data["cleanup"])
    return ActiveValidationResult(
        schema_version=data["schemaVersion"],
        run_id=data["runId"],
        validator_id=data["validatorId"],
        validator_version=data["validatorVersion"],
        status=ActiveValidationStatus(data["status"]),
        started_at=data["startedAt"],
        completed_at=data["completedAt"],
        duration_ms=int(data["durationMs"]),
        host_identifier_hash=data["hostIdentifierHash"],
        authorization_digest=data["authorizationDigest"],
        policy_digest=data["policyDigest"],
        rule_ids=data.get("ruleIds", []),
        risk_level=(
            None
            if data.get("riskLevel") is None
            else RiskLevel(data["riskLevel"])
        ),
        required_privileges=data.get("requiredPrivileges", []),
        evidence=data.get("evidence", []),
        limitations=data.get("limitations", []),
        cleanup=cleanup,
        error_code=data.get("errorCode"),
        error_summary=data.get("errorSummary"),
    )


def _cleanup_from_dict(data: dict[str, Any]) -> RollbackResult:
    """Parse worker cleanup metadata."""

    return RollbackResult(
        required=bool(data["required"]),
        completed=bool(data["completed"]),
        manual_cleanup_required=bool(data.get("manualCleanupRequired", False)),
        remaining_objects=data.get("remainingObjects", []),
        error_code=data.get("errorCode"),
    )


def _failure_result(
    context: ValidationContext,
    plan: ValidationPlan,
    status: ActiveValidationStatus,
    started_at: str,
    started_clock: float,
    cleanup: RollbackResult,
    error_code: str,
    error_summary: str,
) -> ActiveValidationResult:
    """Build a contained executor failure."""

    if cleanup.required and not cleanup.completed:
        status = ActiveValidationStatus.ROLLBACK_FAILED
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
        cleanup=cleanup,
        error_code=error_code,
        error_summary=error_summary,
    )


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate keys in worker output."""

    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate worker result key")
        result[key] = value
    return result
