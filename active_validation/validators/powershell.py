"""PowerShell logging validators with minimized event evidence."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from active_validation.enums import ActiveValidationStatus, RiskLevel
from active_validation.models import (
    ActiveValidationResult,
    ValidationContext,
    ValidationPlan,
    ValidatorDefinition,
)
from active_validation.validators.base import BaseActiveValidator, utc_start

SCRIPT_DIR = Path(__file__).resolve().parents[1] / "powershell"


class PowerShellScriptBlockLoggingValidator(BaseActiveValidator):
    """Confirm Script Block Logging using a unique harmless marker."""

    definition = ValidatorDefinition(
        validator_id="VAL-PS-SCRIPTBLOCK-001",
        version="1.0.0",
        title="PowerShell Script Block Logging runtime validation",
        description="Checks for the validator's Event ID 4104 marker.",
        supported_rule_ids=("PS-002",),
        supported_platforms=("windows",),
        required_privileges=("STANDARD_USER",),
        risk_level=RiskLevel.LOW_IMPACT,
        network_impact="NONE",
        system_change_impact="TRANSIENT_EVENT",
        requires_rollback=False,
        default_timeout_seconds=20,
        maximum_timeout_seconds=60,
        required_capabilities=("POWERSHELL", "EVENT_LOG_READ"),
        evidence_produced=("EVENT_ID", "MARKER_HASH", "BOOLEAN_OBSERVATION"),
        safety_constraints=("NO_FULL_EVENT_PAYLOAD", "NO_USER_COMMAND_HISTORY"),
    )

    def execute(
        self,
        context: ValidationContext,
        plan: ValidationPlan,
    ) -> ActiveValidationResult:
        """Run the contract script and return its minimized result."""

        return _run_contract_script(self, "Validate-ScriptBlockLogging.ps1", context)


class PowerShellModuleLoggingValidator(BaseActiveValidator):
    """Reserve module logging validation pending stable cross-version behavior."""

    definition = ValidatorDefinition(
        validator_id="VAL-PS-MODULELOG-001",
        version="1.0.0",
        title="PowerShell Module Logging runtime validation",
        description=(
            "Reserved until stable Windows and PowerShell edition behavior "
            "is verified."
        ),
        supported_rule_ids=("PS-003",),
        supported_platforms=("windows",),
        required_privileges=("STANDARD_USER",),
        risk_level=RiskLevel.LOW_IMPACT,
        network_impact="NONE",
        system_change_impact="TRANSIENT_EVENT",
        requires_rollback=False,
        default_timeout_seconds=20,
        maximum_timeout_seconds=60,
        required_capabilities=("POWERSHELL", "EVENT_LOG_READ"),
        evidence_produced=("EVENT_ID", "BOOLEAN_OBSERVATION"),
        safety_constraints=("NO_FULL_EVENT_PAYLOAD",),
    )

    def execute(
        self,
        context: ValidationContext,
        plan: ValidationPlan,
    ) -> ActiveValidationResult:
        """Return an explicit unsupported result while under review."""

        started_at, started_clock = utc_start()
        return self.result(
            context,
            ActiveValidationStatus.NOT_SUPPORTED,
            started_at,
            started_clock,
            limitations=["Cross-version event semantics require human review."],
        )


def _run_contract_script(
    validator: BaseActiveValidator,
    script_name: str,
    context: ValidationContext,
) -> ActiveValidationResult:
    """Execute one JSON-only PowerShell contract script."""

    started_at, started_clock = utc_start()
    script = SCRIPT_DIR / script_name
    input_path = Path(context.temporary_directory) / "powershell-input.json"
    input_path.write_text(
        json.dumps(
            {
                "schemaVersion": "1.0",
                "runId": context.run_id,
                "validatorId": context.validator_id,
                "timeoutSeconds": context.timeout_seconds,
                "temporaryDirectory": context.temporary_directory,
                "policy": context.policy,
            }
        ),
        encoding="utf-8",
    )
    stdout_path = Path(context.temporary_directory) / "powershell-stdout.json"
    stderr_path = Path(context.temporary_directory) / "powershell-stderr.log"
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        process = subprocess.Popen(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script),
                "-InputPath",
                str(input_path),
            ],
            stdout=stdout,
            stderr=stderr,
            creationflags=(
                subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
            ),
        )
        try:
            process.wait(timeout=context.timeout_seconds)
        except subprocess.TimeoutExpired:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            else:
                process.kill()
            return validator.result(
                context,
                ActiveValidationStatus.TIMED_OUT,
                started_at,
                started_clock,
                error_code="POWERSHELL_CONTRACT_TIMEOUT",
                error_summary="PowerShell validator exceeded its timeout",
            )
    if stdout_path.stat().st_size > 65_536 or stderr_path.stat().st_size > 65_536:
        return validator.result(
            context,
            ActiveValidationStatus.ERROR,
            started_at,
            started_clock,
            error_code="POWERSHELL_OUTPUT_LIMIT_EXCEEDED",
            error_summary="PowerShell validator output exceeded its limit",
        )
    if process.returncode != 0:
        return validator.result(
            context,
            ActiveValidationStatus.ERROR,
            started_at,
            started_clock,
            error_code="POWERSHELL_CONTRACT_FAILED",
            error_summary="PowerShell validator returned a non-zero exit code",
        )
    try:
        payload = json.loads(stdout_path.read_text(encoding="utf-8"))
        status = ActiveValidationStatus(payload["status"])
        evidence = payload.get("evidence", [])
        limitations = payload.get("limitations", [])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return validator.result(
            context,
            ActiveValidationStatus.ERROR,
            started_at,
            started_clock,
            error_code="INVALID_POWERSHELL_RESULT",
            error_summary="PowerShell validator output did not match the contract",
        )
    return validator.result(
        context,
        status,
        started_at,
        started_clock,
        evidence=evidence,
        limitations=limitations,
    )
