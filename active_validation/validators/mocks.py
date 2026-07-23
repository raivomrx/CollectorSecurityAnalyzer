"""Non-production validators used only by contract tests."""

from __future__ import annotations

import os
import subprocess
import sys
import time

from active_validation.enums import ActiveValidationStatus, RiskLevel
from active_validation.models import (
    ActiveValidationResult,
    RollbackResult,
    ValidationContext,
    ValidationPlan,
    ValidatorDefinition,
)
from active_validation.validators.base import BaseActiveValidator, utc_start


class MockValidator(BaseActiveValidator):
    """Return the requested test outcome without touching the host."""

    definition = ValidatorDefinition(
        validator_id="VAL-MOCK-001",
        version="1.0.0",
        title="Contract mock",
        description="Test-only validator.",
        supported_rule_ids=("PS-002",),
        supported_platforms=("windows", "linux"),
        required_privileges=(),
        risk_level=RiskLevel.SAFE_READ_ONLY,
        network_impact="NONE",
        system_change_impact="NONE",
        requires_rollback=False,
        default_timeout_seconds=2,
        maximum_timeout_seconds=5,
        required_capabilities=(),
        evidence_produced=("BOOLEAN_OBSERVATION",),
        safety_constraints=("TEST_ONLY",),
    )

    def execute(
        self,
        context: ValidationContext,
        plan: ValidationPlan,
    ) -> ActiveValidationResult:
        """Return the outcome selected in test policy."""

        started_at, started_clock = utc_start()
        behavior = context.policy.get("mockBehavior", "pass")
        if behavior == "nonzero":
            os._exit(7)
        if behavior == "malformed":
            sys.stdout.write("{malformed")
            sys.stdout.flush()
            os._exit(0)
        if behavior == "oversized_stdout":
            sys.stdout.write("X" * 262_145)
            sys.stdout.flush()
            os._exit(0)
        if behavior == "oversized_stderr":
            sys.stderr.write("X" * 65_537)
            sys.stderr.flush()
            os._exit(0)
        if behavior == "timeout":
            time.sleep(context.timeout_seconds + 2)
        if behavior == "process_tree_timeout":
            marker_path = context.policy["processTreeMarker"]
            subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    (
                        "import pathlib,sys,time;"
                        "time.sleep(2);"
                        "pathlib.Path(sys.argv[1]).write_text('survived')"
                    ),
                    marker_path,
                ]
            )
            time.sleep(context.timeout_seconds + 2)
        if behavior == "error":
            raise RuntimeError("Mock execution error")
        if behavior == "sensitive":
            evidence = [{"observation": "password=blocked-value"}]
        elif behavior == "environment":
            evidence = [{
                "evidenceType": "MOCK_ENVIRONMENT",
                "secretInherited": os.getenv("CSA_TEST_SECRET") is not None,
            }]
        else:
            evidence = [{"evidenceType": "MOCK", "observed": behavior == "pass"}]
        result = self.result(
            context,
            (
                ActiveValidationStatus.PASSED
                if behavior == "pass"
                else ActiveValidationStatus.FAILED
            ),
            started_at,
            started_clock,
            evidence=evidence,
        )
        if behavior == "validator_mismatch":
            result.validator_id = "VAL-WRONG-001"
        if behavior == "run_mismatch":
            result.run_id = "wrong-run"
        return result


class MockRollbackFailureValidator(MockValidator):
    """Return an explicit rollback failure for executor tests."""

    definition = ValidatorDefinition(
        validator_id="VAL-MOCK-ROLLBACK-001",
        version="1.0.0",
        title="Rollback contract mock",
        description="Test-only rollback failure.",
        supported_rule_ids=("FW-005",),
        supported_platforms=("windows", "linux"),
        required_privileges=(),
        risk_level=RiskLevel.CONTROLLED_TEMPORARY_CHANGE,
        network_impact="NONE",
        system_change_impact="TEMPORARY_TEST_OBJECT",
        requires_rollback=True,
        default_timeout_seconds=2,
        maximum_timeout_seconds=5,
        required_capabilities=(),
        evidence_produced=("BOOLEAN_OBSERVATION",),
        safety_constraints=("TEST_ONLY",),
    )

    def rollback(
        self,
        context: ValidationContext,
        plan: ValidationPlan,
    ) -> RollbackResult:
        """Simulate a tracked object requiring manual cleanup."""

        return RollbackResult(
            required=True,
            completed=False,
            manual_cleanup_required=True,
            remaining_objects=[{
                "objectType": "temporary_file",
                "redactedName": f"CSA-VALIDATION-{context.run_id}",
            }],
            error_code="MOCK_ROLLBACK_FAILED",
        )


class MockRollbackSuccessValidator(MockValidator):
    """Confirm that rollback runs across every worker outcome."""

    definition = ValidatorDefinition(
        validator_id="VAL-MOCK-ROLLBACK-SUCCESS-001",
        version="1.0.0",
        title="Rollback success contract mock",
        description="Test-only successful rollback.",
        supported_rule_ids=("FW-005",),
        supported_platforms=("windows", "linux"),
        required_privileges=(),
        risk_level=RiskLevel.CONTROLLED_TEMPORARY_CHANGE,
        network_impact="NONE",
        system_change_impact="TEMPORARY_TEST_OBJECT",
        requires_rollback=True,
        default_timeout_seconds=2,
        maximum_timeout_seconds=5,
        required_capabilities=(),
        evidence_produced=("BOOLEAN_OBSERVATION",),
        safety_constraints=("TEST_ONLY",),
    )

    def rollback(
        self,
        context: ValidationContext,
        plan: ValidationPlan,
    ) -> RollbackResult:
        """Report successful cleanup from normal and recovery workers."""

        return RollbackResult(required=True, completed=True)
