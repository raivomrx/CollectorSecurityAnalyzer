"""Read-only Windows Defender runtime validator."""

from active_validation.enums import RiskLevel
from active_validation.models import (
    ActiveValidationResult,
    ValidationContext,
    ValidationPlan,
    ValidatorDefinition,
)
from active_validation.validators.base import BaseActiveValidator
from active_validation.validators.powershell import _run_contract_script


class DefenderRuntimeValidator(BaseActiveValidator):
    """Confirm Defender runtime health without creating test files or scans."""

    definition = ValidatorDefinition(
        validator_id="VAL-DEFENDER-RUNTIME-001",
        version="1.0.0",
        title="Windows Defender runtime health",
        description="Reads service, engine, and real-time protection state.",
        supported_rule_ids=("DEF-001", "DEF-002", "DEF-008"),
        supported_platforms=("windows",),
        required_privileges=("STANDARD_USER",),
        risk_level=RiskLevel.SAFE_READ_ONLY,
        network_impact="NONE",
        system_change_impact="NONE",
        requires_rollback=False,
        default_timeout_seconds=15,
        maximum_timeout_seconds=30,
        required_capabilities=("POWERSHELL", "DEFENDER_STATUS"),
        evidence_produced=("BOOLEAN_OBSERVATION", "SERVICE_STATE"),
        safety_constraints=("NO_TEST_FILE", "NO_SCAN", "NO_QUARANTINE_READ"),
    )

    def execute(
        self,
        context: ValidationContext,
        plan: ValidationPlan,
    ) -> ActiveValidationResult:
        """Read Defender operational state through a JSON-only script."""

        return _run_contract_script(self, "Validate-DefenderRuntime.ps1", context)
