"""Credential-safe Responder exposure policy checks and correlation."""

from __future__ import annotations

from typing import Any

from active_validation.enums import (
    ActiveValidationStatus,
    ResponderExposureStatus,
    ResponderRiskLevel,
    RiskLevel,
)
from active_validation.models import (
    ActiveValidationResult,
    ValidationContext,
    ValidationPlan,
    ValidatorDefinition,
)
from active_validation.validators.base import BaseActiveValidator, utc_start


class _RegistryPolicyValidator(BaseActiveValidator):
    """Read a bounded set of Windows registry values without exporting data."""

    registry_queries: tuple[tuple[str, str, str], ...] = ()

    def execute(
        self,
        context: ValidationContext,
        plan: ValidationPlan,
    ) -> ActiveValidationResult:
        """Read declared policy values and retain only typed observations."""

        started_at, started_clock = utc_start()
        try:
            import winreg
        except ImportError:
            return self.result(
                context,
                ActiveValidationStatus.NOT_SUPPORTED,
                started_at,
                started_clock,
                limitations=["Windows registry API is unavailable."],
            )
        observations: dict[str, Any] = {}
        for name, path, value_name in self.registry_queries:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                    value, _ = winreg.QueryValueEx(key, value_name)
                observations[name] = value
            except FileNotFoundError:
                observations[name] = None
            except PermissionError:
                return self.result(
                    context,
                    ActiveValidationStatus.ACCESS_DENIED,
                    started_at,
                    started_clock,
                    limitations=["A declared policy location was not readable."],
                )
        return self.interpret(context, started_at, started_clock, observations)

    def interpret(
        self,
        context: ValidationContext,
        started_at: str,
        started_clock: float,
        observations: dict[str, Any],
    ) -> ActiveValidationResult:
        """Translate bounded policy values into minimized evidence."""

        raise NotImplementedError


class WpadExposureValidator(_RegistryPolicyValidator):
    """Read machine WPAD policy without starting a server or resolving a name."""

    definition = ValidatorDefinition(
        validator_id="VAL-WPAD-EXPOSURE-001",
        version="1.0.0",
        title="WPAD policy exposure",
        description="Reads machine auto-proxy policy only.",
        supported_rule_ids=("PROTO-003",),
        supported_platforms=("windows",),
        required_privileges=("STANDARD_USER",),
        risk_level=RiskLevel.SAFE_READ_ONLY,
        network_impact="NONE",
        system_change_impact="NONE",
        requires_rollback=False,
        default_timeout_seconds=10,
        maximum_timeout_seconds=20,
        required_capabilities=("REGISTRY_READ",),
        evidence_produced=("BOOLEAN_OBSERVATION", "PROVENANCE"),
        safety_constraints=("NO_ROGUE_SERVER", "NO_NAME_RESOLUTION"),
        domain="RESPONDER_EXPOSURE",
    )
    registry_queries = (
        (
            "disableWpad",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp",
            "DisableWpad",
        ),
    )

    def interpret(
        self,
        context: ValidationContext,
        started_at: str,
        started_clock: float,
        observations: dict[str, Any],
    ) -> ActiveValidationResult:
        """Report whether machine policy explicitly disables WPAD."""

        disabled = observations["disableWpad"] == 1
        known = observations["disableWpad"] is not None
        if not known:
            status = ActiveValidationStatus.INCONCLUSIVE
        elif disabled:
            status = ActiveValidationStatus.PASSED
        else:
            status = ActiveValidationStatus.FAILED
        return self.result(
            context,
            status,
            started_at,
            started_clock,
            evidence=[{
                "evidenceType": "WPAD_POLICY",
                "explicitlyDisabled": disabled,
                "machinePolicyKnown": known,
                "provenance": "LOCAL_MACHINE_POLICY",
            }],
            limitations=[] if known else ["No explicit machine policy was available."],
        )


class NtlmPolicyValidator(_RegistryPolicyValidator):
    """Read local LAN Manager policy without claiming domain-effective denial."""

    definition = ValidatorDefinition(
        validator_id="VAL-NTLM-POLICY-001",
        version="1.0.0",
        title="Legacy authentication policy",
        description="Reads local policy and preserves effective-state uncertainty.",
        supported_rule_ids=("PROTO-006",),
        supported_platforms=("windows",),
        required_privileges=("STANDARD_USER",),
        risk_level=RiskLevel.SAFE_READ_ONLY,
        network_impact="NONE",
        system_change_impact="NONE",
        requires_rollback=False,
        default_timeout_seconds=10,
        maximum_timeout_seconds=20,
        required_capabilities=("REGISTRY_READ",),
        evidence_produced=("POLICY_STATE", "PROVENANCE"),
        safety_constraints=("NO_AUTHENTICATION", "NO_CREDENTIAL_MATERIAL"),
        domain="RESPONDER_EXPOSURE",
    )
    registry_queries = (
        (
            "compatibilityLevel",
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "LmCompatibilityLevel",
        ),
    )

    def interpret(
        self,
        context: ValidationContext,
        started_at: str,
        started_clock: float,
        observations: dict[str, Any],
    ) -> ActiveValidationResult:
        """Classify local policy conservatively."""

        value = observations["compatibilityLevel"]
        state = "UNKNOWN"
        if isinstance(value, int):
            state = "LEGACY_ALLOWED" if value < 5 else "RESTRICTED_LOCAL"
        return self.result(
            context,
            ActiveValidationStatus.INCONCLUSIVE,
            started_at,
            started_clock,
            evidence=[{
                "evidenceType": "AUTHENTICATION_POLICY",
                "policyState": state,
                "numericLevel": value if isinstance(value, int) else None,
                "provenance": "LOCAL_POLICY",
                "effectivePolicyConfirmed": False,
            }],
            limitations=[
                "Local policy alone does not prove domain-effective "
                "authentication behavior."
            ],
        )


class SmbSigningExposureValidator(_RegistryPolicyValidator):
    """Read SMB client/server signing requirements without opening a session."""

    definition = ValidatorDefinition(
        validator_id="VAL-SMB-SIGNING-EXPOSURE-001",
        version="1.0.0",
        title="SMB signing relay mitigation",
        description="Reads local client and server signing requirements.",
        supported_rule_ids=("PROTO-002",),
        supported_platforms=("windows",),
        required_privileges=("STANDARD_USER",),
        risk_level=RiskLevel.SAFE_READ_ONLY,
        network_impact="NONE",
        system_change_impact="NONE",
        requires_rollback=False,
        default_timeout_seconds=10,
        maximum_timeout_seconds=20,
        required_capabilities=("REGISTRY_READ",),
        evidence_produced=("BOOLEAN_OBSERVATION", "PROVENANCE"),
        safety_constraints=("NO_SESSION", "NO_AUTHENTICATION_CHALLENGE"),
        domain="RESPONDER_EXPOSURE",
    )
    registry_queries = (
        (
            "clientRequired",
            r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
            "RequireSecuritySignature",
        ),
        (
            "serverRequired",
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "RequireSecuritySignature",
        ),
    )

    def interpret(
        self,
        context: ValidationContext,
        started_at: str,
        started_clock: float,
        observations: dict[str, Any],
    ) -> ActiveValidationResult:
        """Report precise signing policy semantics."""

        client = observations["clientRequired"] == 1
        server = observations["serverRequired"] == 1
        known = all(observations[name] is not None for name in observations)
        if not known:
            status = ActiveValidationStatus.INCONCLUSIVE
        elif client and server:
            status = ActiveValidationStatus.PASSED
        else:
            status = ActiveValidationStatus.FAILED
        return self.result(
            context,
            status,
            started_at,
            started_clock,
            evidence=[{
                "evidenceType": "SMB_SIGNING_POLICY",
                "clientRequired": client,
                "serverRequired": server,
                "policyKnown": known,
                "provenance": "LOCAL_MACHINE_POLICY",
            }],
            limitations=[
                "Signing mitigates relay but does not by itself prevent "
                "credential exposure."
            ],
        )


class ResponderExposureValidator(BaseActiveValidator):
    """Correlate independent safe observations into attack-path risk."""

    definition = ValidatorDefinition(
        validator_id="VAL-RESPONDER-EXPOSURE-001",
        version="1.0.0",
        title="Responder-style exposure correlation",
        description=(
            "Correlates name resolution, authentication, path, and signing "
            "evidence."
        ),
        supported_rule_ids=("PROTO-002", "PROTO-003", "PROTO-004", "PROTO-006"),
        supported_platforms=("windows",),
        required_privileges=("STANDARD_USER",),
        risk_level=RiskLevel.SAFE_READ_ONLY,
        network_impact="NONE",
        system_change_impact="NONE",
        requires_rollback=False,
        default_timeout_seconds=5,
        maximum_timeout_seconds=10,
        required_capabilities=(),
        evidence_produced=("ATTACK_PATH_SUMMARY", "CONFIDENCE"),
        safety_constraints=(
            "NO_SPOOFING",
            "NO_ROGUE_SERVER",
            "NO_AUTHENTICATION_CHALLENGE",
            "NO_CREDENTIAL_MATERIAL",
        ),
        domain="RESPONDER_EXPOSURE",
    )

    def execute(
        self,
        context: ValidationContext,
        plan: ValidationPlan,
    ) -> ActiveValidationResult:
        """Apply conservative and transparent attack-path decision logic."""

        started_at, started_clock = utc_start()
        indexed = {
            item.get("validatorId"): item for item in context.prior_results
            if isinstance(item, dict)
        }
        classic_observation_ids = {
            "VAL-LLMNR-OBSERVE-001",
            "VAL-NBTNS-OBSERVE-001",
        }
        legacy_observed = any(
            indexed.get(item, {}).get("status") == "FAILED"
            for item in classic_observation_ids
        )
        legacy_not_observed = all(
            indexed.get(item, {}).get("status") == "PASSED"
            for item in classic_observation_ids
        )
        auth_state = _evidence_value(indexed.get("VAL-NTLM-POLICY-001"), "policyState")
        auth_effective = (
            _evidence_value(
                indexed.get("VAL-NTLM-POLICY-001"),
                "effectivePolicyConfirmed",
            )
            is True
        )
        auth_permitted = auth_effective and auth_state == "PERMITTED"
        auth_denied = auth_effective and auth_state in {
            "DENIED_EFFECTIVE",
            "RESTRICTED_EFFECTIVE",
        }
        path_value = _evidence_value(
            indexed.get("VAL-OUTBOUND-SMB-PATH-001"),
            "pathReachable",
        )
        path_known = isinstance(path_value, bool)
        path_available = path_value is True
        client_signing_value = _evidence_value(
            indexed.get("VAL-SMB-SIGNING-EXPOSURE-001"),
            "clientRequired",
        )
        server_signing_value = _evidence_value(
            indexed.get("VAL-SMB-SIGNING-EXPOSURE-001"),
            "serverRequired",
        )
        signing_known = isinstance(client_signing_value, bool) and isinstance(
            server_signing_value,
            bool,
        )
        client_signing = client_signing_value is True
        server_signing = server_signing_value is True
        signing_required = client_signing and server_signing
        config_likely = _passive_true(
            context.passive_data,
            "LLMNR_ENABLED",
        ) or _passive_true(
            context.passive_data,
            "NETBIOS_OVER_TCPIP_ENABLED",
        )

        status = ResponderExposureStatus.INCONCLUSIVE
        risk = ResponderRiskLevel.UNKNOWN
        active_status = ActiveValidationStatus.INCONCLUSIVE
        confidence = 35
        if (
            legacy_observed
            and auth_permitted
            and path_available
            and signing_known
            and not signing_required
        ):
            status, risk, active_status, confidence = (
                ResponderExposureStatus.EXPOSURE_CONFIRMED,
                ResponderRiskLevel.HIGH,
                ActiveValidationStatus.FAILED,
                95,
            )
        elif legacy_observed and auth_permitted:
            status, risk, active_status, confidence = (
                ResponderExposureStatus.EXPOSURE_CONFIRMED,
                ResponderRiskLevel.MEDIUM,
                ActiveValidationStatus.FAILED,
                85,
            )
        elif (
            config_likely
            and auth_permitted
            and signing_known
            and not signing_required
        ):
            status, risk, active_status, confidence = (
                ResponderExposureStatus.EXPOSURE_LIKELY,
                ResponderRiskLevel.MEDIUM,
                ActiveValidationStatus.FAILED,
                70,
            )
        elif legacy_observed and auth_denied and signing_required:
            status, risk, active_status, confidence = (
                ResponderExposureStatus.EXPOSURE_PARTIALLY_MITIGATED,
                ResponderRiskLevel.LOW,
                ActiveValidationStatus.INCONCLUSIVE,
                80,
            )
        elif legacy_not_observed and auth_denied and signing_required:
            status, risk, active_status, confidence = (
                ResponderExposureStatus.EXPOSURE_NOT_OBSERVED,
                ResponderRiskLevel.LOW,
                ActiveValidationStatus.PASSED,
                90,
            )
        prerequisites = []
        if legacy_observed:
            prerequisites.append("Legacy name query observed")
        if auth_permitted:
            prerequisites.append("Integrated authentication permitted")
        if path_available:
            prerequisites.append("Outbound service path available")
        mitigations = []
        if auth_denied:
            mitigations.append("Integrated authentication effectively restricted")
        if signing_required:
            mitigations.append("Client and server signing required")
        missing = [
            label
            for validator_id, label in (
                ("VAL-LLMNR-OBSERVE-001", "LLMNR observation"),
                ("VAL-NBTNS-OBSERVE-001", "NBT-NS observation"),
                ("VAL-NTLM-POLICY-001", "effective authentication policy"),
                ("VAL-SMB-SIGNING-EXPOSURE-001", "SMB signing policy"),
                ("VAL-OUTBOUND-SMB-PATH-001", "outbound service path"),
            )
            if (
                validator_id not in indexed
                or (
                    validator_id == "VAL-NTLM-POLICY-001"
                    and not auth_effective
                )
                or (
                    validator_id == "VAL-SMB-SIGNING-EXPOSURE-001"
                    and not signing_known
                )
                or (
                    validator_id == "VAL-OUTBOUND-SMB-PATH-001"
                    and not path_known
                )
            )
        ]
        attack_paths = []
        if legacy_observed or config_likely:
            attack_paths.append({
                "path": "LEGACY_NAME_RESOLUTION_TO_INTEGRATED_AUTH",
                "observation": "CONFIRMED" if legacy_observed else "CONFIGURATION_ONLY",
                "mitigation": (
                    "SIGNING_REQUIRED"
                    if signing_required
                    else "NOT_CONFIRMED"
                ),
            })
        evidence = [{
            "evidenceType": "RESPONDER_EXPOSURE_ASSESSMENT",
            "exposureStatus": status.value,
            "riskLevel": risk.value,
            "confidence": confidence,
            "attackPrerequisites": prerequisites,
            "observedAttackPaths": attack_paths,
            "mitigatingControls": mitigations,
            "missingEvidence": missing,
        }]
        limitations = [
            "No spoofing, authentication challenge, credential capture, "
            "or packet retention was performed."
        ]
        if status == ResponderExposureStatus.EXPOSURE_NOT_OBSERVED:
            limitations.append(
                "No Responder-style exposure was observed in the tested "
                "conditions. This does not prove that every possible "
                "name-resolution or authentication path is unavailable in "
                "all network environments."
            )
        return self.result(
            context,
            active_status,
            started_at,
            started_clock,
            evidence=evidence,
            limitations=limitations,
        )


def _evidence_value(result: dict[str, Any] | None, key: str) -> Any:
    """Return the first matching minimized evidence value."""

    if not result:
        return None
    for item in result.get("evidence", []):
        if isinstance(item, dict) and key in item:
            return item[key]
    return None


def _passive_true(data: dict[str, Any], setting_id: str) -> bool:
    """Read one canonical passive setting without inferring from names."""

    for setting in data.get("security", {}).get("settings", []):
        if setting.get("settingId") == setting_id:
            return setting.get("effectiveValue") is True
    return False
