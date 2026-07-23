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
    """Resolve bounded WPAD policy evidence without starting a rogue service."""

    definition = ValidatorDefinition(
        validator_id="VAL-WPAD-EXPOSURE-001",
        version="1.0.0",
        title="WPAD policy exposure",
        description="Correlates machine, collected user, service, and policy evidence.",
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
        evidence_produced=("WPAD_POLICY_STATE", "PROVENANCE"),
        safety_constraints=("NO_ROGUE_SERVER", "NO_NAME_RESOLUTION"),
        domain="RESPONDER_EXPOSURE",
        produced_evidence_types=("WPAD_POLICY_STATE",),
        execution_order=300,
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
        settings = _settings_by_id(context.passive_data)
        auto_detect = _setting_value(settings, "WININET_AUTODETECT")
        auto_config_url = _setting_value(settings, "WININET_AUTOCONFIG_URL")
        web_client = _setting_value(settings, "WEBCLIENT_SERVICE_STATE")
        win_http = _setting_value(settings, "WINHTTP_PROXY_CONFIGURATION")
        policy_sources = [
            item for item in (
                "LOCAL_MACHINE_DISABLE_FLAG"
                if observations["disableWpad"] is not None else None,
                "WININET_USER_POLICY" if auto_detect is not None else None,
                "AUTOCONFIG_POLICY" if auto_config_url is not None else None,
                "WINHTTP_CONFIGURATION" if win_http is not None else None,
                "WEBCLIENT_SERVICE" if web_client is not None else None,
            )
            if item
        ]
        known = bool(policy_sources)
        exposed = (
            not disabled
            and (
                auto_detect is True
                or bool(auto_config_url)
                or str(web_client).casefold() in {"running", "enabled", "automatic"}
            )
        )
        if not known:
            status = ActiveValidationStatus.INCONCLUSIVE
        elif disabled:
            status = ActiveValidationStatus.PASSED
        elif exposed or observations["disableWpad"] == 0:
            status = ActiveValidationStatus.FAILED
        else:
            status = ActiveValidationStatus.INCONCLUSIVE
        return self.result(
            context,
            status,
            started_at,
            started_clock,
            evidence=[{
                "evidenceType": "WPAD_POLICY",
                "explicitlyDisabled": disabled,
                "machinePolicyKnown": known,
                "autoDetectEnabled": auto_detect is True,
                "autoConfigUrlConfigured": bool(auto_config_url),
                "webClientEnabled": str(web_client).casefold() in {
                    "running", "enabled", "automatic"
                },
                "winHttpConfigurationKnown": win_http is not None,
                "policySources": policy_sources,
                "precedenceConfirmed": any(
                    item in {"WININET_USER_POLICY", "AUTOCONFIG_POLICY"}
                    for item in policy_sources
                ),
                "provenance": "CANONICAL_WPAD_RESOLVER",
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
        produced_evidence_types=("AUTHENTICATION_POLICY",),
        execution_order=100,
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
        settings = _settings_by_id(context.passive_data)
        source_candidates = (
            ("NTLM_MDM_POLICY", "MDM_POLICY"),
            ("NTLM_DOMAIN_POLICY", "DOMAIN_POLICY"),
            ("NTLM_OUTGOING_POLICY", "GROUP_POLICY_RESULT"),
            ("NTLM_INCOMING_POLICY", "GROUP_POLICY_RESULT"),
            ("NTLM_AUDIT_POLICY", "AUDIT_POLICY"),
        )
        sources = []
        effective_value = None
        for setting_id, source_class in source_candidates:
            if setting_id in settings:
                sources.append({
                    "sourceClass": source_class,
                    "settingId": setting_id,
                })
                if effective_value is None:
                    effective_value = settings[setting_id].get("effectiveValue")
        if isinstance(value, int):
            sources.append({
                "sourceClass": "REGISTRY_FALLBACK",
                "settingId": "LM_COMPATIBILITY_LEVEL",
            })
        effective_confirmed = any(
            item["sourceClass"] in {
                "MDM_POLICY",
                "DOMAIN_POLICY",
                "GROUP_POLICY_RESULT",
            }
            for item in sources
        )
        state = "UNKNOWN"
        normalized = str(effective_value).casefold()
        if effective_confirmed:
            if effective_value in {0, False} or normalized in {
                "deny", "denied", "blocked", "disabled"
            }:
                state = "DENIED"
            elif normalized in {"audit", "audit_only"}:
                state = "AUDIT_ONLY"
            elif normalized in {"exceptions", "restricted_with_exceptions"}:
                state = "RESTRICTED_WITH_EXCEPTIONS"
            else:
                state = "PERMITTED"
        return self.result(
            context,
            (
                ActiveValidationStatus.PASSED
                if effective_confirmed and state == "DENIED"
                else ActiveValidationStatus.INCONCLUSIVE
            ),
            started_at,
            started_clock,
            evidence=[{
                "evidenceType": "AUTHENTICATION_POLICY",
                "state": state,
                "policyState": state,
                "numericLevel": value if isinstance(value, int) else None,
                "sources": sources,
                "precedence": [
                    "MDM_POLICY",
                    "DOMAIN_POLICY",
                    "GROUP_POLICY_RESULT",
                    "LOCAL_POLICY",
                    "REGISTRY_FALLBACK",
                ],
                "provenance": "CANONICAL_NTLM_POLICY_RESOLVER",
                "effectivePolicyConfirmed": effective_confirmed,
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
        produced_evidence_types=("SMB_SIGNING_POLICY",),
        execution_order=200,
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
                "outboundClientSigningRequired": client,
                "inboundServerSigningRequired": server,
                "outboundRelayMitigated": client,
                "inboundRelayMitigated": server,
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
        depends_on_validator_ids=(
            "VAL-NTLM-POLICY-001",
            "VAL-SMB-SIGNING-EXPOSURE-001",
            "VAL-WPAD-EXPOSURE-001",
        ),
        optional_dependency_ids=(
            "VAL-LLMNR-OBSERVE-001",
            "VAL-NBTNS-OBSERVE-001",
            "VAL-OUTBOUND-SMB-PATH-001",
            "VAL-RESPONDER-DEEP-001",
        ),
        required_evidence_types=(
            "AUTHENTICATION_POLICY",
            "SMB_SIGNING_POLICY",
            "WPAD_POLICY_STATE",
        ),
        produced_evidence_types=("ATTACK_PATH_SUMMARY", "CONFIDENCE"),
        execution_order=1000,
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
        deep_exposure = _evidence_value(
            indexed.get("VAL-RESPONDER-DEEP-001"),
            "exposureStatus",
        )
        deep_protocol = _evidence_value(
            indexed.get("VAL-RESPONDER-DEEP-001"),
            "protocol",
        )
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
            "DENIED",
            "DENIED_EFFECTIVE",
            "RESTRICTED_EFFECTIVE",
        }
        wpad_disabled = _evidence_value(
            indexed.get("VAL-WPAD-EXPOSURE-001"),
            "explicitlyDisabled",
        )
        wpad_known = (
            _evidence_value(
                indexed.get("VAL-WPAD-EXPOSURE-001"),
                "machinePolicyKnown",
            )
            is True
        )
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
        outbound_relay_mitigated = client_signing
        inbound_relay_mitigated = server_signing
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
        if deep_exposure == "EXPOSURE_CONFIRMED":
            status, risk, active_status, confidence = (
                ResponderExposureStatus.EXPOSURE_CONFIRMED,
                (
                    ResponderRiskLevel.MEDIUM
                    if outbound_relay_mitigated
                    else ResponderRiskLevel.HIGH
                ),
                ActiveValidationStatus.FAILED,
                98,
            )
        elif deep_exposure == "EXPOSURE_LIKELY":
            status, risk, active_status, confidence = (
                ResponderExposureStatus.EXPOSURE_LIKELY,
                ResponderRiskLevel.MEDIUM,
                ActiveValidationStatus.FAILED,
                80,
            )
        elif deep_exposure == "EXPOSURE_PARTIALLY_MITIGATED":
            status, risk, active_status, confidence = (
                ResponderExposureStatus.EXPOSURE_PARTIALLY_MITIGATED,
                ResponderRiskLevel.LOW,
                ActiveValidationStatus.INCONCLUSIVE,
                88,
            )
        elif deep_exposure == "EXPOSURE_NOT_OBSERVED":
            status, risk, active_status, confidence = (
                ResponderExposureStatus.EXPOSURE_NOT_OBSERVED,
                ResponderRiskLevel.LOW,
                ActiveValidationStatus.PASSED,
                92,
            )
        elif (
            legacy_observed
            and auth_permitted
            and path_available
            and signing_known
            and not outbound_relay_mitigated
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
            and not outbound_relay_mitigated
        ):
            status, risk, active_status, confidence = (
                ResponderExposureStatus.EXPOSURE_LIKELY,
                ResponderRiskLevel.MEDIUM,
                ActiveValidationStatus.FAILED,
                70,
            )
        elif legacy_observed and auth_denied and outbound_relay_mitigated:
            status, risk, active_status, confidence = (
                ResponderExposureStatus.EXPOSURE_PARTIALLY_MITIGATED,
                ResponderRiskLevel.LOW,
                ActiveValidationStatus.INCONCLUSIVE,
                80,
            )
        elif legacy_not_observed and auth_denied and outbound_relay_mitigated:
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
        if outbound_relay_mitigated:
            mitigations.append("Outbound SMB relay mitigated by client signing")
        if inbound_relay_mitigated:
            mitigations.append("Local SMB relay mitigated by server signing")
        missing = [
            label
            for validator_id, label in (
                ("VAL-LLMNR-OBSERVE-001", "LLMNR observation"),
                ("VAL-NBTNS-OBSERVE-001", "NBT-NS observation"),
                ("VAL-NTLM-POLICY-001", "effective authentication policy"),
                ("VAL-SMB-SIGNING-EXPOSURE-001", "SMB signing policy"),
                ("VAL-OUTBOUND-SMB-PATH-001", "outbound service path"),
                ("VAL-WPAD-EXPOSURE-001", "WPAD policy"),
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
                or (
                    validator_id == "VAL-WPAD-EXPOSURE-001"
                    and not wpad_known
                )
            )
        ]
        attack_paths = []
        if legacy_observed or config_likely:
            attack_paths.append({
                "path": "LEGACY_NAME_RESOLUTION_TO_INTEGRATED_AUTH",
                "observation": "CONFIRMED" if legacy_observed else "CONFIGURATION_ONLY",
                "mitigation": (
                    "OUTBOUND_CLIENT_SIGNING_REQUIRED"
                    if outbound_relay_mitigated
                    else "NOT_CONFIRMED"
                ),
            })
        if deep_exposure:
            authentication_path = (
                "RESPONDER_NAME_RESOLUTION_TO_HTTP_NTLM_AUTH"
                if deep_protocol == "HTTP"
                else "RESPONDER_NAME_RESOLUTION_TO_OUTBOUND_SMB_AUTH"
            )
            attack_paths.extend([
                {
                    "path": authentication_path,
                    "observation": deep_exposure,
                    "mitigation": (
                        "CLIENT_SIGNING_REQUIRED"
                        if outbound_relay_mitigated else "NOT_CONFIRMED"
                    ),
                },
                {
                    "path": "RELAY_TO_REMOTE_SMB_SERVICE",
                    "observation": "NOT_ATTEMPTED",
                    "mitigation": (
                        "CLIENT_SIGNING_REQUIRED"
                        if outbound_relay_mitigated else "NOT_CONFIRMED"
                    ),
                },
                {
                    "path": "RELAY_TO_LOCAL_SMB_SERVER",
                    "observation": "NOT_ATTEMPTED",
                    "mitigation": (
                        "SERVER_SIGNING_REQUIRED"
                        if inbound_relay_mitigated else "NOT_CONFIRMED"
                    ),
                },
            ])
        if wpad_known and not wpad_disabled:
            attack_paths.append({
                "path": "WPAD_TO_HTTP_NTLM_AUTH",
                "observation": "POLICY_PATH_PRESENT",
                "mitigation": (
                    "NTLM_EFFECTIVELY_DENIED"
                    if auth_denied else "NOT_CONFIRMED"
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


def _settings_by_id(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Index canonical collector settings by ID."""

    settings = data.get("security", {}).get("settings", [])
    return {
        str(item.get("settingId")): item
        for item in settings
        if isinstance(item, dict) and item.get("settingId")
    }


def _setting_value(
    settings: dict[str, dict[str, Any]],
    setting_id: str,
) -> Any:
    """Return one canonical setting's effective value."""

    item = settings.get(setting_id)
    return item.get("effectiveValue") if item else None
