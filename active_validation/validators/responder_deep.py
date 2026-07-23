"""Controlled, credential-safe Responder authentication-path validation."""

from __future__ import annotations

from dataclasses import asdict

from active_validation.deep_protocol import (
    build_run_marker,
    build_transport_marker,
    scoped_transport_signal,
)
from active_validation.digest import sha256_digest
from active_validation.enums import ActiveValidationStatus, RiskLevel
from active_validation.models import (
    ApplicabilityResult,
    CredentialFlowObservation,
    RollbackResult,
    ValidationContext,
    ValidationPlan,
    ValidatorDefinition,
)
from active_validation.validators.base import BaseActiveValidator, utc_start
from active_validation.live_transport import (
    LiveTransportError,
    rollback_live_transport,
    run_live_transport,
)


class ResponderDeepValidator(BaseActiveValidator):
    """Evaluate an exact-scope one-shot Responder protocol observation."""

    definition = ValidatorDefinition(
        validator_id="VAL-RESPONDER-DEEP-001",
        version="1.0.0",
        title="Controlled Responder Authentication Exposure Validation",
        description="Confirms an authorized authentication path without retention.",
        supported_rule_ids=("PROTO-002", "PROTO-003", "PROTO-004", "PROTO-006"),
        supported_platforms=("windows",),
        required_privileges=("LOCAL_ADMIN",),
        risk_level=RiskLevel.CONTROLLED_TEMPORARY_CHANGE,
        network_impact="SCOPED_LISTENER",
        system_change_impact="TEMPORARY_FIREWALL_AND_LISTENER",
        requires_rollback=True,
        default_timeout_seconds=30,
        maximum_timeout_seconds=60,
        required_capabilities=(
            "SCOPED_NAME_RESPONSE",
            "SCOPED_AUTHENTICATION_CHALLENGE",
        ),
        evidence_produced=("CREDENTIAL_FLOW_OBSERVATION", "ATTACK_PATH_SUMMARY"),
        safety_constraints=(
            "EXACT_MARKER_ONLY",
            "ONE_SHOT",
            "NO_CREDENTIAL_RETENTION",
            "NO_RELAY",
            "NO_CRACKING",
        ),
        domain="RESPONDER_EXPOSURE",
        required_evidence_types=("AUTHORIZED_SCOPE",),
        produced_evidence_types=(
            "CREDENTIAL_FLOW_OBSERVATION",
            "ATTACK_PATH_SUMMARY",
        ),
        execution_order=800,
    )

    def check_applicability(self, context: ValidationContext) -> ApplicabilityResult:
        """Require the exact deep profile, policy, authorization, and identity."""

        base = super().check_applicability(context)
        if not base.applicable:
            return base
        if context.profile != "deep-responder-validation":
            return _blocked(
                ActiveValidationStatus.BLOCKED_BY_SAFETY_POLICY,
                "Deep Responder profile was not selected",
            )
        required_policy = {
            "allowDeepResponderValidation": True,
            "allowNameResolutionResponses": True,
            "allowAuthenticationChallenges": True,
            "allowTemporaryNetworkListeners": True,
            "allowTemporaryFirewallChanges": True,
            "allowSyntheticCredentialFlow": True,
            "allowRealCredentialObservation": False,
            "allowCredentialMaterialRetention": False,
            "allowCredentialRelay": False,
            "allowHashCracking": False,
            "allowExternalTargets": False,
        }
        if any(
            context.policy.get(key) is not value
            for key, value in required_policy.items()
        ):
            return _blocked(
                ActiveValidationStatus.BLOCKED_BY_SAFETY_POLICY,
                "Deep Responder policy gate is incomplete",
            )
        required_permissions = {
            "nameResolutionSpoofing": True,
            "authenticationChallenge": True,
            "temporaryListener": True,
            "temporaryFirewallChange": True,
            "credentialMaterialRetention": False,
            "credentialRelay": False,
            "hashCracking": False,
        }
        if any(
            context.authorization_permissions.get(key) is not value
            for key, value in required_permissions.items()
        ):
            return _blocked(
                ActiveValidationStatus.BLOCKED_BY_AUTHORIZATION,
                "Deep Responder permissions are incomplete",
            )
        scope = context.authorization_scope
        if any(not scope.get(key) for key in (
            "networkInterfaces",
            "allowedSourceAddresses",
            "allowedTargetAddresses",
            "allowedProtocols",
        )):
            return _blocked(
                ActiveValidationStatus.BLOCKED_BY_AUTHORIZATION,
                "Deep Responder network scope is incomplete",
            )
        identity = context.test_identity or {}
        if (
            identity.get("mode") not in {
                "DEDICATED_TEST_ACCOUNT",
                "SYNTHETIC_LOCAL_ACCOUNT",
                "EXPLICIT_CURRENT_USER_TEST",
                "MACHINE_ACCOUNT_OBSERVATION",
            }
            or identity.get("authorizedForAuthenticationTest") is not True
        ):
            return _blocked(
                ActiveValidationStatus.BLOCKED_BY_AUTHORIZATION,
                "Authorized test identity is unavailable",
            )
        return base

    def execute(
        self,
        context: ValidationContext,
        plan: ValidationPlan,
    ):
        """Classify a protocol-parser-backed, exact-scope transport observation."""

        started_at, started_clock = utc_start()
        marker = (
            build_transport_marker(
                context.run_id,
                str(context.live_transport_config["nameResolutionProtocol"]),
            )
            if context.live_transport_config is not None
            else build_run_marker(context.run_id)
        )
        if (
            context.live_transport_config is not None
            and context.transport_observation is not None
        ):
            return self.result(
                context,
                ActiveValidationStatus.BLOCKED_BY_SAFETY_POLICY,
                started_at,
                started_clock,
                evidence=[_empty_evidence(marker, "LIVE_CONFIGURATION_CONFLICT")],
                limitations=["Live and test-double transports cannot be combined."],
            )
        observation = context.transport_observation
        if context.live_transport_config is not None:
            try:
                observation = run_live_transport(context, plan)
            except LiveTransportError:
                return self.result(
                    context,
                    ActiveValidationStatus.INCONCLUSIVE,
                    started_at,
                    started_clock,
                    evidence=[_empty_evidence(marker, "LIVE_TRANSPORT_FAILED")],
                    limitations=["The trusted live transport harness failed safely."],
                )
        if observation is None:
            return self.result(
                context,
                ActiveValidationStatus.INCONCLUSIVE,
                started_at,
                started_clock,
                evidence=[_empty_evidence(marker, "NO_TRANSPORT")],
                limitations=[
                    "No self-hosted or controlled protocol transport observation "
                    "was supplied."
                ],
            )
        if (
            observation.get("runId") != context.run_id
            or observation.get("planDigest") != context.plan_digest
            or observation.get("authorizationDigest")
            != context.authorization_digest
        ):
            return self.result(
                context,
                ActiveValidationStatus.INCONCLUSIVE,
                started_at,
                started_clock,
                evidence=[_empty_evidence(marker, "DIGEST_BINDING_MISMATCH")],
                limitations=[
                    "Transport observation did not match the reviewed run."
                ],
            )
        if any(
            observation.get(key, False) is not False
            for key in (
                "credentialMaterialRetained",
                "credentialMaterialWrittenToDisk",
                "credentialMaterialIncludedInReport",
                "relayAttempted",
                "crackingAttempted",
            )
        ):
            return self.result(
                context,
                ActiveValidationStatus.INCONCLUSIVE,
                started_at,
                started_clock,
                evidence=[_empty_evidence(marker, "CREDENTIAL_SAFETY_MISMATCH")],
                limitations=[
                    "Transport observation violated the credential-safety contract."
                ],
            )
        signal = scoped_transport_signal(
            observation,
            marker,
            context.authorization_scope,
        )
        if signal is None:
            return self.result(
                context,
                ActiveValidationStatus.INCONCLUSIVE,
                started_at,
                started_clock,
                evidence=[_empty_evidence(marker, "SCOPE_MISMATCH")],
                limitations=["Transport event did not match the authorized scope."],
            )
        flow = CredentialFlowObservation(
            flow_observed=signal.authentication_attempt_observed,
            protocol=signal.protocol,
            authentication_family=(
                "NTLM" if signal.authentication_attempt_observed else None
            ),
            test_identity_matched=signal.test_identity_matched,
            identity_hash=(
                (context.test_identity or {}).get("identityHash")
                if signal.test_identity_matched
                else None
            ),
            message_types_observed=signal.message_types_observed,
        )
        complete_chain = (
            signal.marker_query_observed
            and signal.response_sent
            and signal.listener_operational
            and signal.connection_observed
        )
        if (
            complete_chain
            and signal.authentication_attempt_observed
            and signal.test_identity_matched
            and signal.protocol_parser_verified
            and {"NEGOTIATE", "CHALLENGE", "AUTHENTICATE"} <= set(
                signal.message_types_observed
            )
        ):
            exposure, status, confidence = (
                "EXPOSURE_CONFIRMED",
                ActiveValidationStatus.FAILED,
                98,
            )
        elif complete_chain and signal.authentication_attempt_observed and (
            signal.ntlm_outbound_blocked or signal.client_signing_required
        ):
            exposure, status, confidence = (
                "EXPOSURE_PARTIALLY_MITIGATED",
                ActiveValidationStatus.INCONCLUSIVE,
                85,
            )
        elif complete_chain and signal.connection_observed:
            exposure, status, confidence = (
                "EXPOSURE_LIKELY",
                ActiveValidationStatus.FAILED,
                75,
            )
        elif (
            signal.marker_query_observed
            and signal.response_sent
            and signal.listener_operational
            and signal.sufficient_observation_window
        ):
            exposure, status, confidence = (
                "EXPOSURE_NOT_OBSERVED",
                ActiveValidationStatus.PASSED,
                90,
            )
        else:
            exposure, status, confidence = (
                "INCONCLUSIVE",
                ActiveValidationStatus.INCONCLUSIVE,
                40,
            )
        evidence = {
            "evidenceType": "RESPONDER_DEEP_VALIDATION",
            "assessmentDepth": "DEEP_VALIDATION",
            "exposureStatus": exposure,
            "confidence": confidence,
            "runMarkerHash": f"sha256:{sha256_digest(marker)}",
            "nameResolutionResponseSent": signal.response_sent,
            "authenticationChallengeIssued":
                signal.authentication_challenge_issued,
            "authorizedTestIdentityUsed": True,
            "authenticationAttemptObserved":
                signal.authentication_attempt_observed,
            "protocol": signal.protocol,
            "nameResolutionProtocol": observation.get(
                "nameResolutionProtocol"
            ),
            "transportMode": (
                "SELF_HOSTED_WINDOWS_HARNESS"
                if context.live_transport_config is not None
                else "CONTROLLED_TRANSPORT_TEST_DOUBLE"
            ),
            "networkConfirmation": context.live_transport_config is not None,
            "protocolParserVerified": signal.protocol_parser_verified,
            "flow": asdict(flow),
            "credentialMaterialRetained": False,
            "relayAttempted": False,
            "crackingAttempted": False,
            "scopeMismatchCount": 0,
            "firewallRuleCreated": observation.get(
                "firewallRuleCreated", False
            ),
            "firewallRuleRemoved": observation.get(
                "firewallRuleRemoved", False
            ),
        }
        limitations = []
        if exposure == "EXPOSURE_NOT_OBSERVED":
            limitations.append(
                "No exposure was observed under the tested interface, protocol, "
                "policy, identity and network conditions."
            )
        return self.result(
            context,
            status,
            started_at,
            started_clock,
            evidence=[evidence],
            limitations=limitations,
        )

    def rollback(
        self,
        context: ValidationContext,
        plan: ValidationPlan,
    ) -> RollbackResult:
        """Report cleanup supplied by the isolated one-shot transport."""

        if context.live_transport_config is not None:
            return rollback_live_transport(context)
        completed = (
            context.transport_observation is None
            or context.transport_observation.get("cleanupCompleted", True) is True
        )
        return RollbackResult(
            required=True,
            completed=completed,
            manual_cleanup_required=not completed,
            remaining_objects=(
                []
                if completed
                else [{
                    "objectType": "scoped_listener",
                    "redactedName": f"CSA-VALIDATION-{context.run_id}",
                }]
            ),
            error_code=None if completed else "DEEP_TRANSPORT_CLEANUP_FAILED",
        )


def _blocked(status: ActiveValidationStatus, reason: str) -> ApplicabilityResult:
    """Build one blocked applicability result."""

    return ApplicabilityResult(applicable=False, status=status, reason=reason)


def _empty_evidence(marker: str, reason: str) -> dict[str, object]:
    """Return a credential-free incomplete observation."""

    return {
        "evidenceType": "RESPONDER_DEEP_VALIDATION",
        "assessmentDepth": "DEEP_VALIDATION",
        "exposureStatus": "INCONCLUSIVE",
        "transportMode": "NOT_COMPLETED",
        "networkConfirmation": False,
        "incompleteReason": reason,
        "runMarkerHash": f"sha256:{sha256_digest(marker)}",
        "nameResolutionResponseSent": False,
        "authenticationChallengeIssued": False,
        "authorizedTestIdentityUsed": False,
        "authenticationAttemptObserved": False,
        "credentialMaterialRetained": False,
        "relayAttempted": False,
        "crackingAttempted": False,
        "scopeMismatchCount": 1 if reason == "SCOPE_MISMATCH" else 0,
    }
