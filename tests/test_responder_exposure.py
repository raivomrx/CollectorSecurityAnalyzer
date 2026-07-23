"""Tests for credential-safe Responder exposure correlation."""

from __future__ import annotations

import unittest

from active_validation.enums import (
    ActiveValidationStatus,
    ResponderExposureStatus,
    ResponderRiskLevel,
    RiskLevel,
)
from active_validation.models import ValidationContext, ValidationPlan
from active_validation.validators.responder import (
    ResponderExposureValidator,
    SmbSigningExposureValidator,
    WpadExposureValidator,
)


class ResponderExposureTests(unittest.TestCase):
    """Verify conservative attack-path decisions without network activity."""

    def test_high_risk_requires_complete_unmitigated_path(self) -> None:
        """Observed query, permitted auth, outbound path, and weak signing is high."""

        result = self._evaluate([
            self._result("VAL-LLMNR-OBSERVE-001", "FAILED"),
            self._result(
                "VAL-NTLM-POLICY-001",
                "INCONCLUSIVE",
                policyState="PERMITTED",
                effectivePolicyConfirmed=True,
            ),
            self._result("VAL-OUTBOUND-SMB-PATH-001", "PASSED", pathReachable=True),
            self._result(
                "VAL-SMB-SIGNING-EXPOSURE-001",
                "FAILED",
                clientRequired=False,
                serverRequired=False,
            ),
        ])
        evidence = result.evidence[0]
        self.assertEqual(ActiveValidationStatus.FAILED, result.status)
        self.assertEqual(
            ResponderExposureStatus.EXPOSURE_CONFIRMED.value,
            evidence["exposureStatus"],
        )
        self.assertEqual(ResponderRiskLevel.HIGH.value, evidence["riskLevel"])

    def test_observed_query_and_permitted_auth_is_medium(self) -> None:
        """Missing path evidence should prevent a high classification."""

        result = self._evaluate([
            self._result("VAL-NBTNS-OBSERVE-001", "FAILED"),
            self._result(
                "VAL-NTLM-POLICY-001",
                "INCONCLUSIVE",
                policyState="PERMITTED",
                effectivePolicyConfirmed=True,
            ),
        ])
        self.assertEqual("MEDIUM", result.evidence[0]["riskLevel"])

    def test_configuration_only_path_is_likely_not_confirmed(self) -> None:
        """Passive fallback configuration cannot claim runtime observation."""

        result = self._evaluate(
            [
                self._result(
                    "VAL-NTLM-POLICY-001",
                    "INCONCLUSIVE",
                    policyState="PERMITTED",
                    effectivePolicyConfirmed=True,
                ),
                self._result(
                    "VAL-SMB-SIGNING-EXPOSURE-001",
                    "FAILED",
                    clientRequired=False,
                    serverRequired=False,
                ),
            ],
            llmnr_enabled=True,
        )
        self.assertEqual("EXPOSURE_LIKELY", result.evidence[0]["exposureStatus"])
        self.assertEqual(
            "CONFIGURATION_ONLY",
            result.evidence[0]["observedAttackPaths"][0]["observation"],
        )

    def test_effective_restriction_and_signing_partially_mitigate(
        self,
    ) -> None:
        """Observed fallback with effective controls should be low and partial."""

        result = self._evaluate([
            self._result("VAL-LLMNR-OBSERVE-001", "FAILED"),
            self._result(
                "VAL-NTLM-POLICY-001",
                "PASSED",
                policyState="DENIED_EFFECTIVE",
                effectivePolicyConfirmed=True,
            ),
            self._result(
                "VAL-SMB-SIGNING-EXPOSURE-001",
                "PASSED",
                clientRequired=True,
                serverRequired=True,
            ),
        ])
        self.assertEqual(
            "EXPOSURE_PARTIALLY_MITIGATED",
            result.evidence[0]["exposureStatus"],
        )
        self.assertEqual("LOW", result.evidence[0]["riskLevel"])

    def test_no_observation_with_effective_controls_is_not_observed(self) -> None:
        """No observed fallback plus effective controls supports a safe result."""

        result = self._evaluate([
            self._result("VAL-LLMNR-OBSERVE-001", "PASSED"),
            self._result("VAL-NBTNS-OBSERVE-001", "PASSED"),
            self._result(
                "VAL-NTLM-POLICY-001",
                "PASSED",
                policyState="DENIED_EFFECTIVE",
                effectivePolicyConfirmed=True,
            ),
            self._result(
                "VAL-SMB-SIGNING-EXPOSURE-001",
                "PASSED",
                clientRequired=True,
                serverRequired=True,
            ),
        ])
        self.assertEqual(ActiveValidationStatus.PASSED, result.status)
        self.assertEqual("EXPOSURE_NOT_OBSERVED", result.evidence[0]["exposureStatus"])
        self.assertEqual("LOW", result.evidence[0]["riskLevel"])

    def test_local_policy_uncertainty_cannot_confirm_exposure(self) -> None:
        """A local-only authentication setting is not effective-policy proof."""

        result = self._evaluate([
            self._result("VAL-LLMNR-OBSERVE-001", "FAILED"),
            self._result(
                "VAL-NTLM-POLICY-001",
                "INCONCLUSIVE",
                policyState="LEGACY_ALLOWED",
                effectivePolicyConfirmed=False,
            ),
            self._result(
                "VAL-SMB-SIGNING-EXPOSURE-001",
                "FAILED",
                clientRequired=False,
                serverRequired=False,
            ),
        ])
        self.assertEqual(ActiveValidationStatus.INCONCLUSIVE, result.status)
        self.assertEqual("INCONCLUSIVE", result.evidence[0]["exposureStatus"])

    def test_policy_validators_preserve_unknown_and_explicit_states(self) -> None:
        """Missing values remain inconclusive while explicit exposure fails."""

        context = self._context([])
        wpad = WpadExposureValidator()
        signing = SmbSigningExposureValidator()
        wpad_unknown = wpad.interpret(context, "start", 0.0, {"disableWpad": None})
        wpad_enabled = wpad.interpret(context, "start", 0.0, {"disableWpad": 0})
        signing_unknown = signing.interpret(
            context,
            "start",
            0.0,
            {"clientRequired": None, "serverRequired": None},
        )
        self.assertEqual(ActiveValidationStatus.INCONCLUSIVE, wpad_unknown.status)
        self.assertEqual(ActiveValidationStatus.FAILED, wpad_enabled.status)
        self.assertEqual(ActiveValidationStatus.INCONCLUSIVE, signing_unknown.status)

    def test_missing_evidence_is_inconclusive(self) -> None:
        """Unknown attack-path conditions must not become affected or safe."""

        result = self._evaluate([])
        self.assertEqual(ActiveValidationStatus.INCONCLUSIVE, result.status)
        self.assertEqual("INCONCLUSIVE", result.evidence[0]["exposureStatus"])
        self.assertGreater(len(result.evidence[0]["missingEvidence"]), 0)

    def test_aggregate_contains_no_credential_material(self) -> None:
        """Aggregate evidence should contain decisions, never captured material."""

        result = self._evaluate([])
        serialized = str(result.evidence).casefold()
        for forbidden in ("password=", "hash=", "challenge=", "bearer "):
            self.assertNotIn(forbidden, serialized)

    def _evaluate(
        self,
        prior_results: list[dict[str, object]],
        llmnr_enabled: bool = False,
    ):
        """Run the pure correlation validator in-process for decision tests."""

        validator = ResponderExposureValidator()
        context = self._context(prior_results, llmnr_enabled)
        plan = ValidationPlan(
            "run",
            validator.definition.validator_id,
            "1.0.0",
            5,
            RiskLevel.SAFE_READ_ONLY,
            False,
            "CSA-VALIDATION-run",
            1,
        )
        return validator.execute(context, plan)

    @staticmethod
    def _context(
        prior_results: list[dict[str, object]],
        llmnr_enabled: bool = False,
    ) -> ValidationContext:
        """Build a minimized context for pure validator decisions."""

        return ValidationContext(
            schema_version="1.0",
            run_id="run",
            validator_id="VAL-RESPONDER-EXPOSURE-001",
            timeout_seconds=5,
            temporary_directory="",
            host_identifier_hash="host",
            authorization_digest="authorization",
            policy_digest="policy",
            platform="windows",
            observed_privileges=(),
            passive_data={
                "security": {
                    "settings": [{
                        "settingId": "LLMNR_ENABLED",
                        "effectiveValue": llmnr_enabled,
                    }]
                }
            },
            passive_results={},
            prior_results=prior_results,
            policy={},
        )

    @staticmethod
    def _result(
        validator_id: str,
        status: str,
        **evidence: object,
    ) -> dict[str, object]:
        """Build a minimized prior-result fixture."""

        return {
            "validatorId": validator_id,
            "status": status,
            "evidence": [evidence] if evidence else [],
        }
