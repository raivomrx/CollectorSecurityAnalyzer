"""Deep Responder safety, protocol, planning, and production-flow tests."""

from __future__ import annotations

import json
import struct
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from active_validation.authorization import AuthorizationError, load_authorization
from active_validation.deep_protocol import (
    build_llmnr_response,
    build_nbtns_response,
    build_run_marker,
    build_transport_marker,
    build_ephemeral_ntlm_challenge,
    parse_ntlm_message_type,
    scoped_transport_signal,
)
from active_validation.engine import execute_active_validation
from active_validation.enums import ResponderExposureStatus, RiskLevel
from active_validation.evidence import SensitiveEvidenceError, validate_output_text
from active_validation.planner import (
    PlanningError,
    ValidationPlanner,
    plan_digest,
)
from active_validation.policy import DEFAULT_POLICY, load_policy
from active_validation.registry import ValidatorRegistry
from active_validation.models import ValidatorDefinition
from active_validation.validators.base import BaseActiveValidator
from report import generate_html_report
from software.inventory import build_inventory


def _definition(
    validator_id: str,
    risk: RiskLevel = RiskLevel.SAFE_READ_ONLY,
    dependencies: tuple[str, ...] = (),
) -> ValidatorDefinition:
    """Build metadata used only for planner contract fixtures."""

    return ValidatorDefinition(
        validator_id=validator_id,
        version="1.0.0",
        title=validator_id,
        description="Planner contract fixture.",
        supported_rule_ids=(),
        supported_platforms=("windows",),
        required_privileges=("STANDARD_USER",),
        risk_level=risk,
        network_impact="NONE",
        system_change_impact="NONE",
        requires_rollback=False,
        default_timeout_seconds=5,
        maximum_timeout_seconds=5,
        required_capabilities=(),
        evidence_produced=(),
        safety_constraints=(),
        depends_on_validator_ids=dependencies,
    )


class CycleAValidator(BaseActiveValidator):
    """First cycle fixture."""

    definition = _definition("VAL-CYCLE-A-001", dependencies=("VAL-CYCLE-B-001",))


class CycleBValidator(BaseActiveValidator):
    """Second cycle fixture."""

    definition = _definition("VAL-CYCLE-B-001", dependencies=("VAL-CYCLE-A-001",))


class UnknownDependencyValidator(BaseActiveValidator):
    """Unknown dependency fixture."""

    definition = _definition(
        "VAL-UNKNOWN-DEP-001",
        dependencies=("VAL-MISSING-001",),
    )


class DisabledParentValidator(BaseActiveValidator):
    """Disabled dependency parent fixture."""

    definition = _definition(
        "VAL-DISABLED-PARENT-001",
        dependencies=("VAL-DISABLED-CHILD-001",),
    )


class DisabledChildValidator(BaseActiveValidator):
    """Disabled dependency fixture."""

    definition = _definition("VAL-DISABLED-CHILD-001")


class RiskParentValidator(BaseActiveValidator):
    """Risk escalation parent fixture."""

    definition = _definition(
        "VAL-RISK-PARENT-001",
        dependencies=("VAL-RISK-CHILD-001",),
    )


class RiskChildValidator(BaseActiveValidator):
    """Higher-risk dependency fixture."""

    definition = _definition(
        "VAL-RISK-CHILD-001",
        risk=RiskLevel.CONTROLLED_TEMPORARY_CHANGE,
    )


class ResponderDeepTests(unittest.TestCase):
    """Exercise deep validation through the production execution boundary."""

    def setUp(self) -> None:
        """Create isolated policy, authorization, audit, and worker files."""

        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        """Remove isolated artifacts."""

        self.temporary.cleanup()

    def test_controlled_transport_does_not_claim_network_confirmation(self) -> None:
        """A test double may confirm parsing but not a live network finding."""

        run = self._execute(self._observation("confirmed"))
        self.assertEqual(
            ResponderExposureStatus.EXPOSURE_LIKELY,
            run.responder_exposure.status,
        )
        deep = next(
            item for item in run.results
            if item.validator_id == "VAL-RESPONDER-DEEP-001"
        )
        self.assertEqual("FAILED", deep.status.value)
        self.assertFalse(deep.evidence[0]["credentialMaterialRetained"])
        self.assertFalse(deep.evidence[0]["relayAttempted"])
        self.assertEqual("VERIFIED", run.audit_verification_status)
        self.assertEqual(64, len(run.final_audit_entry_hash or ""))

        report_path = generate_html_report(
            data={"ComputerName": "HOSTNAME-01", "OS": "Windows 11"},
            audit_findings=[],
            score=100,
            software_inventory=build_inventory(
                [],
                unknown_products_path=self.root / "unknown-products.json",
            ),
            rule_metadata={},
            cve_summary=None,
            active_validation=run,
            output_path=self.root / "deep-report.html",
        )
        html = report_path.read_text(encoding="utf-8")
        self.assertIn("DEEP_VALIDATION", html)
        self.assertIn("CONTROLLED_TRANSPORT_TEST_DOUBLE", html)
        self.assertIn("Live network confirmation</span><strong>False", html)
        self.assertIn("Authentication attempt observed", html)
        self.assertIn("Credential material retained", html)
        self.assertIn(run.final_audit_entry_hash, html)

    def test_likely_partial_and_not_observed_outcomes(self) -> None:
        """The deep classifier should preserve all required result semantics."""

        expected = {
            "likely": "EXPOSURE_LIKELY",
            "partial": "EXPOSURE_PARTIALLY_MITIGATED",
            "not_observed": "EXPOSURE_NOT_OBSERVED",
        }
        for mode, status in expected.items():
            with self.subTest(mode=mode):
                run = self._execute(self._observation(mode))
                self.assertEqual(status, run.responder_exposure.status.value)

    def test_deep_requires_exact_permissions(self) -> None:
        """Missing spoofing permission must block before a transport action."""

        authorization = self._authorization()
        data = json.loads(authorization.read_text(encoding="utf-8"))
        data["permissions"]["nameResolutionSpoofing"] = False
        authorization.write_text(json.dumps(data), encoding="utf-8")
        run = self._execute(
            self._observation("confirmed"),
            authorization_path=authorization,
        )
        deep = next(
            item for item in run.results
            if item.validator_id == "VAL-RESPONDER-DEEP-001"
        )
        self.assertEqual("BLOCKED_BY_AUTHORIZATION", deep.status.value)
        self.assertEqual([], deep.evidence)

    def test_deep_requires_every_policy_gate(self) -> None:
        """A missing deep policy flag must block without downgrading the test."""

        policy_path = self._policy()
        document = json.loads(policy_path.read_text(encoding="utf-8"))
        document["allowAuthenticationChallenges"] = False
        policy_path.write_text(json.dumps(document), encoding="utf-8")
        run = self._execute(
            self._observation("confirmed"),
            policy_path=policy_path,
        )
        deep = next(
            item for item in run.results
            if item.validator_id == "VAL-RESPONDER-DEEP-001"
        )
        self.assertEqual("BLOCKED_BY_SAFETY_POLICY", deep.status.value)
        self.assertEqual([], deep.evidence)

    def test_scope_mismatch_is_ignored(self) -> None:
        """Wrong marker, source, or interface must produce no response evidence."""

        observation = self._observation("confirmed")
        observation["sourceAddress"] = "192.0.2.99"
        run = self._execute(observation)
        deep = next(
            item for item in run.results
            if item.validator_id == "VAL-RESPONDER-DEEP-001"
        )
        self.assertEqual("INCONCLUSIVE", deep.status.value)
        self.assertFalse(deep.evidence[0]["nameResolutionResponseSent"])
        self.assertEqual(1, deep.evidence[0]["scopeMismatchCount"])

    def test_credential_safety_mismatch_fails_closed(self) -> None:
        """Unsafe transport claims must never become exposure evidence."""

        observation = self._observation("confirmed")
        observation["credentialMaterialRetained"] = True
        run = self._execute(observation)
        deep = next(
            item for item in run.results
            if item.validator_id == "VAL-RESPONDER-DEEP-001"
        )
        self.assertEqual("INCONCLUSIVE", deep.status.value)
        self.assertEqual(
            "CREDENTIAL_SAFETY_MISMATCH",
            deep.evidence[0]["incompleteReason"],
        )
        self.assertFalse(deep.evidence[0]["networkConfirmation"])

    def test_protocol_response_is_exact_marker_only(self) -> None:
        """LLMNR and NBT-NS codecs must ignore every other query name."""

        marker = build_run_marker("RUN-1")
        query = self._query(marker)
        self.assertIsNotNone(build_llmnr_response(query, marker, "192.0.2.10"))
        nbtns_marker = build_transport_marker("RUN-1", "NBT_NS")
        nbtns_query = self._nbtns_query(nbtns_marker)
        self.assertIsNotNone(
            build_nbtns_response(
                nbtns_query,
                nbtns_marker,
                "192.0.2.10",
            )
        )
        wrong = self._query("OTHER-NAME")
        self.assertIsNone(build_llmnr_response(wrong, marker, "192.0.2.10"))
        self.assertIsNone(
            build_nbtns_response(
                self._nbtns_query("WRONG-NAME"),
                nbtns_marker,
                "192.0.2.10",
            )
        )

    def test_ntlm_parser_returns_only_message_labels(self) -> None:
        """The production parser must reduce protocol bytes to safe labels."""

        negotiate = b"SMB" + b"NTLMSSP\x00" + struct.pack("<I", 1) + b"\x00" * 8
        challenge = build_ephemeral_ntlm_challenge("RUN-NTLM")
        authenticate = b"NTLMSSP\x00" + struct.pack("<I", 3) + b"\x00" * 32
        self.assertEqual("NEGOTIATE", parse_ntlm_message_type(negotiate))
        self.assertEqual("CHALLENGE", parse_ntlm_message_type(challenge))
        self.assertEqual("AUTHENTICATE", parse_ntlm_message_type(authenticate))

    def test_listener_scope_limits_are_enforced(self) -> None:
        """One-shot and bounded payload limits must reject broad transports."""

        observation = self._observation("confirmed")
        observation["queryMarker"] = build_run_marker("RUN-2")
        observation["connectionCount"] = 2
        with self.assertRaises(ValueError):
            scoped_transport_signal(
                observation,
                observation["queryMarker"],
                self._scope(),
            )
        observation["connectionCount"] = 1
        observation["listenerAddress"] = "0.0.0.0"
        self.assertIsNone(
            scoped_transport_signal(
                observation,
                observation["queryMarker"],
                self._scope(),
            )
        )

    def test_plan_dependencies_digest_and_order(self) -> None:
        """Planner must add dependencies and run the aggregate last."""

        policy = load_policy(self._policy())
        authorization = load_authorization(self._authorization())
        plans = ValidationPlanner(ValidatorRegistry()).plan(
            run_id="PLAN",
            requested_validator_ids=[
                "VAL-RESPONDER-DEEP-001",
                "VAL-RESPONDER-EXPOSURE-001",
            ],
            policy=policy,
            authorization=authorization,
            device_identifier="HOSTNAME-01",
            profile="deep-responder-validation",
            platform="windows",
            observed_privileges=("STANDARD_USER", "LOCAL_ADMIN"),
        )
        self.assertEqual("VAL-RESPONDER-EXPOSURE-001", plans[-1].validator_id)
        self.assertEqual(5, len(plans))
        self.assertEqual(64, len(plan_digest(plans)))

    def test_unauthorized_dependency_is_a_planning_error(self) -> None:
        """The aggregate must never silently run without required inputs."""

        authorization_path = self._authorization()
        document = json.loads(authorization_path.read_text(encoding="utf-8"))
        document["scope"]["validatorIds"] = [
            "VAL-RESPONDER-EXPOSURE-001"
        ]
        authorization_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(PlanningError):
            ValidationPlanner(ValidatorRegistry()).plan(
                run_id="PLAN",
                requested_validator_ids=["VAL-RESPONDER-EXPOSURE-001"],
                policy=load_policy(self._policy()),
                authorization=load_authorization(authorization_path),
                device_identifier="HOSTNAME-01",
                platform="windows",
            )

    def test_invalid_dependency_shapes_are_rejected(self) -> None:
        """Planner must fail closed for every invalid dependency shape."""

        scenarios = (
            (
                "cycle",
                [
                    ("CycleAValidator", "VAL-CYCLE-A-001", "ACTIVE"),
                    ("CycleBValidator", "VAL-CYCLE-B-001", "ACTIVE"),
                ],
                "VAL-CYCLE-A-001",
                None,
            ),
            (
                "unknown",
                [
                    (
                        "UnknownDependencyValidator",
                        "VAL-UNKNOWN-DEP-001",
                        "ACTIVE",
                    ),
                ],
                "VAL-UNKNOWN-DEP-001",
                None,
            ),
            (
                "disabled",
                [
                    (
                        "DisabledParentValidator",
                        "VAL-DISABLED-PARENT-001",
                        "ACTIVE",
                    ),
                    (
                        "DisabledChildValidator",
                        "VAL-DISABLED-CHILD-001",
                        "DISABLED",
                    ),
                ],
                "VAL-DISABLED-PARENT-001",
                None,
            ),
            (
                "risk",
                [
                    ("RiskParentValidator", "VAL-RISK-PARENT-001", "ACTIVE"),
                    ("RiskChildValidator", "VAL-RISK-CHILD-001", "ACTIVE"),
                ],
                "VAL-RISK-PARENT-001",
                "safe-read-only",
            ),
        )
        for name, entries, selected, profile in scenarios:
            with self.subTest(name=name):
                registry = ValidatorRegistry(self._fixture_registry(name, entries))
                ids = [item[1] for item in entries]
                with self.assertRaises(PlanningError):
                    ValidationPlanner(registry).plan(
                        run_id="PLAN",
                        requested_validator_ids=[selected],
                        policy=load_policy(self._policy()),
                        authorization=load_authorization(
                            self._authorization(ids)
                        ),
                        device_identifier="HOSTNAME-01",
                        profile=profile,
                        platform="windows",
                        observed_privileges=(
                            "STANDARD_USER",
                            "LOCAL_ADMIN",
                        ),
                    )

    def test_plaintext_secret_and_credential_output_are_blocked(self) -> None:
        """Authorization and process output must reject credential material."""

        path = self._authorization()
        document = json.loads(path.read_text(encoding="utf-8"))
        document["testIdentity"]["password"] = "SyntheticSecretValue"
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(AuthorizationError):
            load_authorization(path)
        with self.assertRaises(SensitiveEvidenceError):
            validate_output_text("Proxy-Authorization: NTLM synthetic-value")

    def test_plan_digest_mismatch_stops_before_audit(self) -> None:
        """Exact-plan confirmation must fail before validator execution."""

        with self.assertRaises(ValueError):
            self._execute(
                self._observation("confirmed"),
                required_plan_digest="0" * 64,
            )

    def _execute(
        self,
        observation: dict[str, object],
        authorization_path: Path | None = None,
        required_plan_digest: str | None = None,
        policy_path: Path | None = None,
    ):
        """Execute the complete deep profile through child workers."""

        return execute_active_validation(
            data={
                "device": {"hostname": "HOSTNAME-01", "elevated": True},
                "operatingSystem": {"name": "Windows 11"},
                "security": {"settings": []},
            },
            findings=[],
            policy=load_policy(policy_path or self._policy()),
            authorization=load_authorization(
                authorization_path or self._authorization()
            ),
            requested_validator_ids=[
                "VAL-RESPONDER-DEEP-001",
                "VAL-RESPONDER-EXPOSURE-001",
            ],
            audit_path=self.root / f"audit-{uuid4().hex}.jsonl",
            profile="deep-responder-validation",
            require_related_rule=False,
            required_plan_digest=required_plan_digest,
            transport_observations={
                "VAL-RESPONDER-DEEP-001": observation,
            },
        )

    def _policy(self) -> Path:
        """Write the exact deep safety policy."""

        data = dict(DEFAULT_POLICY)
        data.update({
            "enabled": True,
            "allowedRiskLevels": [
                "SAFE_READ_ONLY",
                "CONTROLLED_TEMPORARY_CHANGE",
            ],
            "allowTemporarySystemChanges": True,
            "allowNetworkListeners": True,
            "allowLoopbackNetworkTests": False,
            "allowDeepResponderValidation": True,
            "allowNameResolutionResponses": True,
            "allowAuthenticationChallenges": True,
            "allowTemporaryNetworkListeners": True,
            "allowTemporaryFirewallChanges": True,
            "allowSyntheticCredentialFlow": True,
        })
        return self._write("deep-policy.json", data)

    def _authorization(
        self,
        validator_ids: list[str] | None = None,
    ) -> Path:
        """Write an exact-scope secret-reference-only authorization."""

        now = datetime.now(timezone.utc)
        data = {
            "schemaVersion": "1.0",
            "authorized": True,
            "assessmentId": "CSA-DEEP-001",
            "scope": {
                "deviceIdentifiers": ["HOSTNAME-01"],
                "validatorIds": validator_ids or [
                    "VAL-NTLM-POLICY-001",
                    "VAL-SMB-SIGNING-EXPOSURE-001",
                    "VAL-WPAD-EXPOSURE-001",
                    "VAL-RESPONDER-DEEP-001",
                    "VAL-RESPONDER-EXPOSURE-001",
                ],
                **self._scope(),
            },
            "permissions": {
                "nameResolutionSpoofing": True,
                "authenticationChallenge": True,
                "temporaryListener": True,
                "temporaryFirewallChange": True,
                "credentialMaterialRetention": False,
                "credentialRelay": False,
                "hashCracking": False,
            },
            "testIdentity": {
                "mode": "DEDICATED_TEST_ACCOUNT",
                "identifier": "CSA-TEST-USER",
                "credentialReference": "secure-runtime-reference",
                "authorizedForAuthenticationTest": True,
            },
            "authorizedBy": "test-operator",
            "authorizedAt": (now - timedelta(minutes=1)).isoformat(),
            "expiresAt": (now + timedelta(hours=1)).isoformat(),
            "purpose": "Controlled deep validation test",
        }
        return self._write("deep-authorization.json", data)

    def _fixture_registry(
        self,
        name: str,
        entries: list[tuple[str, str, str]],
    ) -> Path:
        """Write a strict registry that imports fixtures from this module."""

        return self._write(
            f"registry-{name}.json",
            {
                "schemaVersion": "1.0",
                "validators": [
                    {
                        "validatorId": validator_id,
                        "version": "1.0.0",
                        "module": __name__,
                        "class": class_name,
                        "status": status,
                        "supportedRuleIds": [],
                    }
                    for class_name, validator_id, status in entries
                ],
            },
        )

    @staticmethod
    def _scope() -> dict[str, list[str]]:
        """Return exact network scope."""

        return {
            "networkInterfaces": ["Ethernet"],
            "allowedSourceAddresses": ["192.0.2.10"],
            "allowedTargetAddresses": ["192.0.2.25"],
            "allowedProtocols": ["LLMNR", "NBT_NS", "SMB", "HTTP"],
        }

    @staticmethod
    def _observation(mode: str) -> dict[str, object]:
        """Return a minimized protocol-harness observation."""

        observed = mode in {"confirmed", "partial"}
        messages = (
            [
                parse_ntlm_message_type(
                    b"NTLMSSP\x00" + struct.pack("<I", 1) + b"\x00" * 8
                ),
                parse_ntlm_message_type(
                    build_ephemeral_ntlm_challenge("HARNESS")
                ),
                parse_ntlm_message_type(
                    b"NTLMSSP\x00" + struct.pack("<I", 3) + b"\x00" * 32
                ),
            ]
            if mode == "confirmed"
            else (["NEGOTIATE"] if observed else [])
        )
        return {
            "queryMarker": "$CSA_RUN_MARKER",
            "networkInterface": "Ethernet",
            "sourceAddress": "192.0.2.25",
            "listenerAddress": "192.0.2.10",
            "protocol": "SMB",
            "markerQueryObserved": True,
            "responseSent": True,
            "responseCount": 1,
            "listenerOperational": True,
            "connectionObserved": mode != "not_observed",
            "connectionCount": 0 if mode == "not_observed" else 1,
            "payloadBytes": 256,
            "authenticationChallengeIssued": observed,
            "authenticationAttemptObserved": observed,
            "messageTypesObserved": messages,
            "testIdentityMatched": mode == "confirmed",
            "sufficientObservationWindow": True,
            "ntlmOutboundBlocked": mode == "partial",
            "clientSigningRequired": mode == "partial",
            "protocolParserVerified": True,
            "cleanupCompleted": True,
        }

    @staticmethod
    def _query(marker: str) -> bytes:
        """Build one bounded DNS-label query for protocol parser tests."""

        label = marker.encode("ascii")
        return (
            b"\x12\x34\x00\x00"
            + struct.pack("!H", 1)
            + b"\x00\x00\x00\x00\x00\x00"
            + bytes([len(label)])
            + label
            + b"\x00\x00\x01\x00\x01"
        )

    @staticmethod
    def _nbtns_query(marker: str) -> bytes:
        """Build one first-level encoded NBT-NS query."""

        raw_name = marker.upper().ljust(15).encode("ascii") + b"\x00"
        encoded = bytearray()
        for value in raw_name:
            encoded.extend((65 + (value >> 4), 65 + (value & 0x0F)))
        return (
            b"\x12\x34\x01\x10\x00\x01\x00\x00\x00\x00\x00\x00"
            + b"\x20"
            + bytes(encoded)
            + b"\x00\x00\x20\x00\x01"
        )

    def _write(self, name: str, data: object) -> Path:
        """Write one isolated JSON document."""

        path = self.root / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return path


if __name__ == "__main__":
    unittest.main()
