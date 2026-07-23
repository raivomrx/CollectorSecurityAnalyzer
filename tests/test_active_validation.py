"""Contract tests for the safe active validation engine."""

from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from active_validation.audit import AuditLog, AuditVerificationError, verify_audit_log
from active_validation.authorization import (
    AuthorizationError,
    load_authorization,
    require_scope,
)
from active_validation.cleanup import CleanupRegistry
from active_validation.correlation import correlate
from active_validation.enums import (
    ActiveValidationStatus,
    CorrelatedRuleStatus,
    RiskLevel,
    ValidatorStatus,
)
from active_validation.evidence import SensitiveEvidenceError, validate_evidence
from active_validation.engine import execute_active_validation
from active_validation.executor import ValidationExecutor
from active_validation.json_io import StrictJsonError, load_strict_json
from active_validation.models import (
    RegistryEntry,
    ValidationContext,
    ValidationPlan,
)
from active_validation.planner import PlanningError, ValidationPlanner
from active_validation.policy import (
    DEFAULT_POLICY,
    SafetyPolicyError,
    load_policy,
    validate_validator_safety,
)
from active_validation.registry import ValidatorRegistry, ValidatorRegistryError
from risk import Finding, Severity, Status
from rules.loader import load_registry as load_rule_registry


class ActiveValidationContractTests(unittest.TestCase):
    """Verify authorization, policy, planning, isolation, and audit contracts."""

    def setUp(self) -> None:
        """Create an isolated test workspace."""

        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        """Remove isolated artifacts."""

        self.temporary.cleanup()

    def test_default_policy_is_disabled(self) -> None:
        """Built-in active validation must be opt-in."""

        policy = self._policy(enabled=False)
        self.assertFalse(policy.enabled)

    def test_policy_rejects_unknown_key(self) -> None:
        """Policy parsing should be strict."""

        data = dict(DEFAULT_POLICY)
        data["unexpected"] = True
        path = self._write("policy.json", data)
        with self.assertRaises(SafetyPolicyError):
            load_policy(path)

    def test_policy_rejects_prohibited_risk(self) -> None:
        """Policy cannot enable prohibited validators."""

        data = dict(DEFAULT_POLICY)
        data["allowedRiskLevels"] = ["PROHIBITED"]
        path = self._write("policy.json", data)
        with self.assertRaises(SafetyPolicyError):
            load_policy(path)

    def test_policy_rejects_unknown_risk_and_excessive_timeout(self) -> None:
        """Unknown enums and timeout values beyond the safety cap must fail."""

        invalid_cases = (
            ("risk", "allowedRiskLevels", ["UNKNOWN_RISK"]),
            ("timeout", "defaultValidatorTimeoutSeconds", 301),
        )
        for name, field, value in invalid_cases:
            data = dict(DEFAULT_POLICY)
            data[field] = value
            with self.subTest(name=name):
                with self.assertRaises(SafetyPolicyError):
                    load_policy(self._write(f"{name}.json", data))

    def test_policy_requires_authorization_and_minimal_evidence(self) -> None:
        """Sprint 4.1 cannot disable authorization or retain raw events."""

        for key in ("requireExplicitAuthorization", "retainRawEventData"):
            data = dict(DEFAULT_POLICY)
            data[key] = not data[key]
            with self.subTest(key=key):
                with self.assertRaises(SafetyPolicyError):
                    load_policy(self._write(f"{key}.json", data))

    def test_strict_json_rejects_duplicate_key(self) -> None:
        """Authorization and policy JSON must reject duplicate keys."""

        path = self.root / "duplicate.json"
        path.write_text(
            '{"schemaVersion":"1.0","schemaVersion":"1.0"}',
            encoding="utf-8",
        )
        with self.assertRaises(StrictJsonError):
            load_strict_json(path)

    def test_authorization_validates_digest_and_scope(self) -> None:
        """A valid grant should retain a deterministic digest."""

        path = self._authorization()
        authorization = load_authorization(path)
        self.assertEqual(64, len(authorization.digest))
        self.assertIn("VAL-DEFENDER-RUNTIME-001", authorization.scope.validator_ids)
        self.assertEqual(authorization.digest, load_authorization(path).digest)

    def test_authorization_requires_purpose_and_exact_scope(self) -> None:
        """Authorization should fail closed for missing intent or scope mismatch."""

        path = self._authorization()
        data = json.loads(path.read_text(encoding="utf-8"))
        data["purpose"] = ""
        with self.assertRaises(AuthorizationError):
            load_authorization(self._write("missing-purpose.json", data))

        authorization = load_authorization(path)
        invalid_scopes = (
            ("OTHER-DEVICE", ["VAL-DEFENDER-RUNTIME-001"], None),
            ("CLIENT-SENSITIVE-01", ["VAL-PS-SCRIPTBLOCK-001"], None),
            (
                "CLIENT-SENSITIVE-01",
                ["VAL-DEFENDER-RUNTIME-001"],
                "CSA-OTHER",
            ),
        )
        for device, validators, assessment_id in invalid_scopes:
            with self.subTest(
                device=device,
                validators=validators,
                assessment_id=assessment_id,
            ):
                with self.assertRaises(AuthorizationError):
                    require_scope(
                        authorization,
                        device,
                        validators,
                        assessment_id,
                    )

    def test_authorization_rejects_expired_grant(self) -> None:
        """Expired authorization must fail closed."""

        now = datetime.now(timezone.utc)
        path = self._authorization(expires_at=now - timedelta(minutes=1))
        with self.assertRaises(AuthorizationError):
            load_authorization(path, now=now)

    def test_authorization_rejects_duplicate_scope_values(self) -> None:
        """Scope arrays should not contain ambiguous duplicates."""

        path = self._authorization(
            validators=[
                "VAL-DEFENDER-RUNTIME-001",
                "VAL-DEFENDER-RUNTIME-001",
            ]
        )
        with self.assertRaises(AuthorizationError):
            load_authorization(path)

    def test_registry_has_only_reviewed_active_validators(self) -> None:
        """ACTIVE registry entries should instantiate with matching metadata."""

        registry = ValidatorRegistry()
        self.assertGreaterEqual(len(registry.get_all()), 10)
        for entry in registry.get_active():
            self.assertEqual(ValidatorStatus.ACTIVE, entry.status)
            definition = registry.definition(entry)
            self.assertEqual(entry.validator_id, definition.validator_id)
            self.assertTrue(definition.required_privileges)
            self.assertTrue(
                set(definition.required_privileges)
                <= {"STANDARD_USER", "LOCAL_ADMIN", "SYSTEM"}
            )

    def test_schema_documents_are_valid_json(self) -> None:
        """Published active validation schemas should remain parseable."""

        schema_dir = (
            Path(__file__).resolve().parents[1] / "active_validation" / "schema"
        )
        names = {path.name for path in schema_dir.glob("*.json")}
        self.assertEqual(
            {
                "authorization.schema.json",
                "policy.schema.json",
                "registry.schema.json",
                "result.schema.json",
            },
            names,
        )
        for path in schema_dir.glob("*.json"):
            with self.subTest(path=path.name):
                self.assertIsInstance(
                    json.loads(path.read_text(encoding="utf-8")),
                    dict,
                )

    def test_validator_mappings_reference_existing_rule_ids(self) -> None:
        """Active validators must not invent CSA rule mappings."""

        rule_registry = load_rule_registry(log_startup=False)
        known_ids = {
            item.rule_id for item in rule_registry.get_execution_info()
        }
        for entry in ValidatorRegistry().get_all():
            with self.subTest(validator_id=entry.validator_id):
                self.assertTrue(set(entry.supported_rule_ids) <= known_ids)

    def test_prohibited_validator_cannot_be_active(self) -> None:
        """Registry should reject an ACTIVE prohibited implementation."""

        registry = {
            "schemaVersion": "1.0",
            "validators": [{
                "validatorId": "VAL-PROHIBITED-001",
                "version": "1.0.0",
                "module": "tests.active_validation_fixtures",
                "class": "ProhibitedValidator",
                "status": "ACTIVE",
                "supportedRuleIds": ["PS-002"],
            }],
        }
        path = self._write("registry.json", registry)
        with self.assertRaises(ValidatorRegistryError):
            ValidatorRegistry(path)

    def test_planner_requires_explicit_selection(self) -> None:
        """Planning without an ID or profile should fail."""

        registry = ValidatorRegistry()
        planner = ValidationPlanner(registry)
        with self.assertRaises(PlanningError):
            planner.plan(
                "run",
                [],
                self._policy(enabled=True),
                load_authorization(self._authorization()),
                "CLIENT-SENSITIVE-01",
            )

    def test_planner_rejects_review_required_validator(self) -> None:
        """Unreviewed validator IDs should remain non-runnable."""

        registry = ValidatorRegistry()
        authorization = load_authorization(
            self._authorization(validators=["VAL-LLMNR-OBSERVE-001"])
        )
        with self.assertRaises(PlanningError):
            ValidationPlanner(registry).plan(
                "run",
                ["VAL-LLMNR-OBSERVE-001"],
                self._policy(enabled=True, risks=["SAFE_READ_ONLY", "LOW_IMPACT"]),
                authorization,
                "CLIENT-SENSITIVE-01",
            )

    def test_planner_is_deterministic(self) -> None:
        """Selection order must not alter plan order."""

        validators = [
            "VAL-WPAD-EXPOSURE-001",
            "VAL-DEFENDER-RUNTIME-001",
        ]
        registry = ValidatorRegistry()
        policy = self._policy(enabled=True)
        authorization = load_authorization(self._authorization(validators=validators))
        first = ValidationPlanner(registry).plan(
            "run", validators, policy, authorization, "CLIENT-SENSITIVE-01"
        )
        second = ValidationPlanner(registry).plan(
            "run",
            list(reversed(validators)),
            policy,
            authorization,
            "CLIENT-SENSITIVE-01",
        )
        self.assertEqual(
            [item.validator_id for item in first],
            [item.validator_id for item in second],
        )

    def test_planner_checks_platform_before_execution(self) -> None:
        """Unsupported target platforms should never reach the worker."""

        registry = ValidatorRegistry()
        authorization = load_authorization(self._authorization())
        with self.assertRaises(PlanningError):
            ValidationPlanner(registry).plan(
                "run",
                ["VAL-DEFENDER-RUNTIME-001"],
                self._policy(enabled=True),
                authorization,
                "CLIENT-SENSITIVE-01",
                platform="linux",
                available_rule_ids={"DEF-001"},
            )

    def test_safety_gate_rejects_temporary_change(self) -> None:
        """Temporary-change validators need the matching policy flag."""

        registry = ValidatorRegistry()
        entry = registry.get("VAL-WIN-FIREWALL-LOOPBACK-001")
        assert entry is not None
        allowed, _ = validate_validator_safety(
            registry.definition(entry),
            self._policy(enabled=True, risks=["CONTROLLED_TEMPORARY_CHANGE"]),
        )
        self.assertFalse(allowed)

    def test_correlation_preserves_passive_results(self) -> None:
        """Correlation should distinguish confirmation and mismatch."""

        cases = (
            (
                "PASS",
                ActiveValidationStatus.PASSED,
                CorrelatedRuleStatus.CONFIRMED_PASS,
            ),
            (
                "FAIL",
                ActiveValidationStatus.FAILED,
                CorrelatedRuleStatus.CONFIRMED_FAIL,
            ),
            (
                "PASS",
                ActiveValidationStatus.FAILED,
                CorrelatedRuleStatus.CONFIGURATION_RUNTIME_MISMATCH,
            ),
            (
                "FAIL",
                ActiveValidationStatus.PASSED,
                CorrelatedRuleStatus.CONFIGURATION_RUNTIME_MISMATCH,
            ),
            (
                None,
                ActiveValidationStatus.PASSED,
                CorrelatedRuleStatus.ACTIVE_ONLY_PASS,
            ),
            (
                None,
                ActiveValidationStatus.FAILED,
                CorrelatedRuleStatus.ACTIVE_ONLY_FAIL,
            ),
            (
                "PASS",
                ActiveValidationStatus.ERROR,
                CorrelatedRuleStatus.PASS_NOT_VALIDATED,
            ),
            (
                "FAIL",
                ActiveValidationStatus.INCONCLUSIVE,
                CorrelatedRuleStatus.FAIL_NOT_VALIDATED,
            ),
        )
        for passive, active, expected in cases:
            with self.subTest(passive=passive, active=active):
                self.assertEqual(expected, correlate(passive, active))

    def test_sensitive_evidence_guard_blocks_plaintext_patterns(self) -> None:
        """Credential-like values should never serialize."""

        samples = [
            "Bearer abc.def",
            "password=secret",
            "-----BEGIN PRIVATE KEY-----",
            "NetNTLM response",
            "NetNTLMv2",
            "challenge-response",
            "Authorization: Basic blocked",
            "username:password",
            "raw packet payload",
            r"C:\Users\Alice\file.txt",
            "access_token=value",
        ]
        for sample in samples:
            with self.subTest(sample=sample):
                with self.assertRaises(SensitiveEvidenceError):
                    validate_evidence([{"value": sample}])

    def test_sensitive_guard_allows_typed_policy_keys(self) -> None:
        """Safe typed values may use protocol-specific field names."""

        validate_evidence([{"ntlmPolicy": "RESTRICTED_EFFECTIVE"}])

    def test_executor_pass_and_fail_are_isolated(self) -> None:
        """Mock validator results should cross the subprocess JSON boundary."""

        passed = self._execute_mock("pass")
        failed = self._execute_mock("fail")
        self.assertEqual(ActiveValidationStatus.PASSED, passed.status)
        self.assertEqual(ActiveValidationStatus.FAILED, failed.status)

    def test_executor_contains_validator_exception(self) -> None:
        """Worker exceptions should become ERROR, not escape."""

        result = self._execute_mock("error")
        self.assertEqual(ActiveValidationStatus.ERROR, result.status)
        self.assertEqual("VALIDATOR_EXCEPTION", result.error_code)

    def test_executor_contains_invalid_worker_contracts(self) -> None:
        """Malformed, oversized, and non-zero workers should fail safely."""

        expectations = {
            "malformed": "INVALID_WORKER_OUTPUT",
            "oversized_stdout": "OUTPUT_LIMIT_EXCEEDED",
            "oversized_stderr": "OUTPUT_LIMIT_EXCEEDED",
            "nonzero": "WORKER_EXIT_ERROR",
            "validator_mismatch": "INVALID_WORKER_OUTPUT",
            "run_mismatch": "INVALID_WORKER_OUTPUT",
        }
        for behavior, error_code in expectations.items():
            with self.subTest(behavior=behavior):
                result = self._execute_mock(behavior)
                self.assertEqual(ActiveValidationStatus.ERROR, result.status)
                self.assertEqual(error_code, result.error_code)

    def test_executor_blocks_sensitive_result(self) -> None:
        """Sensitive mock evidence should be discarded and flagged."""

        result = self._execute_mock("sensitive")
        self.assertEqual(ActiveValidationStatus.ERROR, result.status)
        self.assertEqual("SENSITIVE_EVIDENCE_BLOCKED", result.error_code)
        self.assertEqual([], result.evidence)

    def test_executor_times_out_process(self) -> None:
        """Timeout should produce a technical status, not a failed security check."""

        result = self._execute_mock("timeout", timeout=1)
        self.assertEqual(ActiveValidationStatus.TIMED_OUT, result.status)

    @unittest.skipUnless(os.name == "nt", "Windows process-tree contract")
    def test_executor_terminates_process_tree_on_timeout(self) -> None:
        """A timed-out validator must not leave a child process running."""

        marker = self.root / "process-tree-survived.txt"
        result = self._execute_mock(
            "process_tree_timeout",
            timeout=1,
            extra_policy={"processTreeMarker": str(marker)},
        )
        time.sleep(2.25)
        self.assertEqual(ActiveValidationStatus.TIMED_OUT, result.status)
        self.assertFalse(marker.exists())

    def test_executor_removes_temporary_directory(self) -> None:
        """Successful worker temporary state and recovery record should be removed."""

        self._execute_mock("pass")
        self.assertEqual(
            [],
            list(self.root.glob("CSA-VALIDATION-run1-*")),
        )
        state = self.root / "cleanup-state.json"
        self.assertEqual([], json.loads(state.read_text(encoding="utf-8")))

    def test_executor_does_not_inherit_parent_secret(self) -> None:
        """Worker environment should omit arbitrary parent secrets."""

        previous = os.environ.get("CSA_TEST_SECRET")
        os.environ["CSA_TEST_SECRET"] = "must-not-cross-worker-boundary"
        try:
            result = self._execute_mock("environment")
        finally:
            if previous is None:
                os.environ.pop("CSA_TEST_SECRET", None)
            else:
                os.environ["CSA_TEST_SECRET"] = previous
        self.assertFalse(result.evidence[0]["secretInherited"])

    def test_rollback_failure_is_visible(self) -> None:
        """Cleanup failure must override the original execution outcome."""

        entry = RegistryEntry(
            "VAL-MOCK-ROLLBACK-001",
            "1.0.0",
            "active_validation.validators.mocks",
            "MockRollbackFailureValidator",
            ValidatorStatus.DISABLED,
            ("FW-005",),
        )
        plan = ValidationPlan(
            "run2",
            entry.validator_id,
            entry.version,
            2,
            RiskLevel.CONTROLLED_TEMPORARY_CHANGE,
            True,
            "CSA-VALIDATION-run2",
            1,
        )
        result = ValidationExecutor(self.root).execute(
            entry,
            plan,
            self._context("run2", entry.validator_id, 2, "pass"),
        )
        self.assertEqual(ActiveValidationStatus.ROLLBACK_FAILED, result.status)
        self.assertTrue(result.cleanup.manual_cleanup_required)

    def test_rollback_succeeds_after_all_terminal_paths(self) -> None:
        """Rollback should run after pass, fail, exception, and timeout."""

        expected_statuses = {
            "pass": ActiveValidationStatus.PASSED,
            "fail": ActiveValidationStatus.FAILED,
            "error": ActiveValidationStatus.ERROR,
            "timeout": ActiveValidationStatus.TIMED_OUT,
        }
        for behavior, expected_status in expected_statuses.items():
            with self.subTest(behavior=behavior):
                result = self._execute_rollback_mock(
                    behavior,
                    timeout=1 if behavior == "timeout" else 2,
                )
                self.assertEqual(expected_status, result.status)
                self.assertTrue(result.cleanup.required)
                self.assertTrue(result.cleanup.completed)
                self.assertFalse(result.cleanup.manual_cleanup_required)

    def test_audit_hash_chain_verifies(self) -> None:
        """Complete lifecycle event chain should verify."""

        path = self.root / "audit.jsonl"
        audit = AuditLog(path)
        audit.append("authorization_loaded")
        audit.append("validator_started", {"validatorId": "VAL-TEST"})
        audit.append("run_completed")
        self.assertEqual(3, verify_audit_log(path))

    def test_audit_tampering_is_detected(self) -> None:
        """Changing an audit event should break its hash."""

        path = self.root / "audit.jsonl"
        audit = AuditLog(path)
        audit.append("authorization_loaded")
        audit.append("run_completed")
        path.write_text(
            path.read_text(encoding="utf-8").replace("run_completed", "run_changed"),
            encoding="utf-8",
        )
        with self.assertRaises(AuditVerificationError):
            verify_audit_log(path)

    def test_audit_terminal_removal_is_detected(self) -> None:
        """Removing the final event should make the lifecycle incomplete."""

        path = self.root / "audit.jsonl"
        audit = AuditLog(path)
        audit.append("authorization_loaded")
        audit.append("run_completed")
        first = path.read_text(encoding="utf-8").splitlines()[0]
        path.write_text(first + "\n", encoding="utf-8")
        with self.assertRaises(AuditVerificationError):
            verify_audit_log(path)

    def test_audit_rejects_raw_or_sensitive_details(self) -> None:
        """Audit API should reject evidence payloads and credential-like text."""

        audit = AuditLog(self.root / "audit.jsonl")
        with self.assertRaises(ValueError):
            audit.append("authorization_loaded", {"evidence": []})
        with self.assertRaises(SensitiveEvidenceError):
            audit.append(
                "authorization_loaded",
                {"summary": "password=blocked-value"},
            )

    def test_cleanup_is_dry_run_by_default(self) -> None:
        """Crash cleanup must not remove tracked objects in dry-run mode."""

        temp_root = self.root / "temp"
        target = temp_root / "CSA-VALIDATION-old"
        target.mkdir(parents=True)
        registry = CleanupRegistry(self.root / "state.json", temp_root)
        registry.track({
            "objectType": "temporary_directory",
            "name": "CSA-VALIDATION-old",
            "path": str(target),
            "runId": "old",
            "createdAt": "2020-01-01T00:00:00Z",
        })
        actions = registry.cleanup(apply=False, minimum_age_seconds=1)
        self.assertTrue(target.exists())
        self.assertEqual("WOULD_REMOVE", actions[0]["action"])

    def test_cleanup_apply_removes_only_tracked_csa_objects(self) -> None:
        """Applied recovery must leave unrelated temporary objects untouched."""

        temp_root = self.root / "temp"
        target = temp_root / "CSA-VALIDATION-old"
        unrelated = temp_root / "unrelated"
        target.mkdir(parents=True)
        unrelated.mkdir()
        registry = CleanupRegistry(self.root / "state.json", temp_root)
        registry.track({
            "objectType": "temporary_directory",
            "name": target.name,
            "path": str(target),
            "runId": "old",
            "createdAt": "2020-01-01T00:00:00Z",
        })
        actions = registry.cleanup(apply=True, minimum_age_seconds=1)
        self.assertFalse(target.exists())
        self.assertTrue(unrelated.exists())
        self.assertEqual("REMOVED", actions[0]["action"])
        self.assertEqual([], registry.records())

    def test_cleanup_rejects_non_csa_namespace(self) -> None:
        """Cleanup registry must not accept arbitrary objects."""

        registry = CleanupRegistry(self.root / "state.json", self.root)
        with self.assertRaises(ValueError):
            registry.track({
                "objectType": "temporary_file",
                "name": "unrelated",
                "path": str(self.root / "unrelated"),
                "runId": "x",
                "createdAt": "2020-01-01T00:00:00Z",
            })

    def test_engine_creates_audited_correlated_run(self) -> None:
        """Engine should execute aggregate correlation through the worker boundary."""

        validator_id = "VAL-RESPONDER-EXPOSURE-001"
        authorization = load_authorization(
            self._authorization(validators=[validator_id])
        )
        audit_path = self.root / "engine-audit.jsonl"
        run = execute_active_validation(
            data={
                "device": {
                    "hostname": "CLIENT-SENSITIVE-01",
                    "elevated": False,
                },
                "operatingSystem": {"name": "Windows 11"},
                "security": {"settings": []},
            },
            findings=[
                Finding(
                    rule_id="PROTO-003",
                    severity=Severity.MEDIUM,
                    status=Status.FAIL,
                )
            ],
            policy=self._policy(enabled=True),
            authorization=authorization,
            requested_validator_ids=[validator_id],
            audit_path=audit_path,
        )
        self.assertTrue(run.formal_authorization_verified)
        self.assertEqual(1, len(run.results))
        self.assertEqual(ActiveValidationStatus.INCONCLUSIVE, run.results[0].status)
        self.assertIsNotNone(run.responder_exposure)
        self.assertGreaterEqual(len(run.correlations), 1)
        self.assertEqual(1, run.summary.planned)
        self.assertEqual(1, run.summary.executed)
        self.assertEqual(1, run.summary.inconclusive)
        self.assertGreaterEqual(verify_audit_log(audit_path), 5)

    def _execute_mock(
        self,
        behavior: str,
        timeout: int = 2,
        extra_policy: dict[str, object] | None = None,
    ):
        """Execute the contract mock through a child process."""

        entry = RegistryEntry(
            "VAL-MOCK-001",
            "1.0.0",
            "active_validation.validators.mocks",
            "MockValidator",
            ValidatorStatus.DISABLED,
            ("PS-002",),
        )
        plan = ValidationPlan(
            "run1",
            entry.validator_id,
            entry.version,
            timeout,
            RiskLevel.SAFE_READ_ONLY,
            False,
            "CSA-VALIDATION-run1",
            1,
        )
        return ValidationExecutor(self.root).execute(
            entry,
            plan,
            self._context(
                "run1",
                entry.validator_id,
                timeout,
                behavior,
                extra_policy,
            ),
        )

    def _execute_rollback_mock(
        self,
        behavior: str,
        timeout: int,
    ):
        """Execute the successful rollback mock through a child process."""

        entry = RegistryEntry(
            "VAL-MOCK-ROLLBACK-SUCCESS-001",
            "1.0.0",
            "active_validation.validators.mocks",
            "MockRollbackSuccessValidator",
            ValidatorStatus.DISABLED,
            ("FW-005",),
        )
        plan = ValidationPlan(
            "rollback-run",
            entry.validator_id,
            entry.version,
            timeout,
            RiskLevel.CONTROLLED_TEMPORARY_CHANGE,
            True,
            "CSA-VALIDATION-rollback-run",
            1,
        )
        return ValidationExecutor(self.root).execute(
            entry,
            plan,
            self._context(
                "rollback-run",
                entry.validator_id,
                timeout,
                behavior,
            ),
        )

    @staticmethod
    def _context(
        run_id: str,
        validator_id: str,
        timeout: int,
        behavior: str,
        extra_policy: dict[str, object] | None = None,
    ) -> ValidationContext:
        """Build a minimal mock worker context."""

        policy: dict[str, object] = {"mockBehavior": behavior}
        policy.update(extra_policy or {})
        return ValidationContext(
            schema_version="1.0",
            run_id=run_id,
            validator_id=validator_id,
            timeout_seconds=timeout,
            temporary_directory="",
            host_identifier_hash="host-digest",
            authorization_digest="authorization-digest",
            policy_digest="policy-digest",
            platform="windows",
            observed_privileges=(),
            passive_data={},
            passive_results={},
            prior_results=[],
            policy=policy,
        )

    def _policy(
        self,
        enabled: bool,
        risks: list[str] | None = None,
    ):
        """Write and load a policy fixture."""

        data = dict(DEFAULT_POLICY)
        data["enabled"] = enabled
        if risks is not None:
            data["allowedRiskLevels"] = risks
        return load_policy(self._write("policy.json", data))

    def _authorization(
        self,
        expires_at: datetime | None = None,
        validators: list[str] | None = None,
    ) -> Path:
        """Write a valid or deliberately altered authorization fixture."""

        now = datetime.now(timezone.utc)
        data = {
            "schemaVersion": "1.0",
            "authorized": True,
            "assessmentId": "CSA-TEST-001",
            "scope": {
                "deviceIdentifiers": ["CLIENT-SENSITIVE-01"],
                "validatorIds": validators or ["VAL-DEFENDER-RUNTIME-001"],
            },
            "authorizedBy": "test-operator",
            "authorizedAt": (now - timedelta(minutes=1)).isoformat(),
            "expiresAt": (expires_at or now + timedelta(hours=1)).isoformat(),
            "purpose": "Contract test",
        }
        return self._write("authorization.json", data)

    def _write(self, name: str, data: object) -> Path:
        """Write one JSON fixture."""

        path = self.root / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return path
