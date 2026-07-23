"""Trusted live Responder transport boundary and isolation tests."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import socket
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from active_validation.deep_protocol import (
    build_ephemeral_ntlm_challenge,
    parse_ntlm_authenticate_identity_hash,
    parse_ntlm_message_type,
)
from active_validation.digest import canonical_json, sha256_digest
from active_validation.engine import validate_live_transport_config
from active_validation.enums import RiskLevel
from active_validation.live_transport import (
    LiveTransportError,
    run_live_transport,
)
from active_validation.models import (
    AuthorizationScope,
    ValidationAuthorization,
    ValidationContext,
    ValidationPlan,
)
from active_validation.transport_harness import (
    _run,
    _trusted_script,
    _read_authentication_token,
    cleanup_firewall_state,
)


class LiveResponderTransportTests(unittest.TestCase):
    """Verify attestation, cleanup, parsers, and temporary-file isolation."""

    def setUp(self) -> None:
        """Create a private worker-like temporary directory."""

        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        """Remove isolated files."""

        self.temporary.cleanup()

    def test_trusted_harness_output_is_attested_and_bound(self) -> None:
        """Only an HMAC-bound observation may cross the subprocess boundary."""

        observed_paths: set[str] = set()
        observed_timeout: list[int] = []

        def completed(command, **kwargs):
            output = Path(command[command.index("--output") + 1])
            input_path = Path(command[command.index("--input") + 1])
            observed_paths.add(input_path.name)
            observed_paths.add(output.name)
            payload = json.loads(input_path.read_text(encoding="utf-8"))
            observed_timeout.append(payload["timeoutSeconds"])
            self.assertEqual(25, kwargs["timeout"])
            observation = self._observation(payload)
            key = bytes.fromhex(kwargs["env"]["CSA_HARNESS_ATTESTATION_KEY"])
            output.write_text(
                json.dumps({
                    "observation": observation,
                    "attestation": hmac.new(
                        key,
                        canonical_json(observation).encode("utf-8"),
                        hashlib.sha256,
                    ).hexdigest(),
                }),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(command, 0)

        context = self._context()
        with patch(
            "active_validation.live_transport.subprocess.run",
            side_effect=completed,
        ):
            observation = run_live_transport(context, self._plan())
        self.assertEqual(context.run_id, observation["runId"])
        self.assertEqual(context.plan_digest, observation["planDigest"])
        self.assertEqual(
            context.authorization_digest,
            observation["authorizationDigest"],
        )
        self.assertEqual(2, len(observed_paths))
        self.assertEqual([20], observed_timeout)
        self.assertEqual([], list(self.root.glob("harness-*.json")))

    def test_twenty_harness_runs_use_unique_files_and_leave_no_outputs(self) -> None:
        """Repeated runs must not collide or retain worker sidecars."""

        names: set[str] = set()

        def completed(command, **kwargs):
            input_path = Path(command[command.index("--input") + 1])
            output_path = Path(command[command.index("--output") + 1])
            self.assertNotIn(input_path.name, names)
            self.assertNotIn(output_path.name, names)
            names.update((input_path.name, output_path.name))
            payload = json.loads(input_path.read_text(encoding="utf-8"))
            observation = self._observation(payload)
            key = bytes.fromhex(kwargs["env"]["CSA_HARNESS_ATTESTATION_KEY"])
            output_path.write_text(
                json.dumps({
                    "observation": observation,
                    "attestation": hmac.new(
                        key,
                        canonical_json(observation).encode("utf-8"),
                        hashlib.sha256,
                    ).hexdigest(),
                }),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(command, 0)

        with patch(
            "active_validation.live_transport.subprocess.run",
            side_effect=completed,
        ):
            for index in range(20):
                context = self._context(f"RUN-{index:02d}")
                run_live_transport(context, self._plan(context.run_id))
        self.assertEqual(40, len(names))
        self.assertEqual([], list(self.root.iterdir()))

    def test_invalid_attestation_is_rejected_and_files_are_removed(self) -> None:
        """A forged observation must fail closed without retained sidecars."""

        def forged(command, **_kwargs):
            input_path = Path(command[command.index("--input") + 1])
            output_path = Path(command[command.index("--output") + 1])
            payload = json.loads(input_path.read_text(encoding="utf-8"))
            output_path.write_text(
                json.dumps({
                    "observation": self._observation(payload),
                    "attestation": "0" * 64,
                }),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(command, 0)

        with patch(
            "active_validation.live_transport.subprocess.run",
            side_effect=forged,
        ):
            with self.assertRaises(LiveTransportError):
                run_live_transport(self._context(), self._plan())
        self.assertEqual([], list(self.root.glob("harness-*.json")))

    def test_firewall_cleanup_removes_only_tracked_names(self) -> None:
        """Recovery cleanup must remove and verify exact CSA firewall rules."""

        state = self.root / "firewall-state-test.json"
        state.write_text(
            json.dumps({
                "schemaVersion": "1.0",
                "runId": "abc123",
                "createdAt": "2026-07-23T10:00:00Z",
                "rules": [
                    {
                        "name": "CSA-VALIDATION-abc123-LLMNR",
                        "protocol": "UDP",
                        "port": 5355,
                        "created": True,
                    },
                    {
                        "name": "CSA-VALIDATION-abc123-HTTP",
                        "protocol": "TCP",
                        "port": 8080,
                        "created": True,
                    },
                ],
            }),
            encoding="utf-8",
        )
        removed: list[str] = []
        with (
            patch(
                "active_validation.transport_harness._firewall_script",
                side_effect=lambda action, name: removed.append(name),
            ),
            patch(
                "active_validation.transport_harness._firewall_exists",
                return_value=False,
            ),
        ):
            self.assertTrue(cleanup_firewall_state(state))
        self.assertEqual(2, len(removed))
        self.assertFalse(state.exists())

    def test_http_token_parser_keeps_no_header_or_token_file(self) -> None:
        """A real HTTP token is reduced to an NTLM label entirely in memory."""

        server, client = socket.socketpair()
        try:
            negotiate = b"NTLMSSP\x00" + struct.pack("<I", 1) + b"\x00" * 8
            encoded = base64.b64encode(negotiate)
            client.sendall(
                b"GET / HTTP/1.1\r\nHost: csa\r\nAuthorization: NTLM "
                + encoded
                + b"\r\n\r\n"
            )
            token = _read_authentication_token(server)
            self.assertEqual("NEGOTIATE", parse_ntlm_message_type(token))
            self.assertEqual([], list(self.root.iterdir()))
        finally:
            server.close()
            client.close()

    def test_authenticate_identity_is_hashed_without_response_fields(self) -> None:
        """Type 3 parsing should return only the normalized identity hash."""

        message = self._type_three("LAB", "CSA-TEST-USER")
        identity_hash = parse_ntlm_authenticate_identity_hash(message)
        self.assertEqual(
            "sha256:" + sha256_digest("lab\\csa-test-user"),
            identity_hash,
        )
        self.assertEqual(
            "CHALLENGE",
            parse_ntlm_message_type(
                build_ephemeral_ntlm_challenge("RUN-IDENTITY")
            ),
        )

    def test_packaged_transport_scripts_match_the_trust_allowlist(self) -> None:
        """The subprocess must reject modified firewall or trigger scripts."""

        for name in (
            "Manage-ResponderFirewall.ps1",
            "Invoke-ResponderMarkerLookup.ps1",
        ):
            with self.subTest(name=name):
                self.assertTrue(_trusted_script(name).is_file())

    def test_completed_empty_window_is_recorded_as_sufficient(self) -> None:
        """A full observation window is sufficient even without a response."""

        config = {
            **self._context().live_transport_config,
            "runId": "abc123",
            "planDigest": "d" * 64,
            "authorizationDigest": "a" * 64,
            "marker": "CSA-RSP-ABCDEF12-ABCDEF",
            "expectedIdentityHash": "sha256:" + "1" * 64,
            "timeoutSeconds": 5,
            "firewallStatePath": str(
                self.root / "firewall-state-window.json"
            ),
        }
        listener = MagicMock()
        with (
            patch(
                "active_validation.transport_harness.monotonic",
                side_effect=(0.0, 5.0),
            ),
            patch(
                "active_validation.transport_harness._firewall_script"
            ),
            patch(
                "active_validation.transport_harness._resolution_listener",
                return_value=listener,
            ),
            patch(
                "active_validation.transport_harness._http_listener",
                return_value=listener,
            ),
            patch(
                "active_validation.transport_harness._start_trigger",
                return_value=None,
            ),
            patch(
                "active_validation.transport_harness._observe_resolution"
            ),
            patch("active_validation.transport_harness._observe_http"),
            patch(
                "active_validation.transport_harness.cleanup_firewall_state",
                return_value=True,
            ),
        ):
            observation = _run(config)
        self.assertTrue(observation["sufficientObservationWindow"])
        self.assertTrue(observation["cleanupCompleted"])

    def test_live_scope_requires_distinct_authorized_ipv4_hosts(self) -> None:
        """Planning must reject same-host and non-IPv4 live transports."""

        authorization = self._authorization()
        valid = dict(self._context().live_transport_config)
        self.assertEqual(
            valid,
            validate_live_transport_config(
                valid,
                "deep-responder-validation",
                authorization,
                "HOSTNAME-01",
            ),
        )
        same_host = dict(valid)
        same_host["targetAddress"] = same_host["listenerAddress"]
        with self.assertRaises(ValueError):
            validate_live_transport_config(
                same_host,
                "deep-responder-validation",
                authorization,
                "HOSTNAME-01",
            )
        ipv6 = dict(valid)
        ipv6["listenerAddress"] = "2001:db8::10"
        ipv6_authorization = ValidationAuthorization(
            **{
                field: getattr(authorization, field)
                for field in (
                    "schema_version",
                    "authorized",
                    "assessment_id",
                    "authorized_by",
                    "authorized_at",
                    "expires_at",
                    "purpose",
                    "digest",
                    "permissions",
                    "test_identity",
                )
            },
            scope=AuthorizationScope(
                device_identifiers=("HOSTNAME-01",),
                validator_ids=("VAL-RESPONDER-DEEP-001",),
                network_interfaces=("Ethernet",),
                allowed_source_addresses=("2001:db8::10",),
                allowed_target_addresses=("192.0.2.25",),
                allowed_protocols=("LLMNR", "HTTP"),
            ),
        )
        with self.assertRaises(ValueError):
            validate_live_transport_config(
                ipv6,
                "deep-responder-validation",
                ipv6_authorization,
                "HOSTNAME-01",
            )

    def _context(self, run_id: str = "RUN-LIVE-001") -> ValidationContext:
        """Build one worker-like live context."""

        return ValidationContext(
            schema_version="1.0",
            run_id=run_id,
            validator_id="VAL-RESPONDER-DEEP-001",
            timeout_seconds=30,
            temporary_directory=str(self.root),
            host_identifier_hash="host-digest",
            authorization_digest="a" * 64,
            policy_digest="p" * 64,
            platform="windows",
            observed_privileges=("STANDARD_USER", "LOCAL_ADMIN"),
            passive_data={},
            passive_results={},
            prior_results=[],
            policy={},
            authorization_scope={},
            authorization_permissions={},
            test_identity={
                "mode": "DEDICATED_TEST_ACCOUNT",
                "identityHash": (
                    "sha256:" + sha256_digest("lab\\csa-test-user")
                ),
                "credentialReference": "secure-runtime-reference",
                "authorizedForAuthenticationTest": True,
            },
            profile="deep-responder-validation",
            plan_digest="d" * 64,
            live_transport_config={
                "enabled": True,
                "networkInterface": "Ethernet",
                "listenerAddress": "192.0.2.10",
                "targetAddress": "192.0.2.25",
                "nameResolutionProtocol": "LLMNR",
                "listenerPort": 8080,
                "remoteComputer": "HOSTNAME-01",
                "firewallProfile": "Private",
            },
        )

    @staticmethod
    def _plan(run_id: str = "RUN-LIVE-001") -> ValidationPlan:
        """Build one bounded live plan."""

        return ValidationPlan(
            run_id=run_id,
            validator_id="VAL-RESPONDER-DEEP-001",
            validator_version="1.0.0",
            timeout_seconds=30,
            risk_level=RiskLevel.CONTROLLED_TEMPORARY_CHANGE,
            requires_rollback=True,
            temporary_object_prefix=f"CSA-VALIDATION-{run_id}",
            sequence=4,
            profile="deep-responder-validation",
        )

    @staticmethod
    def _authorization() -> ValidationAuthorization:
        """Build an exact authorization for live transport planning."""

        return ValidationAuthorization(
            schema_version="1.0",
            authorized=True,
            assessment_id="CSA-LIVE-001",
            scope=AuthorizationScope(
                device_identifiers=("HOSTNAME-01",),
                validator_ids=("VAL-RESPONDER-DEEP-001",),
                network_interfaces=("Ethernet",),
                allowed_source_addresses=("192.0.2.10",),
                allowed_target_addresses=("192.0.2.25",),
                allowed_protocols=("LLMNR", "HTTP"),
            ),
            authorized_by="test",
            authorized_at="2026-07-23T00:00:00Z",
            expires_at="2026-07-24T00:00:00Z",
            purpose="Transport contract test",
            digest="a" * 64,
        )

    @staticmethod
    def _observation(payload: dict[str, object]) -> dict[str, object]:
        """Build a safe harness observation from the exact input bindings."""

        return {
            "runId": payload["runId"],
            "planDigest": payload["planDigest"],
            "authorizationDigest": payload["authorizationDigest"],
            "transportMode": "SELF_HOSTED_WINDOWS_HARNESS",
            "queryMarker": payload["marker"],
            "networkInterface": payload["networkInterface"],
            "sourceAddress": payload["targetAddress"],
            "listenerAddress": payload["listenerAddress"],
            "nameResolutionProtocol": payload["nameResolutionProtocol"],
            "protocol": "HTTP",
            "credentialMaterialRetained": False,
            "credentialMaterialWrittenToDisk": False,
            "credentialMaterialIncludedInReport": False,
            "relayAttempted": False,
            "crackingAttempted": False,
            "cleanupCompleted": True,
        }

    @staticmethod
    def _type_three(domain: str, username: str) -> bytes:
        """Build a synthetic Type 3 message containing no response bytes."""

        domain_bytes = domain.encode("utf-16-le")
        user_bytes = username.encode("utf-16-le")
        payload_offset = 64
        domain_offset = payload_offset
        user_offset = domain_offset + len(domain_bytes)

        def security_buffer(length: int, offset: int) -> bytes:
            return struct.pack("<HHI", length, length, offset)

        return (
            b"NTLMSSP\x00"
            + struct.pack("<I", 3)
            + security_buffer(0, payload_offset)
            + security_buffer(0, payload_offset)
            + security_buffer(len(domain_bytes), domain_offset)
            + security_buffer(len(user_bytes), user_offset)
            + security_buffer(0, user_offset + len(user_bytes))
            + security_buffer(0, user_offset + len(user_bytes))
            + struct.pack("<I", 1)
            + domain_bytes
            + user_bytes
        )


if __name__ == "__main__":
    unittest.main()
