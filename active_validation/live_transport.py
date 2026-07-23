"""Trusted subprocess boundary for the self-hosted transport harness."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Any

from active_validation.deep_protocol import build_transport_marker
from active_validation.digest import canonical_json
from active_validation.evidence import validate_evidence
from active_validation.models import (
    RollbackResult,
    ValidationContext,
    ValidationPlan,
)
from active_validation.transport_harness import cleanup_firewall_state


class LiveTransportError(RuntimeError):
    """Report an invalid or failed trusted harness boundary."""


def run_live_transport(
    context: ValidationContext,
    plan: ValidationPlan,
) -> dict[str, Any]:
    """Run the packaged harness and verify its ephemeral HMAC attestation."""

    config = context.live_transport_config
    identity = context.test_identity or {}
    if config is None:
        raise LiveTransportError("Live transport configuration is unavailable")
    if not context.plan_digest or not context.authorization_digest:
        raise LiveTransportError("Live transport digests are unavailable")
    expected_identity_hash = identity.get("identityHash")
    if not isinstance(expected_identity_hash, str):
        raise LiveTransportError("Expected test identity hash is unavailable")
    run_directory = Path(context.temporary_directory).resolve()
    token = secrets.token_hex(12)
    input_path = run_directory / f"harness-input-{token}.json"
    output_path = run_directory / f"harness-output-{token}.json"
    state_path = run_directory / f"firewall-state-{token}.json"
    marker = build_transport_marker(
        context.run_id,
        str(config["nameResolutionProtocol"]),
    )
    observation_timeout = max(5, min(plan.timeout_seconds - 10, 50))
    payload = {
        "schemaVersion": "1.0",
        "runId": context.run_id,
        "planDigest": context.plan_digest,
        "authorizationDigest": context.authorization_digest,
        "marker": marker,
        "networkInterface": config["networkInterface"],
        "listenerAddress": config["listenerAddress"],
        "targetAddress": config["targetAddress"],
        "nameResolutionProtocol": config["nameResolutionProtocol"],
        "listenerPort": config["listenerPort"],
        "remoteComputer": config["remoteComputer"],
        "expectedIdentityHash": expected_identity_hash,
        "timeoutSeconds": observation_timeout,
        "firewallProfile": config["firewallProfile"],
        "firewallStatePath": str(state_path),
    }
    validate_evidence([{
        key: value
        for key, value in payload.items()
        if key != "firewallStatePath"
    }])
    input_path.write_text(
        json.dumps(payload, separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )
    key = secrets.token_bytes(32)
    environment = dict(os.environ)
    environment["CSA_HARNESS_ATTESTATION_KEY"] = key.hex()
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "active_validation.transport_harness",
                "--input",
                str(input_path),
                "--output",
                str(output_path),
            ],
            cwd=Path(__file__).resolve().parent.parent,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(6, plan.timeout_seconds - 5),
            check=False,
            creationflags=(
                subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
            ),
        )
        if completed.returncode != 0 or not output_path.is_file():
            raise LiveTransportError("Trusted transport harness failed")
        document = json.loads(output_path.read_text(encoding="utf-8"))
        if not isinstance(document, dict) or set(document) != {
            "observation",
            "attestation",
        }:
            raise LiveTransportError("Harness output contract is invalid")
        observation = document["observation"]
        attestation = document["attestation"]
        if not isinstance(observation, dict) or not isinstance(attestation, str):
            raise LiveTransportError("Harness output types are invalid")
        expected_attestation = hmac.new(
            key,
            canonical_json(observation).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(attestation, expected_attestation):
            raise LiveTransportError("Harness attestation is invalid")
        if (
            observation.get("runId") != context.run_id
            or observation.get("planDigest") != context.plan_digest
            or observation.get("authorizationDigest")
            != context.authorization_digest
            or observation.get("queryMarker") != marker
            or observation.get("transportMode")
            != "SELF_HOSTED_WINDOWS_HARNESS"
        ):
            raise LiveTransportError("Harness output binding is invalid")
        validate_evidence([observation])
        return observation
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        raise LiveTransportError("Trusted transport harness failed") from error
    finally:
        key = b"\x00" * len(key)
        input_path.unlink(missing_ok=True)
        output_path.unlink(missing_ok=True)


def rollback_live_transport(context: ValidationContext) -> RollbackResult:
    """Remove and verify every exact firewall rule tracked by the harness."""

    run_directory = Path(context.temporary_directory)
    state_paths = list(run_directory.glob("firewall-state-*.json"))
    completed = all(cleanup_firewall_state(path) for path in state_paths)
    remaining = [
        {
            "objectType": "firewall_rule",
            "redactedName": f"CSA-VALIDATION-{context.run_id}-FIREWALL",
        }
    ] if not completed else []
    return RollbackResult(
        required=True,
        completed=completed,
        manual_cleanup_required=not completed,
        remaining_objects=remaining,
        error_code=None if completed else "LIVE_FIREWALL_CLEANUP_FAILED",
    )
