"""Build privacy-safe CI artifacts for the active validation contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from active_validation.audit import AuditLog, verify_audit_log
from active_validation.engine import disabled_run
from active_validation.registry import ValidatorRegistry
from active_validation.serialization import active_run_to_dict


def build_artifacts(output_dir: str | Path) -> list[Path]:
    """Create deterministic metadata-only CI evidence artifacts."""

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    registry = ValidatorRegistry()
    registry_path = output / "validator-registry-summary.json"
    registry_path.write_text(
        json.dumps(
            {
                "schemaVersion": "1.0",
                "total": len(registry.get_all()),
                "active": [
                    {
                        "validatorId": item.validator_id,
                        "version": item.version,
                        "status": item.status.value,
                    }
                    for item in registry.get_active()
                ],
                "reviewRequired": [
                    item.validator_id
                    for item in registry.get_all()
                    if item.status.value == "REVIEW_REQUIRED"
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    mock_path = output / "mock-validation-results.json"
    mock_path.write_text(
        json.dumps(
            {
                "schemaVersion": "1.0",
                "run": active_run_to_dict(disabled_run()),
                "contractResult": {
                    "validatorId": "VAL-MOCK-001",
                    "status": "PASSED",
                    "evidence": [{"evidenceType": "MOCK", "observed": True}],
                    "cleanup": {"required": False, "completed": True},
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    audit_path = output / "audit-log.jsonl"
    audit = AuditLog(audit_path)
    audit.append(
        "authorization_loaded",
        {"runId": "CI-CONTRACT", "authorizationDigest": "REDACTED"},
    )
    audit.append(
        "policy_loaded",
        {"runId": "CI-CONTRACT", "policyDigest": "REDACTED"},
    )
    audit.append(
        "run_completed",
        {"runId": "CI-CONTRACT", "resultCount": 0},
    )
    verification_path = output / "audit-verification.json"
    verification_path.write_text(
        json.dumps(
            {
                "schemaVersion": "1.0",
                "valid": True,
                "entryCount": verify_audit_log(audit_path),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    cleanup_path = output / "cleanup-summary.json"
    cleanup_path.write_text(
        json.dumps(
            {
                "schemaVersion": "1.0",
                "dryRun": True,
                "trackedObjects": 0,
                "actions": [],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return [
        registry_path,
        mock_path,
        audit_path,
        verification_path,
        cleanup_path,
    ]


def main() -> None:
    """Build contract artifacts from CLI arguments."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    build_artifacts(args.output)


if __name__ == "__main__":
    main()
