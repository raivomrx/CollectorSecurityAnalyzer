"""Command-line interface for active validation administration."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from active_validation.audit import verify_audit_log
from active_validation.authorization import load_authorization
from active_validation.cleanup import (
    DEFAULT_STATE_PATH,
    DEFAULT_TEMPORARY_ROOT,
    CleanupRegistry,
)
from active_validation.engine import execute_active_validation
from active_validation.planner import ValidationPlanner, plan_digest
from active_validation.policy import load_policy
from active_validation.registry import ValidatorRegistry
from active_validation.serialization import active_run_to_dict, to_camel_dict
from parser import parse_collector_file


def main() -> None:
    """Run an active-validation administration command."""

    parser = _build_parser()
    args = parser.parse_args()
    registry = ValidatorRegistry()
    if args.command == "list":
        for entry in registry.get_all():
            print(
                f"{entry.validator_id}\t{entry.version}\t{entry.status.value}"
            )
        return
    if args.command == "show":
        entry = registry.get(args.validator_id)
        if entry is None:
            parser.error("Unknown validator ID")
        print(
            json.dumps(to_camel_dict(registry.definition(entry)), indent=2)
        )
        return
    if args.command == "validate-policy":
        policy = load_policy(args.path)
        print(f"VALID\t{policy.digest}")
        return
    if args.command == "validate-authorization":
        authorization = load_authorization(args.path)
        print(f"VALID\t{authorization.digest}")
        return
    if args.command == "verify-audit":
        print(f"VALID\tentries={verify_audit_log(args.path)}")
        return
    if args.command == "cleanup":
        cleanup = CleanupRegistry(args.state, args.temporary_root)
        actions = cleanup.cleanup(
            apply=args.apply,
            minimum_age_seconds=args.minimum_age,
        )
        print(json.dumps(actions, indent=2))
        return
    policy = load_policy(args.policy)
    authorization = load_authorization(args.authorization)
    requested = args.validator or []
    if args.command == "plan":
        device = args.device
        if device is None and len(authorization.scope.device_identifiers) == 1:
            device = authorization.scope.device_identifiers[0]
        if device is None:
            parser.error(
                "--device is required when authorization covers multiple devices"
            )
        plans = ValidationPlanner(registry).plan(
            run_id="PLAN",
            requested_validator_ids=requested,
            policy=policy,
            authorization=authorization,
            device_identifier=device,
            assessment_id=args.assessment_id,
            profile=args.profile,
        )
        print(json.dumps({
            "planDigest": plan_digest(plans),
            "profile": args.profile,
            "deepResponderSummary": _deep_summary(
                policy, authorization, args.profile
            ),
            "plans": to_camel_dict(plans),
        }, indent=2))
        return
    data = parse_collector_file(args.input)
    run = execute_active_validation(
        data=data,
        findings=[],
        policy=policy,
        authorization=authorization,
        requested_validator_ids=requested,
        audit_path=args.audit,
        assessment_id=args.assessment_id,
        profile=args.profile,
        registry=registry,
        require_related_rule=False,
        required_plan_digest=args.require_plan_digest,
    )
    print(json.dumps(active_run_to_dict(run), indent=2))


def _build_parser() -> argparse.ArgumentParser:
    """Build the active-validation CLI parser."""

    parser = argparse.ArgumentParser(description="CSA Active Validation Engine")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list")
    show = subparsers.add_parser("show")
    show.add_argument("validator_id")
    for command in ("validate-policy", "validate-authorization", "verify-audit"):
        child = subparsers.add_parser(command)
        child.add_argument("path")
    cleanup = subparsers.add_parser("cleanup")
    cleanup.add_argument(
        "--state",
        default=str(DEFAULT_STATE_PATH),
    )
    cleanup.add_argument(
        "--temporary-root",
        default=str(DEFAULT_TEMPORARY_ROOT),
    )
    cleanup.add_argument("--minimum-age", type=int, default=3600)
    mode = cleanup.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    for command in ("plan", "run"):
        child = subparsers.add_parser(command)
        child.add_argument("--policy", required=True)
        child.add_argument("--authorization", required=True)
        child.add_argument("--device")
        child.add_argument("--assessment-id")
        child.add_argument("--validator", action="append")
        child.add_argument(
            "--profile",
            choices=[
                "safe-read-only",
                "safe-local",
                "controlled-temporary",
                "deep-responder-validation",
            ],
        )
        if command == "run":
            child.add_argument("--input", required=True)
            child.add_argument("--audit", required=True)
            child.add_argument("--require-plan-digest")
    return parser


def _deep_summary(policy, authorization, profile: str | None):
    """Return a credential-free deep plan summary."""

    if profile != "deep-responder-validation":
        return None
    return {
        "title": "Deep Responder Validation",
        "nameResolutionResponse": (
            "ENABLED" if policy.allow_name_resolution_responses else "DISABLED"
        ),
        "authenticationChallenge": (
            "ENABLED" if policy.allow_authentication_challenges else "DISABLED"
        ),
        "credentialRelay": "DISABLED",
        "credentialCracking": "DISABLED",
        "credentialRetention": "DISABLED",
        "authorizedInterfaces": list(authorization.scope.network_interfaces),
        "authorizedTargets": list(
            authorization.scope.allowed_target_addresses
        ),
        "temporaryListener": policy.allow_temporary_network_listeners,
        "temporaryFirewallRule": policy.allow_temporary_firewall_changes,
        "rollbackRequired": True,
    }


if __name__ == "__main__":
    main()
