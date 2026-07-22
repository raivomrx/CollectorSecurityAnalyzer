"""Command-line tools for framework pack operations."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import asdict
from typing import Any

from frameworks.comparison import compare_packs
from frameworks.coverage import calculate_coverage
from frameworks.enums import MappingStatus, MappingStrength, PackStatus
from frameworks.registry import FrameworkPackRegistry
from frameworks.review import apply_review, review_candidates
from frameworks.serialization import _normalize
from frameworks.validation import FrameworkPackValidator
from rules.loader import load_registry


def main() -> None:
    """Run the framework pack CLI."""

    parser = argparse.ArgumentParser(description="CSA framework content-pack tools")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list", help="List registered packs")

    validate = subparsers.add_parser("validate", help="Validate registered packs")
    validate.add_argument("selection", nargs="*", help="FRAMEWORK[:VERSION]")
    validate.add_argument("--all", action="store_true", help="Validate every registered pack")
    validate.add_argument("--require-reviewed", action="store_true")
    validate.add_argument("--active-only", action="store_true")
    validate.add_argument("--strict-sources", action="store_true")

    show = subparsers.add_parser("show", help="Show one pack")
    show.add_argument("selection", help="FRAMEWORK[:VERSION]")

    coverage = subparsers.add_parser("coverage", help="Show static pack coverage")
    coverage.add_argument("selection", help="FRAMEWORK[:VERSION]")

    compare = subparsers.add_parser("compare", help="Compare two pack versions")
    compare.add_argument("framework_id")
    compare.add_argument("old_version")
    compare.add_argument("new_version")

    candidates = subparsers.add_parser(
        "review-candidates",
        help="Export mapping candidates without changing pack state",
    )
    candidates.add_argument("--framework")
    candidates.add_argument("--status", choices=[item.value for item in MappingStatus])
    candidates.add_argument("--strength", choices=[item.value for item in MappingStrength])
    candidates.add_argument("--format", choices=["table", "json", "csv"], default="table")

    review = subparsers.add_parser("apply-review", help="Apply audited human review decisions")
    review.add_argument("--input", required=True)
    review.add_argument("--framework", required=True)
    review.add_argument("--version", required=True)
    review.add_argument("--audit-output")

    args = parser.parse_args()
    registry = FrameworkPackRegistry()
    if args.command == "list":
        _print_pack_list(registry)
        return
    if args.command == "show":
        pack = _resolve(registry, args.selection)
        if pack.status != PackStatus.ACTIVE:
            print(
                f"WARNING: {pack.framework_id}:{pack.version} is {pack.status.value}; "
                "it is not an active release pack.",
                file=sys.stderr,
            )
        print(json.dumps(_normalize(asdict(pack)), indent=2, ensure_ascii=False))
        return
    if args.command == "coverage":
        pack = _resolve(registry, args.selection)
        metrics = calculate_coverage(pack, ())
        print(
            json.dumps(
                {
                    "rawMappingCoveragePercent": metrics.mapping_coverage_percent,
                    "validatedMappingCoveragePercent": (
                        metrics.validated_mapping_coverage_percent
                    ),
                    "formalAssessmentCoveragePercent": (
                        metrics.formal_assessment_coverage_percent
                    ),
                    "traceabilityCoveragePercent": (
                        metrics.traceability_coverage_percent
                    ),
                },
                indent=2,
            )
        )
        return
    if args.command == "compare":
        comparison = compare_packs(
            registry.resolve(args.framework_id, args.old_version),
            registry.resolve(args.framework_id, args.new_version),
        )
        print(json.dumps(_normalize(asdict(comparison)), indent=2))
        return
    if args.command == "review-candidates":
        entries = registry.list(include_archived=True)
        if args.framework:
            entries = [item for item in entries if item.framework_id == args.framework]
        packs = [registry.resolve(item.framework_id, item.version) for item in entries]
        rows = review_candidates(
            packs,
            MappingStatus(args.status) if args.status else None,
            MappingStrength(args.strength) if args.strength else None,
        )
        _print_candidates(rows, args.format)
        return
    if args.command == "apply-review":
        result = apply_review(
            args.input,
            args.framework,
            args.version,
            registry,
            args.audit_output,
        )
        print(
            json.dumps(
                {
                    "frameworkId": result.framework_id,
                    "version": result.version,
                    "previousDigest": result.previous_digest,
                    "newDigest": result.new_digest,
                    "decisionCounts": result.decision_counts,
                    "auditFile": result.audit_path.name,
                },
                indent=2,
            )
        )
        return
    if args.command == "validate":
        packs = _validation_packs(registry, args.selection, args.active_only)
        if args.active_only and not packs:
            print("No active framework packs")
            return
        validator = FrameworkPackValidator(load_registry(log_startup=False))
        errors = [
            f"{pack.framework_id}:{pack.version}: {error}"
            for pack in packs
            for error in validator.validate(
                pack,
                require_reviewed=args.require_reviewed,
                strict_sources=args.strict_sources,
            )
        ]
        if errors:
            for error in errors:
                print(error)
            raise SystemExit(1)
        print(f"Validated {len(packs)} framework pack(s)")


def _validation_packs(
    registry: FrameworkPackRegistry,
    selections: list[str],
    active_only: bool,
) -> list[Any]:
    """Resolve the deterministic set selected for validation."""

    if selections:
        packs = [_resolve(registry, selection) for selection in selections]
    else:
        entries = registry.list(include_archived=True)
        if active_only:
            entries = [item for item in entries if item.status == PackStatus.ACTIVE]
        packs = [registry.resolve(item.framework_id, item.version) for item in entries]
    return [pack for pack in packs if not active_only or pack.status == PackStatus.ACTIVE]


def _print_pack_list(registry: FrameworkPackRegistry) -> None:
    """Print pack release and mapping counts."""

    headings = (
        "Framework ID\tVersion\tStatus\tControls\tMappings\tValidated\t"
        "Provisional\tActive default"
    )
    print(headings)
    for entry in registry.list(include_archived=True):
        pack = registry.resolve(entry.framework_id, entry.version)
        mappings = [mapping for control in pack.controls for mapping in control.mappings]
        validated = sum(item.status == MappingStatus.VALIDATED for item in mappings)
        provisional = sum(item.status == MappingStatus.PROVISIONAL for item in mappings)
        print(
            f"{entry.framework_id}\t{entry.version}\t{entry.status.value}\t"
            f"{len(pack.controls)}\t{len(mappings)}\t{validated}\t{provisional}\t"
            f"{'yes' if entry.default and entry.status == PackStatus.ACTIVE else 'no'}"
        )


def _print_candidates(rows: list[dict[str, Any]], output_format: str) -> None:
    """Print review candidates in a deterministic requested format."""

    if output_format == "json":
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return
    fields = list(rows[0]) if rows else [
        "framework", "pack_version", "control_id", "rule_id",
        "mapping_strength", "current_status", "source_reference", "rationale",
        "limitations", "review_pending_reason",
    ]
    if output_format == "csv":
        writer = csv.DictWriter(sys.stdout, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            value = dict(row)
            value["limitations"] = " | ".join(value["limitations"])
            writer.writerow(value)
        return
    print("\t".join(fields))
    for row in rows:
        print(
            "\t".join(
                " | ".join(value) if isinstance(value, list) else str(value or "")
                for value in (row[field] for field in fields)
            )
        )


def _resolve(registry: FrameworkPackRegistry, selection: str):
    """Resolve FRAMEWORK[:VERSION] syntax."""

    framework_id, separator, version = selection.partition(":")
    return registry.resolve(framework_id, version if separator else "latest")


if __name__ == "__main__":
    main()
