"""Command-line tools for framework pack operations."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from frameworks.comparison import compare_packs
from frameworks.coverage import calculate_coverage
from frameworks.registry import FrameworkPackRegistry
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

    show = subparsers.add_parser("show", help="Show one pack")
    show.add_argument("selection", help="FRAMEWORK[:VERSION]")

    coverage = subparsers.add_parser("coverage", help="Show static pack coverage")
    coverage.add_argument("selection", help="FRAMEWORK[:VERSION]")

    compare = subparsers.add_parser("compare", help="Compare two pack versions")
    compare.add_argument("framework_id")
    compare.add_argument("old_version")
    compare.add_argument("new_version")

    args = parser.parse_args()
    registry = FrameworkPackRegistry()
    if args.command == "list":
        for entry in registry.list(include_archived=True):
            marker = "default" if entry.default else ""
            print(
                f"{entry.framework_id}\t{entry.version}\t{entry.status.value}\t{marker}"
            )
        return
    if args.command == "show":
        pack = _resolve(registry, args.selection)
        print(json.dumps(_normalize(asdict(pack)), indent=2, ensure_ascii=False))
        return
    if args.command == "coverage":
        pack = _resolve(registry, args.selection)
        metrics = calculate_coverage(pack, ())
        print(json.dumps(_normalize(asdict(metrics)), indent=2))
        return
    if args.command == "compare":
        comparison = compare_packs(
            registry.resolve(args.framework_id, args.old_version),
            registry.resolve(args.framework_id, args.new_version),
        )
        print(json.dumps(_normalize(asdict(comparison)), indent=2))
        return
    if args.command == "validate":
        selections = args.selection
        if args.all or not selections:
            packs = [
                registry.resolve(entry.framework_id, entry.version)
                for entry in registry.list(include_archived=True)
            ]
        else:
            packs = [_resolve(registry, selection) for selection in selections]
        validator = FrameworkPackValidator(load_registry(log_startup=False))
        errors = [
            f"{pack.framework_id}:{pack.version}: {error}"
            for pack in packs
            for error in validator.validate(pack, args.require_reviewed)
        ]
        if errors:
            for error in errors:
                print(error)
            raise SystemExit(1)
        print(f"Validated {len(packs)} framework pack(s)")


def _resolve(registry: FrameworkPackRegistry, selection: str):
    """Resolve FRAMEWORK[:VERSION] syntax."""

    framework_id, separator, version = selection.partition(":")
    return registry.resolve(framework_id, version if separator else "latest")


if __name__ == "__main__":
    main()
