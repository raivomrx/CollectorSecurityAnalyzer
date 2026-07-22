"""Dedicated release-validation entry point."""

from __future__ import annotations

import argparse

from frameworks.enums import PackStatus
from frameworks.registry import FrameworkPackRegistry
from frameworks.validation import FrameworkPackValidator
from rules.loader import load_registry


def main() -> None:
    """Validate all packs or the active release set."""

    parser = argparse.ArgumentParser(description="Validate CSA framework packs")
    parser.add_argument("--all", action="store_true", help="Validate every registered pack")
    parser.add_argument("--active-only", action="store_true")
    parser.add_argument("--require-reviewed", action="store_true")
    parser.add_argument("--strict-sources", action="store_true")
    args = parser.parse_args()
    registry = FrameworkPackRegistry()
    entries = registry.list(include_archived=True)
    if args.active_only:
        entries = [entry for entry in entries if entry.status == PackStatus.ACTIVE]
    if args.active_only and not entries:
        print("No active framework packs")
        return
    validator = FrameworkPackValidator(load_registry(log_startup=False))
    errors = []
    for entry in entries:
        pack = registry.resolve(entry.framework_id, entry.version)
        errors.extend(
            f"{pack.framework_id}:{pack.version}: {error}"
            for error in validator.validate(
                pack,
                require_reviewed=args.require_reviewed,
                strict_sources=args.strict_sources,
            )
        )
    if errors:
        for error in errors:
            print(error)
        raise SystemExit(1)
    print(f"Validated {len(entries)} framework pack(s)")


if __name__ == "__main__":
    main()
