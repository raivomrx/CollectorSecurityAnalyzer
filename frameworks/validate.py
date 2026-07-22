"""Dedicated release-validation entry point."""

from __future__ import annotations

import argparse

from frameworks.registry import FrameworkPackRegistry
from frameworks.validation import FrameworkPackValidator
from rules.loader import load_registry


def main() -> None:
    """Validate all packs and optionally require human-reviewed mappings."""

    parser = argparse.ArgumentParser(description="Validate CSA framework packs")
    parser.add_argument("--require-reviewed", action="store_true")
    args = parser.parse_args()
    registry = FrameworkPackRegistry()
    validator = FrameworkPackValidator(load_registry(log_startup=False))
    errors = []
    for entry in registry.list(include_archived=True):
        pack = registry.resolve(entry.framework_id, entry.version)
        errors.extend(
            f"{pack.framework_id}:{pack.version}: {error}"
            for error in validator.validate(pack, args.require_reviewed)
        )
    if errors:
        for error in errors:
            print(error)
        raise SystemExit(1)
    print("All framework packs are valid")


if __name__ == "__main__":
    main()
