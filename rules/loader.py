"""Dynamic rule loader for plug-in style analyzer rules."""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil

from rules.base import BaseRule

LOGGER = logging.getLogger(__name__)


def load_rules() -> list[BaseRule]:
    """Discover, instantiate, and return all available rule classes."""

    package = importlib.import_module("rules")
    _import_rule_modules(package.__name__, package.__path__)

    rules: list[BaseRule] = []
    for rule_class in _iter_rule_classes():
        try:
            rules.append(rule_class())
        except Exception:
            LOGGER.exception("Failed to instantiate rule: %s", rule_class.__name__)

    rules.sort(key=lambda rule: rule.id)
    LOGGER.info("Loaded %s rules", len(rules))
    return rules


def _import_rule_modules(package_name: str, package_path: object) -> None:
    """Import every non-private module in the rules package."""

    for module_info in pkgutil.iter_modules(package_path):
        if module_info.name.startswith("_") or module_info.name in {"base", "loader"}:
            continue
        importlib.import_module(f"{package_name}.{module_info.name}")


def _iter_rule_classes() -> list[type[BaseRule]]:
    """Return all concrete BaseRule subclasses currently imported."""

    subclasses: list[type[BaseRule]] = []
    for subclass in BaseRule.__subclasses__():
        subclasses.extend(_walk_subclasses(subclass))
    return [rule_class for rule_class in subclasses if not inspect.isabstract(rule_class)]


def _walk_subclasses(rule_class: type[BaseRule]) -> list[type[BaseRule]]:
    """Return a rule class and all of its nested subclasses."""

    classes = [rule_class]
    for subclass in rule_class.__subclasses__():
        classes.extend(_walk_subclasses(subclass))
    return classes
