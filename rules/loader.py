"""Dynamic rule loader for plug-in style analyzer rules."""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil

from rules.base import BaseRule
from rules.registry import RuleRegistry

LOGGER = logging.getLogger(__name__)
SKIPPED_MODULES = {"base", "categories", "loader", "metadata", "registry"}


def load_registry(log_startup: bool = True) -> RuleRegistry:
    """Discover rule modules, register their classes, and return a registry."""

    package = importlib.import_module("rules")
    _import_rule_modules(package.__name__, package.__path__)

    registry = RuleRegistry()
    for rule_class in _iter_rule_classes():
        registry.register(rule_class)

    if log_startup:
        _log_registry_startup(registry)
    return registry


def load_rules() -> list[BaseRule]:
    """Discover, register, and return enabled rules."""

    return load_registry().get_enabled()


def _import_rule_modules(package_name: str, package_path: object) -> None:
    """Import every non-private module in the rules package."""

    for module_info in pkgutil.walk_packages(package_path, prefix=f"{package_name}."):
        if module_info.name.startswith("_") or module_info.name in SKIPPED_MODULES:
            continue
        short_name = module_info.name.rsplit(".", 1)[-1]
        if short_name.startswith("_") or short_name in SKIPPED_MODULES:
            continue
        importlib.import_module(module_info.name)


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


def _log_registry_startup(registry: RuleRegistry) -> None:
    """Log registry startup statistics."""

    statistics = registry.get_statistics()
    LOGGER.info("CSA Rule Registry")
    LOGGER.info("Rules loaded: %s", statistics["total_rules"])
    LOGGER.info("Enabled: %s", statistics["enabled_rules"])
    LOGGER.info("Disabled: %s", statistics["disabled_rules"])
    LOGGER.info("Categories: %s", len(statistics["rules_by_category"]))
