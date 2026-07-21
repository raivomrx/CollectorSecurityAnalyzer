"""Validation helpers for the Windows collector evidence manifest."""

from __future__ import annotations

import json
import re
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Iterable


class EvidenceManifestError(ValueError):
    """Raised when the collector evidence manifest is internally inconsistent."""


MATCH_TYPES = {"LITERAL", "WILDCARD", "REGEX"}
CARDINALITIES = {
    "SINGLE",
    "PER_FIREWALL_PROFILE",
    "PER_FIXED_VOLUME",
    "PER_NETWORK_ADAPTER",
    "PER_LOCAL_ACCOUNT",
}
ENTRY_FIELDS = {"id", "matchType", "cardinality", "evidenceUnitId", "canonical"}


def load_evidence_manifest(path: str | Path) -> dict[str, Any]:
    """Load and validate an evidence manifest JSON file."""

    manifest_path = Path(path)
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    validate_evidence_manifest(data, manifest_path.parent / "modules")
    return data


def validate_evidence_manifest(
    manifest: dict[str, Any], module_root: str | Path | None = None
) -> None:
    """Validate module, evidence-unit, alias, and cardinality contracts."""

    if str(manifest.get("version")) != "2.0":
        raise EvidenceManifestError("Evidence manifest version must be 2.0")
    declared_cardinalities = set(manifest.get("cardinalityTypes", []))
    if declared_cardinalities != CARDINALITIES:
        raise EvidenceManifestError("Manifest cardinalityTypes are incomplete or unknown")
    modules = manifest.get("modules")
    if not isinstance(modules, list) or not modules:
        raise EvidenceManifestError("Manifest must declare modules")

    seen_modules: set[str] = set()
    seen_setting_ids: set[str] = set()
    root = Path(module_root) if module_root is not None else None
    for module in modules:
        module_name = str(module.get("module", ""))
        if not module_name or module_name in seen_modules:
            raise EvidenceManifestError(f"Invalid or duplicate module: {module_name}")
        seen_modules.add(module_name)
        entries_by_kind = {
            "mandatory": _entries(module, "mandatoryEvidence"),
            "optional": _entries(module, "optionalEvidence"),
        }
        mandatory_units = {str(item["evidenceUnitId"]) for item in entries_by_kind["mandatory"]}
        optional_units = {str(item["evidenceUnitId"]) for item in entries_by_kind["optional"]}
        overlap = mandatory_units & optional_units
        if overlap:
            raise EvidenceManifestError(
                f"Mandatory and optional evidence units overlap in {module_name}: {sorted(overlap)}"
            )
        entries = entries_by_kind["mandatory"] + entries_by_kind["optional"]
        contexts = module.get("cardinalityContexts", {})
        if not isinstance(contexts, dict) or any(key not in CARDINALITIES - {"SINGLE"} for key in contexts):
            raise EvidenceManifestError(f"Unknown cardinality context in {module_name}")
        _validate_entries(module_name, entries)
        for entry in entries:
            setting_id = str(entry["id"])
            if setting_id in seen_setting_ids:
                raise EvidenceManifestError(f"Evidence ID is declared by multiple modules: {setting_id}")
            seen_setting_ids.add(setting_id)
        if not entries and not module.get("inventoryDomains"):
            raise EvidenceManifestError(f"Module has no evidence contract: {module_name}")
        if root is not None:
            _validate_module_source(root, module_name, entries)


def validate_emitted_setting_ids(
    manifest: dict[str, Any], module_name: str, setting_ids: Iterable[str]
) -> None:
    """Ensure runtime setting IDs are declared by their module manifest."""

    module = next(
        (item for item in manifest.get("modules", []) if item.get("module") == module_name),
        None,
    )
    if module is None:
        raise EvidenceManifestError(f"Runtime module is absent from manifest: {module_name}")
    entries = _entries(module, "mandatoryEvidence") + _entries(module, "optionalEvidence")
    unknown = [setting_id for setting_id in setting_ids if not any(_matches(setting_id, e) for e in entries)]
    if unknown:
        raise EvidenceManifestError(
            f"{module_name} emitted setting IDs absent from manifest: {sorted(unknown)}"
        )


def manifest_declares_setting_id(manifest: dict[str, Any], setting_id: str) -> bool:
    """Return whether any manifest module declares a setting ID."""

    return any(
        _matches(setting_id, entry)
        for module in manifest.get("modules", [])
        for entry in _entries(module, "mandatoryEvidence") + _entries(module, "optionalEvidence")
    )


def _entries(module: dict[str, Any], field: str) -> list[dict[str, Any]]:
    value = module.get(field, [])
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise EvidenceManifestError(f"{module.get('module')}.{field} must be an object list")
    return value


def _validate_entries(module_name: str, entries: list[dict[str, Any]]) -> None:
    seen_ids: set[str] = set()
    groups: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        missing = ENTRY_FIELDS - entry.keys()
        if missing:
            raise EvidenceManifestError(f"{module_name} entry missing fields: {sorted(missing)}")
        setting_id = str(entry["id"])
        match_type = str(entry["matchType"])
        cardinality = str(entry["cardinality"])
        unit_id = str(entry["evidenceUnitId"])
        if not setting_id or not unit_id:
            raise EvidenceManifestError(f"{module_name} contains an empty evidence identifier")
        if not isinstance(entry["canonical"], bool):
            raise EvidenceManifestError(f"Canonical flag must be boolean: {module_name}.{setting_id}")
        if setting_id in seen_ids:
            raise EvidenceManifestError(f"Duplicate evidence ID in {module_name}: {setting_id}")
        seen_ids.add(setting_id)
        if match_type not in MATCH_TYPES:
            raise EvidenceManifestError(f"Unknown matchType in {module_name}: {match_type}")
        if cardinality not in CARDINALITIES:
            raise EvidenceManifestError(f"Unknown cardinality in {module_name}: {cardinality}")
        if match_type == "LITERAL" and re.search(r"[<*>]", setting_id):
            raise EvidenceManifestError(f"Literal evidence ID has placeholder syntax: {setting_id}")
        if match_type == "WILDCARD" and "*" not in setting_id:
            raise EvidenceManifestError(f"Wildcard evidence ID has no wildcard: {setting_id}")
        if match_type == "REGEX":
            try:
                re.compile(setting_id)
            except re.error as error:
                raise EvidenceManifestError(f"Invalid regex evidence ID: {setting_id}") from error
        if cardinality != "SINGLE" and match_type != "WILDCARD" and not entry.get("instanceMetadataField"):
            raise EvidenceManifestError(
                f"Dynamic literal evidence needs instanceMetadataField: {setting_id}"
            )
        groups.setdefault(unit_id, []).append(entry)

    for unit_id, aliases in groups.items():
        canonical_count = sum(item["canonical"] is True for item in aliases)
        if canonical_count != 1:
            raise EvidenceManifestError(
                f"Evidence unit {module_name}.{unit_id} must have exactly one canonical entry"
            )
        if len(aliases) > 1 and any(item["canonical"] not in {True, False} for item in aliases):
            raise EvidenceManifestError(f"Invalid alias declaration: {module_name}.{unit_id}")
        if len({str(item["cardinality"]) for item in aliases}) != 1:
            raise EvidenceManifestError(f"Aliases use different cardinalities: {module_name}.{unit_id}")


def _validate_module_source(
    module_root: Path, module_name: str, entries: list[dict[str, Any]]
) -> None:
    module_path = module_root / f"{module_name}.psm1"
    if not module_path.is_file():
        raise EvidenceManifestError(f"Module file is missing: {module_path}")
    source = module_path.read_text(encoding="utf-8")
    function_name = f"Get-CSA{module_name}Evidence"
    if not re.search(rf"function\s+{re.escape(function_name)}\b", source, re.IGNORECASE):
        raise EvidenceManifestError(f"Module function is missing: {function_name}")
    for entry in entries:
        if entry["matchType"] == "LITERAL" and not re.search(
            rf"(?<![A-Z0-9_]){re.escape(str(entry['id']))}(?![A-Z0-9_])", source
        ):
            raise EvidenceManifestError(
                f"Manifest literal does not map to {function_name}: {entry['id']}"
            )
        if entry["matchType"] == "WILDCARD":
            fragments = [part.strip("_") for part in str(entry["id"]).split("*") if part.strip("_")]
            if any(fragment not in source for fragment in fragments):
                raise EvidenceManifestError(
                    f"Manifest wildcard does not map to {function_name}: {entry['id']}"
                )


def _matches(setting_id: str, entry: dict[str, Any]) -> bool:
    match_type = entry["matchType"]
    pattern = str(entry["id"])
    if match_type == "LITERAL":
        return setting_id.casefold() == pattern.casefold()
    if match_type == "WILDCARD":
        return fnmatchcase(setting_id.casefold(), pattern.casefold())
    return re.fullmatch(pattern, setting_id, flags=re.IGNORECASE) is not None
