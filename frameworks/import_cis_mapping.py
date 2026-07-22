"""Safely import licensed CIS control-to-rule mapping seeds."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from frameworks.digest import pack_content_digest
from frameworks.exceptions import FrameworkPackError
from frameworks.loader import load_json_document
from rules.loader import load_registry

MAX_INPUT_BYTES = 5 * 1024 * 1024
MAX_CONTROLS = 5000
MAX_STRING = 4096
ALLOWED_FIELDS = {
    "controlId", "title", "section", "profile", "level", "automation",
    "ruleIds", "mappingStrength", "mappingStatus", "rationale",
    "evidenceLimitations", "reviewer", "reviewedAt", "reviewMethod",
    "reviewPendingReason", "sourceReference", "sourceRelease",
}
PROFILE_ALIASES = {
    "L1": "Level 1",
    "LEVEL 1": "Level 1",
    "L2": "Level 2",
    "LEVEL 2": "Level 2",
    "BITLOCKER": "BitLocker",
    "NEXT GENERATION WINDOWS SECURITY": "Next Generation Windows Security",
}


def import_cis_mapping(
    input_path: str | Path,
    output_path: str | Path,
    framework_id: str,
    version: str,
    strict_privacy: bool = False,
) -> Path:
    """Import a bounded CSV or JSON file into a draft CIS pack."""

    source = _safe_input_path(input_path)
    output = _safe_output_path(output_path)
    if source == output:
        raise FrameworkPackError("Input and output paths must differ")
    if source.stat().st_size > MAX_INPUT_BYTES:
        raise FrameworkPackError("CIS import exceeds the maximum file size")
    rows = _read_rows(source)
    if len(rows) > MAX_CONTROLS:
        raise FrameworkPackError("CIS import exceeds the maximum control count")
    known_rules = {
        rule.metadata.id
        for rule in load_registry(log_startup=False).get_all()
        if rule.metadata.enabled
        and not getattr(rule.metadata, "deprecated", False)
        and not getattr(rule.metadata, "superseded_by", None)
    }
    controls = [_control(row, known_rules, version) for row in rows]
    ids = [item["controlId"] for item in controls]
    if len(ids) != len(set(ids)):
        raise FrameworkPackError("CIS import contains duplicate control IDs")
    source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    imported_at = datetime.now(timezone.utc).isoformat()
    document: dict[str, Any] = {
        "schemaVersion": "1.0",
        "frameworkId": framework_id,
        "name": "CIS Windows 11 Enterprise CSA Mapping Pack",
        "version": version,
        "status": "DRAFT",
        "source": {
            "publisher": "Center for Internet Security",
            "release": version,
            "publishedAt": None,
            "retrievedAt": date.today().isoformat(),
            "reference": "LOCAL_LICENSED_CIS_IMPORT",
            "sourceDigestSha256": source_digest,
            "sourceFileName": None if strict_privacy else source.name,
            "sourceFormat": source.suffix.lstrip(".").upper(),
            "importedAt": imported_at,
            "recordCount": len(rows),
        },
        "scope": ["Windows 11 Enterprise"],
        "license": (
            "Contains CSA-authored mapping metadata only; CIS source content "
            "remains subject to its license."
        ),
        "createdAt": date.today().isoformat(),
        "updatedAt": date.today().isoformat(),
        "maintainer": "CSA",
        "minimumCsaVersion": "3.2",
        "deprecated": False,
        "supersedes": None,
        "supersededBy": None,
        "assessmentMode": "FORMAL_ASSESSMENT",
        "disclaimers": {
            "en": "Imported mapping metadata requires human source review before assessment.",
            "et": (
                "Imporditud mappingu metaandmed vajavad enne hindamist inimeste "
                "tehtud allikakontrolli."
            ),
        },
        "controls": controls,
        "contentHashSha256": "",
    }
    document["contentHashSha256"] = pack_content_digest(document)
    _atomic_json_write(output, document)
    return output


def _read_rows(path: Path) -> list[dict[str, Any]]:
    """Read whitelisted rows from CSV or duplicate-safe JSON."""

    if path.suffix.casefold() == ".json":
        document = load_json_document(path, MAX_INPUT_BYTES)
        rows = document.get("controls", [])
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            raise FrameworkPackError("JSON import requires a controls array")
    elif path.suffix.casefold() == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames or len(reader.fieldnames) != len(set(reader.fieldnames)):
                raise FrameworkPackError("CSV headers are missing or duplicated")
            rows = list(reader)
    else:
        raise FrameworkPackError("Only CSV and JSON CIS imports are supported")
    for row in rows:
        unexpected = set(row) - ALLOWED_FIELDS
        if unexpected:
            raise FrameworkPackError(f"Unexpected CIS import fields: {sorted(unexpected)}")
        for value in row.values():
            if isinstance(value, str) and len(value) > MAX_STRING:
                raise FrameworkPackError("CIS import string exceeds the maximum length")
    return rows


def _control(
    row: dict[str, Any],
    known_rules: set[str],
    source_release: str,
) -> dict[str, Any]:
    """Normalize one imported control and validate its rule references."""

    control_id = str(row.get("controlId", "")).strip()
    title = str(row.get("title", "")).strip()
    if not control_id or not title:
        raise FrameworkPackError("Every CIS control requires controlId and title")
    rule_ids = _values(row.get("ruleIds"))
    unknown = sorted(set(rule_ids) - known_rules)
    if unknown:
        raise FrameworkPackError(f"Unknown or inactive CSA rule IDs: {unknown}")
    profiles = tuple(_profile(item) for item in _values(row.get("profile")))
    mappings = [
        {
            "ruleId": rule_id,
            "mappingStrength": str(row.get("mappingStrength") or "SUPPORTING"),
            "mappingStatus": "PROVISIONAL",
            "rationale": str(row.get("rationale") or "CSA_ARCHITECT_REVIEW_PENDING"),
            "evidenceLimitations": _values(row.get("evidenceLimitations")),
            "reviewer": None,
            "reviewedAt": None,
            "sourceReference": _public_source_reference(row.get("sourceReference")),
            "sourceRelease": source_release,
            "reviewMethod": "IMPORTED_UNREVIEWED",
            "reviewPendingReason": "REQUIRES_DOMAIN_EXPERT_REVIEW",
        }
        for rule_id in rule_ids
    ]
    return {
        "controlId": control_id,
        "title": title,
        "section": str(row.get("section") or "Imported mapping seed"),
        "profile": list(profiles),
        "level": str(row.get("level") or "TECHNICAL"),
        "automation": str(row.get("automation") or "PARTIAL"),
        "mappings": mappings,
        "tags": ["imported", "licensed-source-required"],
        "notes": "Imported mapping seed; release requires human review.",
    }


def _values(value: Any) -> list[str]:
    """Normalize a JSON list or comma/semicolon-delimited value."""

    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in str(value).replace(";", ",").split(",") if item.strip()]


def _profile(value: str) -> str:
    """Normalize a known CIS profile name without guessing."""

    normalized = PROFILE_ALIASES.get(value.strip().upper())
    if normalized is None:
        raise FrameworkPackError(f"Unknown CIS profile: {value}")
    return normalized


def _safe_input_path(value: str | Path) -> Path:
    """Resolve an existing regular import file."""

    path = Path(value)
    if ".." in path.parts:
        raise FrameworkPackError("Path traversal is not allowed")
    path = path.resolve(strict=True)
    if not path.is_file():
        raise FrameworkPackError("CIS import input must be a regular file")
    return path


def _safe_output_path(value: str | Path) -> Path:
    """Resolve a JSON output path while rejecting traversal."""

    path = Path(value)
    if ".." in path.parts or path.suffix.casefold() != ".json":
        raise FrameworkPackError("Output must be a traversal-free JSON path")
    return path.resolve()


def _public_source_reference(value: Any) -> str | None:
    """Retain only non-local mapping references from imported content."""

    reference = str(value or "").strip()
    if not reference:
        return None
    if re.search(r"(?:^file:|^[a-zA-Z]:[\\/]|^\\\\|^/)", reference, re.IGNORECASE):
        return None
    return reference


def _atomic_json_write(path: Path, document: dict[str, Any]) -> None:
    """Write a complete import with same-directory atomic replacement."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        temporary.write_text(
            json.dumps(document, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    """Run the CIS mapping importer."""

    parser = argparse.ArgumentParser(description="Import a licensed CIS mapping source")
    parser.add_argument("--input", required=True)
    parser.add_argument("--framework", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--strict-privacy", action="store_true")
    args = parser.parse_args()
    print(
        import_cis_mapping(
            args.input,
            args.output,
            args.framework,
            args.version,
            strict_privacy=args.strict_privacy,
        )
    )


if __name__ == "__main__":
    main()
