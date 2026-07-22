"""Auditable export and application of human mapping reviews."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from frameworks.digest import pack_content_digest
from frameworks.enums import MappingStatus, MappingStrength, ReviewMethod
from frameworks.exceptions import FrameworkPackError
from frameworks.loader import load_json_document, load_pack
from frameworks.models import FrameworkPack
from frameworks.registry import FrameworkPackRegistry
from frameworks.validation import FrameworkPackValidator

MAX_REVIEW_BYTES = 2 * 1024 * 1024
REVIEW_FIELDS = (
    "control_id",
    "rule_id",
    "decision",
    "reviewer",
    "reviewed_at",
    "review_method",
    "comment",
)
DECISIONS = {"VALIDATE", "KEEP_PROVISIONAL", "REJECT", "DEPRECATE"}
HUMAN_REVIEW_METHODS = {
    ReviewMethod.MANUAL_SOURCE_REVIEW.value,
    ReviewMethod.PEER_REVIEW.value,
}


@dataclass(frozen=True, slots=True)
class ReviewApplicationResult:
    """Summarize one atomic review application."""

    pack_path: Path
    audit_path: Path
    framework_id: str
    version: str
    previous_digest: str
    new_digest: str
    decision_counts: dict[str, int]


def review_candidates(
    packs: Iterable[FrameworkPack],
    status: MappingStatus | None = None,
    strength: MappingStrength | None = None,
) -> list[dict[str, Any]]:
    """Return deterministic mapping rows for human review."""

    rows = []
    for pack in packs:
        for control in pack.controls:
            for mapping in control.mappings:
                if status is not None and mapping.status != status:
                    continue
                if strength is not None and mapping.strength != strength:
                    continue
                rows.append(
                    {
                        "framework": pack.framework_id,
                        "pack_version": pack.version,
                        "control_id": control.control_id,
                        "rule_id": mapping.rule_id,
                        "mapping_strength": mapping.strength.value,
                        "current_status": mapping.status.value,
                        "source_reference": mapping.source_reference,
                        "rationale": mapping.rationale,
                        "limitations": list(mapping.evidence_limitations),
                        "review_pending_reason": (
                            mapping.review_pending_reason.value
                            if mapping.review_pending_reason is not None
                            else None
                        ),
                    }
                )
    return sorted(
        rows,
        key=lambda item: (
            item["framework"],
            item["pack_version"],
            item["control_id"],
            item["rule_id"],
        ),
    )


def apply_review(
    input_path: str | Path,
    framework_id: str,
    version: str,
    registry: FrameworkPackRegistry | None = None,
    audit_path: str | Path | None = None,
) -> ReviewApplicationResult:
    """Validate and atomically apply human decisions to existing mappings."""

    registry = registry or FrameworkPackRegistry()
    pack = registry.resolve(framework_id, version)
    pack_path = registry.pack_path(framework_id, version)
    source = _safe_review_path(input_path)
    rows = _read_review_rows(source)
    decisions = [_validated_decision(row) for row in rows]
    keys = [(item["control_id"], item["rule_id"]) for item in decisions]
    if len(keys) != len(set(keys)):
        raise FrameworkPackError("Review input contains duplicate mapping decisions")

    document = load_json_document(pack_path)
    controls = {
        str(control.get("controlId")): control
        for control in document.get("controls", [])
    }
    mapping_index: dict[tuple[str, str], tuple[dict[str, Any], dict[str, Any]]] = {}
    for control_id, control in controls.items():
        for mapping in control.get("mappings", []):
            mapping_index[(control_id, str(mapping.get("ruleId")))] = (control, mapping)
    missing = [key for key in keys if key not in mapping_index]
    if missing:
        raise FrameworkPackError(f"Review references unknown mappings: {missing}")

    audit_decisions = []
    for decision in decisions:
        key = (decision["control_id"], decision["rule_id"])
        control, mapping = mapping_index[key]
        _apply_decision(control, mapping, decision)
        audit_decisions.append(dict(decision))

    previous_digest = pack.content_hash_sha256
    document["updatedAt"] = date.today().isoformat()
    document["contentHashSha256"] = pack_content_digest(document)
    new_digest = str(document["contentHashSha256"])
    _validate_candidate_document(document, pack_path)

    decision_counts = {
        decision: sum(item["decision"] == decision for item in decisions)
        for decision in sorted(DECISIONS)
    }
    audit_document = {
        "schemaVersion": "1.0",
        "frameworkId": framework_id,
        "version": version,
        "appliedAt": datetime.now(timezone.utc).isoformat(),
        "inputDigestSha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "previousPackDigestSha256": previous_digest,
        "newPackDigestSha256": new_digest,
        "decisionCounts": decision_counts,
        "decisions": audit_decisions,
    }
    target_audit = (
        Path(audit_path).resolve()
        if audit_path is not None
        else pack_path.with_name("review-audit.json")
    )
    _atomic_json_write(pack_path, document)
    _atomic_json_write(target_audit, audit_document)
    return ReviewApplicationResult(
        pack_path=pack_path,
        audit_path=target_audit,
        framework_id=framework_id,
        version=version,
        previous_digest=previous_digest,
        new_digest=new_digest,
        decision_counts=decision_counts,
    )


def _safe_review_path(value: str | Path) -> Path:
    """Resolve a bounded regular CSV or JSON review file."""

    path = Path(value).resolve(strict=True)
    if not path.is_file() or path.suffix.casefold() not in {".csv", ".json"}:
        raise FrameworkPackError("Review input must be a CSV or JSON file")
    if path.stat().st_size > MAX_REVIEW_BYTES:
        raise FrameworkPackError("Review input exceeds the maximum file size")
    return path


def _read_review_rows(path: Path) -> list[dict[str, Any]]:
    """Read review rows while rejecting duplicate or unexpected fields."""

    if path.suffix.casefold() == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames or len(reader.fieldnames) != len(set(reader.fieldnames)):
                raise FrameworkPackError("Review CSV headers are missing or duplicated")
            if set(reader.fieldnames) != set(REVIEW_FIELDS):
                raise FrameworkPackError("Review CSV fields do not match the required schema")
            return list(reader)
    document = load_json_document(path, MAX_REVIEW_BYTES)
    rows = document.get("reviews")
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise FrameworkPackError("Review JSON requires a reviews array")
    if any(set(row) != set(REVIEW_FIELDS) for row in rows):
        raise FrameworkPackError("Review JSON fields do not match the required schema")
    return rows


def _validated_decision(row: dict[str, Any]) -> dict[str, str]:
    """Normalize one review decision and validate human provenance."""

    value = {field: str(row.get(field) or "").strip() for field in REVIEW_FIELDS}
    if not value["control_id"] or not value["rule_id"]:
        raise FrameworkPackError("Review decisions require control_id and rule_id")
    value["decision"] = value["decision"].upper()
    if value["decision"] not in DECISIONS:
        raise FrameworkPackError(f"Unknown review decision: {value['decision']}")
    if not value["reviewer"]:
        raise FrameworkPackError("Review decisions require a reviewer")
    try:
        date.fromisoformat(value["reviewed_at"])
    except ValueError as error:
        raise FrameworkPackError("Review decisions require a valid ISO review date") from error
    if value["review_method"] not in HUMAN_REVIEW_METHODS:
        raise FrameworkPackError("Review decisions require a manual or peer review method")
    return value


def _apply_decision(
    control: dict[str, Any],
    mapping: dict[str, Any],
    decision: dict[str, str],
) -> None:
    """Apply one previously validated decision to an in-memory document."""

    action = decision["decision"]
    if action == "REJECT":
        control["mappings"].remove(mapping)
        return
    if action == "VALIDATE":
        if not str(mapping.get("sourceReference") or "").strip():
            raise FrameworkPackError("VALIDATE requires an existing source reference")
        if not str(mapping.get("sourceRelease") or "").strip():
            raise FrameworkPackError("VALIDATE requires an existing source release")
        if not str(mapping.get("rationale") or "").strip():
            raise FrameworkPackError("VALIDATE requires an existing mapping rationale")
        mapping["mappingStatus"] = MappingStatus.VALIDATED.value
        mapping["reviewPendingReason"] = None
    elif action == "KEEP_PROVISIONAL":
        mapping["mappingStatus"] = MappingStatus.PROVISIONAL.value
        if not mapping.get("reviewPendingReason"):
            mapping["reviewPendingReason"] = "REQUIRES_DOMAIN_EXPERT_REVIEW"
    elif action == "DEPRECATE":
        mapping["mappingStatus"] = MappingStatus.DEPRECATED.value
        mapping["reviewPendingReason"] = None
    mapping["reviewer"] = decision["reviewer"]
    mapping["reviewedAt"] = decision["reviewed_at"]
    mapping["reviewMethod"] = decision["review_method"]
    if decision["comment"]:
        limitations = mapping.setdefault("evidenceLimitations", [])
        limitations.append(f"Review comment: {decision['comment']}")


def _validate_candidate_document(document: dict[str, Any], target: Path) -> None:
    """Validate a complete candidate before replacing the pack."""

    temporary = _temporary_path(target)
    try:
        temporary.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
        candidate = load_pack(temporary)
        errors = FrameworkPackValidator().validate(candidate)
        if errors:
            raise FrameworkPackError("Reviewed pack is invalid: " + "; ".join(errors))
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_json_write(path: Path, document: dict[str, Any]) -> None:
    """Write one JSON document using same-directory atomic replacement."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = _temporary_path(path)
    try:
        temporary.write_text(
            json.dumps(document, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _temporary_path(target: Path) -> Path:
    """Reserve and close a temporary file next to its atomic target."""

    descriptor, name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    os.close(descriptor)
    return Path(name)
