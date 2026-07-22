"""Validation rules for framework packs and mappings."""

from __future__ import annotations

import re
from collections import Counter
from datetime import date

from frameworks.enums import MappingStatus, PackStatus, ReviewMethod
from frameworks.models import FrameworkPack, RuleMapping
from rules.registry import RuleRegistry

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
REVIEW_PENDING = "CSA_ARCHITECT_REVIEW_PENDING"
VALIDATED_REVIEW_METHODS = {
    ReviewMethod.MANUAL_SOURCE_REVIEW,
    ReviewMethod.PEER_REVIEW,
}
MOJIBAKE_MARKERS = ("\u00c3", "\u00c2", "\u00e2\u20ac", "\ufffd")
LOCAL_PATH_PATTERN = re.compile(
    r"(?:^file:|^[a-zA-Z]:[\\/]|^\\\\|^/home/|^/Users/)",
    re.IGNORECASE,
)


class FrameworkPackValidator:
    """Validate content integrity and rule mapping provenance."""

    def __init__(self, rule_registry: RuleRegistry | None = None) -> None:
        """Create a validator with an optional CSA rule registry."""

        self.rule_registry = rule_registry

    def validate(
        self,
        pack: FrameworkPack,
        require_reviewed: bool = False,
        strict_sources: bool = False,
    ) -> list[str]:
        """Return all pack validation errors."""

        errors: list[str] = []
        if pack.schema_version != "1.0":
            errors.append(f"Unsupported framework schema version: {pack.schema_version}")
        if require_reviewed and pack.status != PackStatus.ACTIVE:
            errors.append(
                f"Release validation requires ACTIVE pack status, got {pack.status.value}"
            )
        required = {
            "schemaVersion": pack.schema_version,
            "frameworkId": pack.framework_id,
            "name": pack.name,
            "version": pack.version,
            "publisher": pack.source.publisher,
            "retrievedAt": pack.source.retrieved_at,
            "sourceReference": pack.source.reference,
            "license": pack.license_notice,
            "maintainer": pack.maintainer,
            "minimumCsaVersion": pack.minimum_csa_version,
        }
        errors.extend(
            f"Missing required field: {name}"
            for name, value in required.items()
            if not value
        )
        if not SHA256_PATTERN.fullmatch(pack.content_hash_sha256):
            errors.append("contentHashSha256 must be a lowercase SHA-256 digest")
        if pack.source.digest_sha256 and not SHA256_PATTERN.fullmatch(pack.source.digest_sha256):
            errors.append("source.digestSha256 must be a lowercase SHA-256 digest")
        try:
            date.fromisoformat(pack.source.retrieved_at)
        except ValueError:
            errors.append("source.retrievedAt must be a valid ISO date")
        if LOCAL_PATH_PATTERN.search(pack.source.reference):
            errors.append("Framework source reference exposes a local path")
        if pack.source.source_file_name and (
            "/" in pack.source.source_file_name
            or "\\" in pack.source.source_file_name
            or ":" in pack.source.source_file_name
        ):
            errors.append("sourceFileName must not contain a path")
        if pack.status == PackStatus.ARCHIVED and not pack.deprecated:
            errors.append("Archived packs must be marked deprecated")
        errors.extend(_mojibake_errors(pack))

        control_ids = [control.control_id for control in pack.controls]
        errors.extend(
            f"Duplicate control ID: {control_id}"
            for control_id, count in Counter(control_ids).items()
            if count > 1
        )
        for control in pack.controls:
            if not control.control_id or not control.title or not control.section:
                errors.append(
                    f"Control has incomplete identity: {control.control_id or '<missing>'}"
                )
            mapping_ids = [mapping.rule_id for mapping in control.mappings]
            errors.extend(
                f"Duplicate mapping {control.control_id} -> {rule_id}"
                for rule_id, count in Counter(mapping_ids).items()
                if count > 1
            )
            for mapping in control.mappings:
                errors.extend(
                    self._validate_mapping(
                        pack,
                        control.control_id,
                        mapping,
                        require_reviewed,
                        strict_sources,
                    )
                )

        mappings = [mapping for control in pack.controls for mapping in control.mappings]
        provisional_count = sum(
            mapping.status == MappingStatus.PROVISIONAL for mapping in mappings
        )
        validated_count = sum(
            mapping.status == MappingStatus.VALIDATED for mapping in mappings
        )
        if pack.status == PackStatus.ACTIVE:
            if not pack.source.release:
                errors.append("ACTIVE pack requires a concrete source release")
            if provisional_count:
                errors.append("ACTIVE pack contains provisional mappings")
            if validated_count == 0:
                errors.append("ACTIVE pack requires at least one validated mapping")
        return errors

    def _validate_mapping(
        self,
        pack: FrameworkPack,
        control_id: str,
        mapping: RuleMapping,
        require_reviewed: bool,
        strict_sources: bool,
    ) -> list[str]:
        """Validate one control mapping."""

        label = f"{control_id} -> {mapping.rule_id}"
        errors: list[str] = []
        if not mapping.rationale.strip():
            errors.append(f"Missing mapping rationale: {label}")
        if mapping.review_method is None:
            errors.append(f"Missing review method: {label}")
        if mapping.source_release is None and (
            pack.framework_id == "EITS"
            or mapping.status == MappingStatus.VALIDATED
        ):
            errors.append(f"Missing mapping source release: {label}")
        if mapping.status == MappingStatus.VALIDATED:
            if not mapping.reviewer or mapping.reviewer == REVIEW_PENDING:
                errors.append(f"Validated mapping lacks a reviewer: {label}")
            if not mapping.reviewed_at:
                errors.append(f"Validated mapping lacks a review date: {label}")
            else:
                try:
                    date.fromisoformat(mapping.reviewed_at)
                except ValueError:
                    errors.append(f"Invalid mapping review date: {label}")
            if not mapping.source_reference:
                errors.append(f"Validated mapping lacks a source reference: {label}")
            if mapping.review_method not in VALIDATED_REVIEW_METHODS:
                errors.append(f"Validated mapping has an invalid review method: {label}")
            if mapping.review_pending_reason is not None:
                errors.append(f"Validated mapping retains a review pending reason: {label}")
        if mapping.status == MappingStatus.PROVISIONAL:
            if mapping.review_pending_reason is None:
                errors.append(f"Provisional mapping lacks a pending reason: {label}")
        if mapping.reviewer == REVIEW_PENDING and mapping.status != MappingStatus.PROVISIONAL:
            errors.append(f"Pending review mapping must be PROVISIONAL: {label}")
        if require_reviewed and mapping.status != MappingStatus.VALIDATED:
            errors.append(f"Mapping is not reviewed: {label}")
        if self.rule_registry is not None:
            rule = self.rule_registry.get(mapping.rule_id)
            metadata = self.rule_registry.get_metadata(mapping.rule_id)
            if rule is None or metadata is None:
                errors.append(f"Unknown rule ID: {mapping.rule_id}")
            elif not metadata.enabled:
                errors.append(f"Mapped rule is disabled: {mapping.rule_id}")
            elif getattr(metadata, "deprecated", False):
                errors.append(f"Mapped rule is deprecated: {mapping.rule_id}")
            elif getattr(metadata, "superseded_by", None):
                errors.append(
                    f"Mapped rule is superseded by {metadata.superseded_by}: {mapping.rule_id}"
                )
        if strict_sources:
            errors.extend(_strict_source_errors(pack, control_id, mapping))
        return errors


def _strict_source_errors(
    pack: FrameworkPack,
    control_id: str,
    mapping: RuleMapping,
) -> list[str]:
    """Return strict source-provenance errors for one mapping."""

    reference = mapping.source_reference or ""
    label = f"{control_id} -> {mapping.rule_id}"
    errors: list[str] = []
    if LOCAL_PATH_PATTERN.search(reference):
        errors.append(f"Mapping source reference exposes a local path: {label}")
    if pack.framework_id == "EITS":
        if "/abimaterjalid" in reference.casefold():
            errors.append(f"E-ITS mapping uses a general source reference: {label}")
        if "/2024/" in reference or "/versioon/2024/" in reference:
            errors.append(f"E-ITS 2026 mapping uses an unexplained 2024 source: {label}")
        if control_id.casefold() not in reference.casefold():
            errors.append(f"E-ITS source reference does not identify {control_id}: {label}")
    return errors


def _mojibake_errors(pack: FrameworkPack) -> list[str]:
    """Reject common double-encoded UTF-8 markers in user-visible metadata."""

    values = [
        pack.framework_id,
        pack.name,
        pack.source.publisher,
        pack.source.reference,
        pack.license_notice,
        pack.disclaimer_en or "",
        pack.disclaimer_et or "",
    ]
    values.extend(control.title for control in pack.controls)
    values.extend(control.notes or "" for control in pack.controls)
    values.extend(
        value
        for control in pack.controls
        for mapping in control.mappings
        for value in (
            mapping.rationale,
            mapping.source_reference or "",
            *mapping.evidence_limitations,
        )
    )
    return [
        "Framework pack contains mojibake text"
        for value in values
        if any(marker in value for marker in MOJIBAKE_MARKERS)
    ][:1]
