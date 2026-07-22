"""Validation rules for framework packs and mappings."""

from __future__ import annotations

import re
from collections import Counter
from datetime import date

from frameworks.enums import MappingStatus, PackStatus
from frameworks.models import FrameworkPack, RuleMapping
from rules.registry import RuleRegistry

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
REVIEW_PENDING = "CSA_ARCHITECT_REVIEW_PENDING"


class FrameworkPackValidator:
    """Validate content integrity and rule mapping provenance."""

    def __init__(self, rule_registry: RuleRegistry | None = None) -> None:
        """Create a validator with an optional CSA rule registry."""

        self.rule_registry = rule_registry

    def validate(self, pack: FrameworkPack, require_reviewed: bool = False) -> list[str]:
        """Return all pack validation errors."""

        errors: list[str] = []
        if pack.schema_version != "1.0":
            errors.append(f"Unsupported framework schema version: {pack.schema_version}")
        if require_reviewed and pack.status != PackStatus.ACTIVE:
            errors.append(f"Release validation requires ACTIVE pack status, got {pack.status.value}")
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
        errors.extend(f"Missing required field: {name}" for name, value in required.items() if not value)
        if not SHA256_PATTERN.fullmatch(pack.content_hash_sha256):
            errors.append("contentHashSha256 must be a lowercase SHA-256 digest")
        if pack.source.digest_sha256 and not SHA256_PATTERN.fullmatch(pack.source.digest_sha256):
            errors.append("source.digestSha256 must be a lowercase SHA-256 digest")
        if pack.status == PackStatus.ARCHIVED and not pack.deprecated:
            errors.append("Archived packs must be marked deprecated")

        control_ids = [control.control_id for control in pack.controls]
        errors.extend(
            f"Duplicate control ID: {control_id}"
            for control_id, count in Counter(control_ids).items()
            if count > 1
        )
        for control in pack.controls:
            if not control.control_id or not control.title or not control.section:
                errors.append(f"Control has incomplete identity: {control.control_id or '<missing>'}")
            mapping_ids = [mapping.rule_id for mapping in control.mappings]
            errors.extend(
                f"Duplicate mapping {control.control_id} -> {rule_id}"
                for rule_id, count in Counter(mapping_ids).items()
                if count > 1
            )
            for mapping in control.mappings:
                errors.extend(self._validate_mapping(control.control_id, mapping, require_reviewed))
        return errors

    def _validate_mapping(
        self,
        control_id: str,
        mapping: RuleMapping,
        require_reviewed: bool,
    ) -> list[str]:
        """Validate one control mapping."""

        label = f"{control_id} -> {mapping.rule_id}"
        errors: list[str] = []
        if not mapping.rationale.strip():
            errors.append(f"Missing mapping rationale: {label}")
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
        return errors
