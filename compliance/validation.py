"""Validation for compliance definitions."""

from __future__ import annotations

from compliance.enums import CompositeMode, EvidenceOperator, EvidenceSourceType, FrameworkType
from compliance.exceptions import ComplianceDefinitionError
from compliance.models import ComplianceProfile, FrameworkDefinition, RuleControlMapping


class ComplianceDefinitionValidator:
    """Validate framework, profile, and mapping definitions."""

    def validate_framework(self, framework: FrameworkDefinition) -> None:
        """Validate one framework definition."""

        if not framework.version:
            raise ComplianceDefinitionError(f"Framework version missing: {framework.framework_id}")
        seen: set[str] = set()
        controls = {control.control_id: control for control in framework.controls}
        for control in framework.controls:
            if control.control_id in seen:
                raise ComplianceDefinitionError(f"Duplicate control ID: {control.control_id}")
            seen.add(control.control_id)
            if control.parent_control_id and control.parent_control_id not in controls:
                raise ComplianceDefinitionError(f"Missing parent control: {control.parent_control_id}")
            self.validate_control_sources(control.evidence_requirements)
        if framework.framework_type == FrameworkType.MICROSOFT_BASELINE:
            metadata = framework.metadata
            for name in ("product", "os", "device_role"):
                if not metadata.get(name):
                    raise ComplianceDefinitionError(f"Microsoft baseline metadata missing: {name}")
        if not framework.official_version or not framework.snapshot_version:
            raise ComplianceDefinitionError(f"Framework snapshot metadata missing: {framework.framework_id}")

    def validate_control_sources(self, requirements) -> None:
        """Validate evidence source and operators."""

        for requirement in requirements:
            EvidenceSourceType(requirement.source_type)
            try:
                EvidenceOperator(requirement.operator)
            except ValueError as error:
                raise ComplianceDefinitionError(f"Unknown evidence operator: {requirement.operator}") from error
            if requirement.weight <= 0:
                raise ComplianceDefinitionError(f"Invalid evidence weight: {requirement.evidence_id}")
            if requirement.extractor == "composite":
                mode = str(requirement.parameters.get("mode", "AND")).upper()
                try:
                    CompositeMode(mode)
                except ValueError as error:
                    raise ComplianceDefinitionError(f"Unknown composite mode: {mode}") from error
                children = requirement.parameters.get("requirements", [])
                if not isinstance(children, list):
                    raise ComplianceDefinitionError(f"Composite requirements invalid: {requirement.evidence_id}")
                for child in children:
                    source_type = child.get("sourceType") if isinstance(child, dict) else None
                    if source_type == EvidenceSourceType.MANUAL_ATTESTATION.value:
                        continue
                    if source_type not in {
                        EvidenceSourceType.FINDING.value,
                        EvidenceSourceType.RAW_FIELD.value,
                    }:
                        raise ComplianceDefinitionError(f"Unsupported composite child source: {source_type}")
                    if child.get("extractor") == "composite":
                        raise ComplianceDefinitionError("Nested composite evidence is not supported")

    def validate_profile(self, profile: ComplianceProfile, frameworks: dict[tuple[str, str], FrameworkDefinition]) -> None:
        """Validate one profile against loaded frameworks."""

        if not profile.version:
            raise ComplianceDefinitionError(f"Profile version missing: {profile.profile_id}")
        for framework_id, version in profile.framework_versions.items():
            framework = frameworks.get((framework_id, version))
            if framework is None:
                raise ComplianceDefinitionError(f"Profile references unknown framework version: {framework_id} {version}")
            if framework.framework_type == FrameworkType.MICROSOFT_BASELINE and not profile.operating_system_patterns:
                raise ComplianceDefinitionError(f"Microsoft baseline profile OS patterns missing: {profile.profile_id}")
            self._validate_profile_controls(profile, framework)

    def _validate_profile_controls(self, profile: ComplianceProfile, framework: FrameworkDefinition) -> None:
        """Validate enabled and excluded control references for one framework."""

        known = {control.control_id for control in framework.controls}
        enabled = set(profile.enabled_controls.get(framework.framework_id, []))
        excluded = set(profile.excluded_controls.get(framework.framework_id, []))
        overlap = enabled & excluded
        if overlap:
            raise ComplianceDefinitionError(f"Control both enabled and excluded: {sorted(overlap)[0]}")
        for control_id in enabled | excluded:
            if control_id not in known:
                raise ComplianceDefinitionError(f"Profile references unknown control: {control_id}")

    def validate_mapping(
        self,
        mapping: RuleControlMapping,
        known_rules: set[str] | None = None,
        frameworks: dict[tuple[str, str], FrameworkDefinition] | None = None,
    ) -> None:
        """Validate one rule-control mapping."""

        if known_rules is not None and mapping.rule_id not in known_rules:
            raise ComplianceDefinitionError(f"Mapping references unknown rule: {mapping.rule_id}")
        if frameworks is not None:
            framework = frameworks.get((mapping.framework_id, mapping.framework_version))
            if framework is None:
                raise ComplianceDefinitionError(
                    f"Mapping references unknown framework version: {mapping.framework_id} {mapping.framework_version}"
                )
            known_controls = {control.control_id for control in framework.controls}
            for control_id in mapping.control_ids:
                if control_id not in known_controls:
                    raise ComplianceDefinitionError(f"Mapping references unknown control: {control_id}")
        if not 0 <= mapping.confidence <= 100:
            raise ComplianceDefinitionError(f"Mapping confidence out of range: {mapping.rule_id}")
        if not mapping.mapping_source or not mapping.mapping_author or not mapping.mapping_version:
            raise ComplianceDefinitionError(f"Mapping audit metadata missing: {mapping.rule_id}")
