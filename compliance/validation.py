"""Validation for compliance definitions."""

from __future__ import annotations

from compliance.enums import EvidenceOperator, EvidenceSourceType
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

    def validate_control_sources(self, requirements) -> None:
        """Validate evidence source and operators."""

        for requirement in requirements:
            EvidenceSourceType(requirement.source_type)
            try:
                EvidenceOperator(requirement.operator)
            except ValueError as error:
                raise ComplianceDefinitionError(f"Unknown evidence operator: {requirement.operator}") from error
            if requirement.weight < 0:
                raise ComplianceDefinitionError(f"Invalid evidence weight: {requirement.evidence_id}")

    def validate_profile(self, profile: ComplianceProfile, frameworks: dict[str, FrameworkDefinition]) -> None:
        """Validate one profile against loaded frameworks."""

        if not profile.version:
            raise ComplianceDefinitionError(f"Profile version missing: {profile.profile_id}")
        for framework_id, control_ids in profile.enabled_controls.items():
            framework = frameworks.get(framework_id)
            if framework is None:
                raise ComplianceDefinitionError(f"Profile references unknown framework: {framework_id}")
            known = {control.control_id for control in framework.controls}
            for control_id in control_ids:
                if control_id not in known:
                    raise ComplianceDefinitionError(f"Profile references unknown control: {control_id}")

    def validate_mapping(self, mapping: RuleControlMapping, known_rules: set[str] | None = None) -> None:
        """Validate one rule-control mapping."""

        if known_rules is not None and mapping.rule_id not in known_rules:
            raise ComplianceDefinitionError(f"Mapping references unknown rule: {mapping.rule_id}")
        if not 0 <= mapping.confidence <= 100:
            raise ComplianceDefinitionError(f"Mapping confidence out of range: {mapping.rule_id}")
        if not mapping.mapping_source or not mapping.mapping_author or not mapping.mapping_version:
            raise ComplianceDefinitionError(f"Mapping audit metadata missing: {mapping.rule_id}")
