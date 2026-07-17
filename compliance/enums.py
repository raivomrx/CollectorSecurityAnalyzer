"""Compliance engine enumerations."""

from __future__ import annotations

from enum import Enum


class FrameworkType(str, Enum):
    """Supported compliance framework types."""

    EITS = "EITS"
    CIS_CONTROLS = "CIS_CONTROLS"
    MICROSOFT_BASELINE = "MICROSOFT_BASELINE"
    CUSTOM_POLICY = "CUSTOM_POLICY"


class ComplianceStatus(str, Enum):
    """Compliance assessment statuses."""

    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    PARTIALLY_COMPLIANT = "PARTIALLY_COMPLIANT"
    NOT_ASSESSED = "NOT_ASSESSED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    MANUAL_REVIEW = "MANUAL_REVIEW"


class EvidenceResult(str, Enum):
    """Evidence evaluation results."""

    SUPPORTS = "SUPPORTS"
    CONTRADICTS = "CONTRADICTS"
    INCONCLUSIVE = "INCONCLUSIVE"
    MISSING = "MISSING"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class EvidenceSourceType(str, Enum):
    """Supported evidence source types."""

    FINDING = "FINDING"
    RAW_FIELD = "RAW_FIELD"
    RULE_METADATA = "RULE_METADATA"
    SOFTWARE_INVENTORY = "SOFTWARE_INVENTORY"
    CVE_RESULT = "CVE_RESULT"
    MANUAL_ATTESTATION = "MANUAL_ATTESTATION"
    EXTERNAL_SYSTEM = "EXTERNAL_SYSTEM"


class RequirementLevel(str, Enum):
    """Requirement strength."""

    MUST = "MUST"
    SHOULD = "SHOULD"
    MAY = "MAY"
    INFORMATIONAL = "INFORMATIONAL"


class AssessmentScope(str, Enum):
    """Assessment scope."""

    ENDPOINT = "ENDPOINT"
    SERVER = "SERVER"
    ORGANISATION = "ORGANISATION"
    IDENTITY = "IDENTITY"
    NETWORK = "NETWORK"
    CLOUD = "CLOUD"
    APPLICATION = "APPLICATION"
    OT = "OT"


class MappingRelationship(str, Enum):
    """Relationship between CSA rules and controls."""

    SUPPORTS = "SUPPORTS"
    CONTRADICTS = "CONTRADICTS"
    PARTIAL = "PARTIAL"
    CONTEXT_ONLY = "CONTEXT_ONLY"


class EvidenceOperator(str, Enum):
    """Supported evidence operators."""

    EQUALS = "EQUALS"
    NOT_EQUALS = "NOT_EQUALS"
    IN = "IN"
    NOT_IN = "NOT_IN"
    CONTAINS = "CONTAINS"
    NOT_CONTAINS = "NOT_CONTAINS"
    EXISTS = "EXISTS"
    NOT_EXISTS = "NOT_EXISTS"
    GREATER_THAN = "GREATER_THAN"
    GREATER_OR_EQUAL = "GREATER_OR_EQUAL"
    LESS_THAN = "LESS_THAN"
    LESS_OR_EQUAL = "LESS_OR_EQUAL"
    STATUS_IS = "STATUS_IS"
    SEVERITY_AT_LEAST = "SEVERITY_AT_LEAST"
