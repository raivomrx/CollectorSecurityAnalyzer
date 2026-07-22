"""Enums shared by framework content-pack services."""

from enum import Enum


class FrameworkControlLevel(str, Enum):
    """Describe the evidence scope of a framework control."""

    TECHNICAL = "TECHNICAL"
    PROCEDURAL = "PROCEDURAL"
    ORGANIZATIONAL = "ORGANIZATIONAL"
    MIXED = "MIXED"


class AutomationCapability(str, Enum):
    """Describe how completely CSA can assess a control."""

    AUTOMATED = "AUTOMATED"
    PARTIAL = "PARTIAL"
    MANUAL = "MANUAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class MappingStrength(str, Enum):
    """Describe how strongly a CSA rule relates to a control."""

    DIRECT = "DIRECT"
    SUPPORTING = "SUPPORTING"
    CONTEXTUAL = "CONTEXTUAL"


class MappingStatus(str, Enum):
    """Describe the review lifecycle of a mapping."""

    VALIDATED = "VALIDATED"
    PROVISIONAL = "PROVISIONAL"
    DEPRECATED = "DEPRECATED"


class FrameworkControlStatus(str, Enum):
    """Describe the conservative endpoint assessment result."""

    SATISFIED = "SATISFIED"
    NOT_SATISFIED = "NOT_SATISFIED"
    PARTIALLY_SATISFIED = "PARTIALLY_SATISFIED"
    NOT_ASSESSABLE = "NOT_ASSESSABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_EVALUATED = "NOT_EVALUATED"


class PackStatus(str, Enum):
    """Describe a framework pack release lifecycle."""

    ACTIVE = "ACTIVE"
    DRAFT = "DRAFT"
    DEPRECATED = "DEPRECATED"
    ARCHIVED = "ARCHIVED"
