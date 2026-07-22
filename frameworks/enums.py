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


class ReviewMethod(str, Enum):
    """Describe how a mapping review decision was produced."""

    MANUAL_SOURCE_REVIEW = "MANUAL_SOURCE_REVIEW"
    PEER_REVIEW = "PEER_REVIEW"
    IMPORTED_UNREVIEWED = "IMPORTED_UNREVIEWED"
    MIGRATED_UNREVIEWED = "MIGRATED_UNREVIEWED"


class ReviewPendingReason(str, Enum):
    """Describe why a provisional mapping still needs human review."""

    SOURCE_VERSION_UNCONFIRMED = "SOURCE_VERSION_UNCONFIRMED"
    EXACT_CONTROL_REFERENCE_MISSING = "EXACT_CONTROL_REFERENCE_MISSING"
    REQUIRES_DOMAIN_EXPERT_REVIEW = "REQUIRES_DOMAIN_EXPERT_REVIEW"
    LICENSED_SOURCE_NOT_AVAILABLE = "LICENSED_SOURCE_NOT_AVAILABLE"
    MAPPING_STRENGTH_UNCONFIRMED = "MAPPING_STRENGTH_UNCONFIRMED"


class AssessmentMode(str, Enum):
    """Describe the maximum meaning of a framework evaluation."""

    FORMAL_ASSESSMENT = "FORMAL_ASSESSMENT"
    TRACEABILITY_ONLY = "TRACEABILITY_ONLY"


class EvaluationMode(str, Enum):
    """Describe how a pack was evaluated in one analyzer run."""

    FORMAL_ASSESSMENT = "FORMAL_ASSESSMENT"
    TRACEABILITY_ONLY = "TRACEABILITY_ONLY"


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
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    DRAFT = "DRAFT"
    DEPRECATED = "DEPRECATED"
    ARCHIVED = "ARCHIVED"
