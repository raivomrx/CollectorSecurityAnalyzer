"""Enumerations used by the active validation engine."""

from enum import Enum


class ActiveValidationStatus(str, Enum):
    """Describe one validator execution outcome."""

    NOT_REQUESTED = "NOT_REQUESTED"
    PLANNED = "PLANNED"
    SKIPPED = "SKIPPED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    ACCESS_DENIED = "ACCESS_DENIED"
    BLOCKED_BY_SAFETY_POLICY = "BLOCKED_BY_SAFETY_POLICY"
    BLOCKED_BY_AUTHORIZATION = "BLOCKED_BY_AUTHORIZATION"
    PASSED = "PASSED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"
    TIMED_OUT = "TIMED_OUT"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"


class CorrelatedRuleStatus(str, Enum):
    """Describe correlation between passive and active results."""

    CONFIRMED_PASS = "CONFIRMED_PASS"
    CONFIRMED_FAIL = "CONFIRMED_FAIL"
    PASS_NOT_VALIDATED = "PASS_NOT_VALIDATED"
    FAIL_NOT_VALIDATED = "FAIL_NOT_VALIDATED"
    CONFIGURATION_RUNTIME_MISMATCH = "CONFIGURATION_RUNTIME_MISMATCH"
    ACTIVE_ONLY_PASS = "ACTIVE_ONLY_PASS"
    ACTIVE_ONLY_FAIL = "ACTIVE_ONLY_FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_EVALUATED = "NOT_EVALUATED"


class RiskLevel(str, Enum):
    """Describe the operational impact of a validator."""

    SAFE_READ_ONLY = "SAFE_READ_ONLY"
    LOW_IMPACT = "LOW_IMPACT"
    CONTROLLED_TEMPORARY_CHANGE = "CONTROLLED_TEMPORARY_CHANGE"
    RESTRICTED = "RESTRICTED"
    PROHIBITED = "PROHIBITED"


class ValidatorStatus(str, Enum):
    """Describe registry lifecycle status for a validator."""

    DRAFT = "DRAFT"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    DISABLED = "DISABLED"


class CredentialExposureStatus(str, Enum):
    """Reserve safe credential-exposure indicator outcomes."""

    NOT_TESTED = "NOT_TESTED"
    TEST_NOT_AUTHORIZED = "TEST_NOT_AUTHORIZED"
    TEST_PROHIBITED_BY_POLICY = "TEST_PROHIBITED_BY_POLICY"
    EXPOSURE_NOT_OBSERVED = "EXPOSURE_NOT_OBSERVED"
    EXPOSURE_INDICATOR_OBSERVED = "EXPOSURE_INDICATOR_OBSERVED"
    INCONCLUSIVE = "INCONCLUSIVE"


class ResponderExposureStatus(str, Enum):
    """Describe a credential-relay attack surface assessment."""

    NOT_TESTED = "NOT_TESTED"
    EXPOSURE_CONFIRMED = "EXPOSURE_CONFIRMED"
    EXPOSURE_LIKELY = "EXPOSURE_LIKELY"
    EXPOSURE_PARTIALLY_MITIGATED = "EXPOSURE_PARTIALLY_MITIGATED"
    EXPOSURE_NOT_OBSERVED = "EXPOSURE_NOT_OBSERVED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"
    ERROR = "ERROR"


class ResponderRiskLevel(str, Enum):
    """Describe aggregate Responder-style attack surface risk."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    UNKNOWN = "UNKNOWN"
