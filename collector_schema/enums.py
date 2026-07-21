"""Collector schema enumerations."""

from __future__ import annotations

from enum import Enum


class CollectionStatus(str, Enum):
    """Supported collector item statuses."""

    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    ACCESS_DENIED = "ACCESS_DENIED"
    NOT_AVAILABLE = "NOT_AVAILABLE"


class ConfigurationSource(str, Enum):
    """Supported configuration value sources."""

    LOCAL_POLICY = "LOCAL_POLICY"
    GROUP_POLICY = "GROUP_POLICY"
    MDM_POLICY = "MDM_POLICY"
    REGISTRY = "REGISTRY"
    DEFAULT = "DEFAULT"
    RUNTIME_STATE = "RUNTIME_STATE"
    SECURITY_PRODUCT = "SECURITY_PRODUCT"
    UNKNOWN = "UNKNOWN"


class UserClassification(str, Enum):
    """Supported local account classifications."""

    LOCAL = "LOCAL"
    DOMAIN = "DOMAIN"
    ENTRA = "ENTRA"
    SERVICE = "SERVICE"
    UNKNOWN = "UNKNOWN"


class PrivacyMode(str, Enum):
    """Supported report privacy modes."""

    STANDARD = "standard"
    STRICT = "strict"
