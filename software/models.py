"""Software Intelligence Engine data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum
from functools import total_ordering


@total_ordering
@dataclass(frozen=True, slots=True)
class ParsedVersion:
    """Represent a normalized, comparable software version."""

    original: str
    parts: tuple[int, ...]
    normalized: str

    def __lt__(self, other: object) -> bool:
        """Compare versions by numeric parts with zero padding."""

        if not isinstance(other, ParsedVersion):
            return NotImplemented
        max_length = max(len(self.parts), len(other.parts))
        left = self.parts + (0,) * (max_length - len(self.parts))
        right = other.parts + (0,) * (max_length - len(other.parts))
        return left < right

    def __eq__(self, other: object) -> bool:
        """Return whether two versions have equal numeric parts."""

        if not isinstance(other, ParsedVersion):
            return NotImplemented
        max_length = max(len(self.parts), len(other.parts))
        left = self.parts + (0,) * (max_length - len(self.parts))
        right = other.parts + (0,) * (max_length - len(other.parts))
        return left == right


@dataclass(slots=True)
class SoftwareProduct:
    """Represent one installed software product."""

    vendor: str
    product: str
    version: str
    normalized_vendor: str
    normalized_product: str
    normalized_version: str
    architecture: str | None = None
    install_date: datetime | None = None
    cpe: str | None = None
    confidence: int = 0
    install_location: str | None = None
    scope: str = "UNKNOWN"
    source: str = "UNKNOWN"
    uninstall_key: str | None = None
    normalization_status: str = "NOT_EVALUATED"
    discovery_eligible: bool = False
    identity_source: str = "UNKNOWN"


@dataclass(slots=True)
class SoftwareInventory:
    """Represent analyzed software inventory summary."""

    products: list[SoftwareProduct] = field(default_factory=list)
    product_count: int = 0
    vendor_count: int = 0
    duplicate_entries: list[SoftwareProduct] = field(default_factory=list)
    outdated_versions: list[SoftwareProduct] = field(default_factory=list)
    unknown_products: list[SoftwareProduct] = field(default_factory=list)
    collection_status: str = "SUCCESS"
    collection_errors: list[str] = field(default_factory=list)
    raw_record_count: int = 0


class LifecycleStatus(str, Enum):
    """Supported software lifecycle assessment states."""

    SUPPORTED = "SUPPORTED"
    OUT_OF_SUPPORT = "OUT_OF_SUPPORT"
    NEARING_END_OF_SUPPORT = "NEARING_END_OF_SUPPORT"
    NOT_EVALUATED = "NOT_EVALUATED"
    UNKNOWN_VERSION = "UNKNOWN_VERSION"


@dataclass(slots=True, frozen=True)
class LifecycleResult:
    """Represent a source-backed lifecycle decision for one product."""

    vendor: str
    product: str
    installed_version: str
    status: LifecycleStatus
    end_of_support_date: date | None
    source: str | None
    data_version: str
    confidence: int
    rationale: str


@dataclass(frozen=True, slots=True)
class NormalizationResult:
    """Represent normalized text with confidence and match reason."""

    value: str
    confidence: int
    reason: str
