"""Software Intelligence Engine data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
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


@dataclass(slots=True)
class SoftwareInventory:
    """Represent analyzed software inventory summary."""

    products: list[SoftwareProduct] = field(default_factory=list)
    product_count: int = 0
    vendor_count: int = 0
    duplicate_entries: list[SoftwareProduct] = field(default_factory=list)
    outdated_versions: list[SoftwareProduct] = field(default_factory=list)
    unknown_products: list[SoftwareProduct] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class NormalizationResult:
    """Represent normalized text with confidence and match reason."""

    value: str
    confidence: int
    reason: str
