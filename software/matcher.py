"""Software matching helpers for aliases and future CPE mapping."""

from __future__ import annotations

from software.models import SoftwareProduct


def is_same_software(left: SoftwareProduct, right: SoftwareProduct) -> bool:
    """Return whether two products refer to the same normalized software."""

    return (
        left.normalized_vendor == right.normalized_vendor
        and left.normalized_product == right.normalized_product
        and left.normalized_version == right.normalized_version
    )
