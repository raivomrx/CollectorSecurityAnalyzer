"""Software inventory builder."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from software.models import SoftwareInventory, SoftwareProduct
from software.normalizer import DEFAULT_UNKNOWN_PRODUCTS_PATH, normalize_software


def build_inventory(
    items: Iterable[Mapping[str, Any] | SoftwareProduct],
    unknown_products_path: str | Path = DEFAULT_UNKNOWN_PRODUCTS_PATH,
) -> SoftwareInventory:
    """Build a normalized software inventory from raw items."""

    products = [
        item if isinstance(item, SoftwareProduct) else _from_mapping(item, unknown_products_path)
        for item in items
    ]
    vendor_count = len({product.normalized_vendor for product in products if product.normalized_vendor})
    duplicate_entries = _find_duplicates(products)
    unknown_products = [product for product in products if product.confidence < 95]

    return SoftwareInventory(
        products=products,
        product_count=len(products),
        vendor_count=vendor_count,
        duplicate_entries=duplicate_entries,
        outdated_versions=[],
        unknown_products=unknown_products,
    )


def _from_mapping(
    item: Mapping[str, Any],
    unknown_products_path: str | Path,
) -> SoftwareProduct:
    """Create a normalized software product from a mapping."""

    return normalize_software(
        vendor=item.get("vendor", item.get("Vendor", "")),
        product=item.get("product", item.get("Product", item.get("name", ""))),
        version=item.get("version", item.get("Version", "")),
        architecture=item.get("architecture", item.get("Architecture")),
        install_date=item.get("install_date", item.get("InstallDate")),
        unknown_products_path=unknown_products_path,
    )


def _find_duplicates(products: list[SoftwareProduct]) -> list[SoftwareProduct]:
    """Return products with duplicate normalized vendor/product/version keys."""

    keys = [
        (
            product.normalized_vendor,
            product.normalized_product,
            product.normalized_version,
        )
        for product in products
    ]
    counts = Counter(keys)
    return [
        product
        for product in products
        if counts[
            (
                product.normalized_vendor,
                product.normalized_product,
                product.normalized_version,
            )
        ]
        > 1
    ]
