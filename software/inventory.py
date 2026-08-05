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
    collection_status: str = "SUCCESS",
    collection_errors: Iterable[str] = (),
) -> SoftwareInventory:
    """Build a normalized software inventory from raw items."""

    collected = [
        item
        if isinstance(item, SoftwareProduct)
        else _from_mapping(item, unknown_products_path)
        for item in items
    ]
    duplicate_entries = _find_duplicates(collected)
    products = _deduplicate(collected)
    vendor_count = len(
        {
            product.normalized_vendor
            for product in products
            if product.normalized_vendor
        }
    )
    unknown_products = [product for product in products if product.confidence < 95]

    return SoftwareInventory(
        products=products,
        product_count=len(products),
        vendor_count=vendor_count,
        duplicate_entries=duplicate_entries,
        outdated_versions=[],
        unknown_products=unknown_products,
        collection_status=collection_status,
        collection_errors=[str(item) for item in collection_errors],
        raw_record_count=len(collected),
    )


def _from_mapping(
    item: Mapping[str, Any],
    unknown_products_path: str | Path,
) -> SoftwareProduct:
    """Create a normalized software product from a mapping."""

    return normalize_software(
        vendor=item.get(
            "publisher",
            item.get(
                "Publisher",
                item.get("vendor", item.get("Vendor", "")),
            ),
        ),
        product=item.get(
            "displayName",
            item.get(
                "DisplayName",
                item.get(
                    "product",
                    item.get("Product", item.get("name", "")),
                ),
            ),
        ),
        version=item.get(
            "displayVersion",
            item.get(
                "DisplayVersion",
                item.get("version", item.get("Version", "")),
            ),
        ),
        architecture=item.get("architecture", item.get("Architecture")),
        install_date=item.get("install_date", item.get("InstallDate")),
        install_location=item.get("installLocation", item.get("InstallLocation")),
        scope=str(item.get("scope", item.get("Scope", "UNKNOWN"))),
        source=str(item.get("source", item.get("Source", "UNKNOWN"))),
        uninstall_key=item.get("uninstallKey", item.get("UninstallKey")),
        unknown_products_path=unknown_products_path,
    )


def _find_duplicates(products: list[SoftwareProduct]) -> list[SoftwareProduct]:
    """Return products with duplicate normalized vendor/product/version keys."""

    keys = [
        (
            product.normalized_vendor,
            product.normalized_product,
            product.normalized_version,
            product.architecture,
            product.scope,
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
                product.architecture,
                product.scope,
            )
        ]
        > 1
    ]


def _deduplicate(products: list[SoftwareProduct]) -> list[SoftwareProduct]:
    """Keep the first product for each normalized package identity."""

    seen: set[tuple[str, str, str, str | None, str]] = set()
    result: list[SoftwareProduct] = []
    for product in products:
        key = (
            product.normalized_vendor,
            product.normalized_product,
            product.normalized_version,
            product.architecture,
            product.scope,
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(product)
    return result
