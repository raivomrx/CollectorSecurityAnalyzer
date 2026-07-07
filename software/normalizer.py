"""Vendor and product normalization for software inventory."""

from __future__ import annotations

import json
import logging
import re
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

from utils import parse_date
from software.models import NormalizationResult, SoftwareProduct
from software.version import normalize_version

LOGGER = logging.getLogger(__name__)
SOFTWARE_DIR = Path(__file__).resolve().parent
DEFAULT_VENDOR_ALIASES_PATH = SOFTWARE_DIR / "vendor_aliases.json"
DEFAULT_PRODUCT_ALIASES_PATH = SOFTWARE_DIR / "product_aliases.json"
DEFAULT_UNKNOWN_PRODUCTS_PATH = SOFTWARE_DIR / "unknown_products.json"
FUZZY_THRESHOLD = 0.88


def normalize_vendor(
    vendor: Any,
    aliases_path: str | Path = DEFAULT_VENDOR_ALIASES_PATH,
) -> NormalizationResult:
    """Normalize a software vendor name."""

    text = _clean_text(vendor)
    aliases = _load_aliases(aliases_path)
    result = _match_alias(text, aliases)
    if result is not None:
        return result
    return NormalizationResult(value=text, confidence=0, reason="unknown")


def normalize_product(
    product: Any,
    aliases_path: str | Path = DEFAULT_PRODUCT_ALIASES_PATH,
) -> NormalizationResult:
    """Normalize a software product name."""

    text = _clean_text(product)
    aliases = _load_aliases(aliases_path)
    result = _match_alias(text, aliases)
    if result is not None:
        return result

    cleaned = _remove_architecture_suffix(text)
    if cleaned != text:
        cleaned_result = _match_alias(cleaned, aliases)
        if cleaned_result is not None:
            return NormalizationResult(
                value=cleaned_result.value,
                confidence=min(cleaned_result.confidence, 95),
                reason="fuzzy",
            )
        return NormalizationResult(value=cleaned, confidence=0, reason="unknown")

    return NormalizationResult(value=text, confidence=0, reason="unknown")


def normalize_software(
    vendor: Any,
    product: Any,
    version: Any,
    architecture: str | None = None,
    install_date: Any = None,
    unknown_products_path: str | Path = DEFAULT_UNKNOWN_PRODUCTS_PATH,
) -> SoftwareProduct:
    """Build a normalized SoftwareProduct from raw inventory values."""

    vendor_result = normalize_vendor(vendor)
    product_result = normalize_product(product)
    confidence = _calculate_confidence(vendor_result, product_result)
    software = SoftwareProduct(
        vendor=_clean_text(vendor),
        product=_clean_text(product),
        version="" if version is None else str(version).strip(),
        normalized_vendor=vendor_result.value,
        normalized_product=product_result.value,
        normalized_version=normalize_version(version),
        architecture=architecture,
        install_date=parse_date(install_date),
        cpe=None,
        confidence=confidence,
    )

    if product_result.confidence == 0:
        log_unknown_product(software, unknown_products_path)

    return software


def log_unknown_product(
    software: SoftwareProduct,
    path: str | Path = DEFAULT_UNKNOWN_PRODUCTS_PATH,
) -> None:
    """Persist an unknown software product for future alias curation."""

    unknown_path = Path(path)
    unknown_path.parent.mkdir(parents=True, exist_ok=True)
    entries = _read_unknown_entries(unknown_path)
    entry = {
        "vendor": software.vendor,
        "product": software.product,
        "version": software.version,
    }
    if entry not in entries:
        entries.append(entry)
        unknown_path.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    LOGGER.info("Unknown software product detected: %s", software.product)


def _calculate_confidence(
    vendor_result: NormalizationResult,
    product_result: NormalizationResult,
) -> int:
    """Calculate software normalization confidence."""

    if vendor_result.confidence >= 95 and product_result.confidence == 100:
        return 100
    if vendor_result.confidence >= 95 and product_result.confidence >= 95:
        return 95
    if vendor_result.confidence >= 95:
        return 60
    return 0


def _load_aliases(path: str | Path) -> dict[str, str]:
    """Load aliases from a JSON file."""

    alias_path = Path(path)
    try:
        with alias_path.open("r", encoding="utf-8") as handle:
            aliases = json.load(handle)
    except FileNotFoundError:
        LOGGER.warning("Alias file not found: %s", alias_path)
        return {}
    except json.JSONDecodeError:
        LOGGER.exception("Alias file contains invalid JSON: %s", alias_path)
        raise

    if not isinstance(aliases, dict):
        raise ValueError(f"Alias file must contain a JSON object: {alias_path}")
    return {str(key): str(value) for key, value in aliases.items()}


def _match_alias(text: str, aliases: dict[str, str]) -> NormalizationResult | None:
    """Match raw text to an alias by exact or fuzzy comparison."""

    normalized_text = _key(text)
    keyed_aliases = {_key(alias): canonical for alias, canonical in aliases.items()}
    if normalized_text in keyed_aliases:
        return NormalizationResult(
            value=keyed_aliases[normalized_text],
            confidence=100,
            reason="exact",
        )

    best_key = ""
    best_score = 0.0
    for alias_key in keyed_aliases:
        score = SequenceMatcher(None, normalized_text, alias_key).ratio()
        if score > best_score:
            best_key = alias_key
            best_score = score

    if best_score >= FUZZY_THRESHOLD:
        return NormalizationResult(
            value=keyed_aliases[best_key],
            confidence=95,
            reason="fuzzy",
        )
    return None


def _remove_architecture_suffix(value: str) -> str:
    """Remove common architecture suffixes from product names."""

    return re.sub(r"\s*\((?:32|64)-bit\)\s*$", "", value, flags=re.IGNORECASE).strip()


def _clean_text(value: Any) -> str:
    """Clean text values for normalization."""

    return re.sub(r"\s+", " ", "" if value is None else str(value)).strip()


def _key(value: str) -> str:
    """Return a case-insensitive matching key."""

    return _clean_text(value).casefold()


def _read_unknown_entries(path: Path) -> list[dict[str, str]]:
    """Read unknown product entries from disk."""

    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        LOGGER.warning("Unknown products file is invalid, recreating: %s", path)
        return []
    if not isinstance(data, list):
        return []
    return [entry for entry in data if isinstance(entry, dict)]
