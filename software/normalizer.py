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
from software.version import compare_versions, normalize_version

LOGGER = logging.getLogger(__name__)
SOFTWARE_DIR = Path(__file__).resolve().parent
DEFAULT_VENDOR_ALIASES_PATH = SOFTWARE_DIR / "vendor_aliases.json"
DEFAULT_PRODUCT_ALIASES_PATH = SOFTWARE_DIR / "product_aliases.json"
DEFAULT_UNKNOWN_PRODUCTS_PATH = SOFTWARE_DIR / "unknown_products.json"
FUZZY_THRESHOLD = 0.88
NORMALIZATION_SCHEMA_VERSION = "software-identity-2.0"
PRODUCT_PATTERNS = (
    (r"^adobe illustrator(?:\s+\d{4})?\b", "Adobe Illustrator"),
    (r"^adobe premiere pro(?:\s+\d{4})?\b", "Adobe Premiere Pro"),
    (r"^adobe lightroom classic\b", "Adobe Lightroom Classic"),
    (r"^vlc media player\b", "VLC media player"),
    (r"^irfanview(?:\s+[\d.]+)?\b", "IrfanView"),
    (r"^xampp\b", "XAMPP"),
    (r"^microsoft \.net (?:runtime|sdk|host|desktop runtime)\b", ".NET"),
    (r"^mozilla firefox\b", "Mozilla Firefox"),
    (r"^7-zip\b", "7-Zip"),
    (r"^teamviewer\b", "TeamViewer"),
    (r"^anydesk\b", "AnyDesk"),
    (r"^forticlient\b", "FortiClient"),
    (r"^java 8(?: update)?\b", "Java 8"),
    (r"^microsoft edge webview2 runtime\b", "Microsoft Edge WebView2 Runtime"),
    (r"^microsoft edge(?:\s+[\d.]+)?$", "Microsoft Edge"),
    (r"^google chrome\b", "Google Chrome"),
    (r"^malwarebytes(?:\s+version)?(?:\s+[\d.]+)?\b", "Malwarebytes"),
)
DISCOVERY_EXCLUSIONS = (
    r"^windows driver package\b",
    r"\b(?:additional|minimum) runtime\b",
    r"\bredistributable\b",
    r"\b(?:update helper|meeting add-in)\b",
)


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
    *,
    version: Any = None,
) -> NormalizationResult:
    """Normalize a software product name."""

    text = _clean_text(product)
    aliases = _load_aliases(aliases_path)
    visual_cpp = _visual_cpp_result(text, version)
    if visual_cpp is not None:
        return visual_cpp
    exact_result = _match_exact_alias(text, aliases)
    if exact_result is not None:
        return _guarded_exact_result(text, exact_result, version)
    if re.search(r"\b(?:helper|updater|update helper|add-in)\b", text, re.IGNORECASE):
        return NormalizationResult(
            value=text,
            confidence=0,
            reason="component_identity_required",
            trace={
                "schemaVersion": NORMALIZATION_SCHEMA_VERSION,
                "candidate": None,
                "positiveEvidence": [],
                "guardrailRejections": [
                    "Component role must remain distinct from the parent product"
                ],
                "finalConfidence": 0,
            },
        )
    cleaned = _canonical_display_name(text, version)
    cleaned_exact = _match_exact_alias(cleaned, aliases)
    if cleaned_exact is not None:
        guarded = _guarded_exact_result(text, cleaned_exact, version)
        if guarded.confidence:
            return NormalizationResult(
                value=guarded.value,
                confidence=95,
                reason="display_name_canonicalized",
                trace={**guarded.trace, "finalConfidence": 95},
            )
        return guarded
    pattern_result = _match_product_pattern(cleaned)
    if pattern_result is not None:
        return pattern_result
    result = _match_alias(
        cleaned,
        aliases,
        identity_guard=True,
        version=version,
    )
    if result is not None:
        return result
    return NormalizationResult(
        value=cleaned,
        confidence=0,
        reason="unknown",
        trace={
            "schemaVersion": NORMALIZATION_SCHEMA_VERSION,
            "candidate": None,
            "positiveEvidence": [],
            "guardrailRejections": [],
            "finalConfidence": 0,
        },
    )


def normalize_software(
    vendor: Any,
    product: Any,
    version: Any,
    architecture: str | None = None,
    install_date: Any = None,
    install_location: str | None = None,
    scope: str = "UNKNOWN",
    source: str = "UNKNOWN",
    uninstall_key: str | None = None,
    unknown_products_path: str | Path = DEFAULT_UNKNOWN_PRODUCTS_PATH,
) -> SoftwareProduct:
    """Build a normalized SoftwareProduct from raw inventory values."""

    vendor_result = normalize_vendor(vendor)
    product_result = normalize_product(product, version=version)
    confidence = _calculate_confidence(vendor_result, product_result)
    discovery_eligible = _is_discovery_candidate(
        vendor_result,
        product_result,
        version,
    )
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
        install_location=install_location,
        scope=scope,
        source=source,
        uninstall_key=uninstall_key,
        normalization_status=(
            "NORMALIZED" if confidence >= 95 else
            "PARTIAL" if confidence >= 60 else
            "DISCOVERY_CANDIDATE" if discovery_eligible else
            "FAILED"
        ),
        discovery_eligible=discovery_eligible,
        identity_source=(
            "VALIDATED_ALIAS" if confidence >= 95 else
            "VENDOR_ALIAS" if confidence >= 60 else
            "RAW_DISCOVERY" if discovery_eligible else
            "UNKNOWN"
        ),
        normalization_trace={
            "schemaVersion": NORMALIZATION_SCHEMA_VERSION,
            "vendor": vendor_result.trace,
            "product": product_result.trace,
            "finalConfidence": confidence,
        },
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


def _is_discovery_candidate(
    vendor_result: NormalizationResult,
    product_result: NormalizationResult,
    version: Any,
) -> bool:
    """Return whether raw identity is safe enough for CPE discovery only."""

    if not vendor_result.value or not product_result.value:
        return False
    if not normalize_version(version):
        return False
    if vendor_result.confidence >= 95 and product_result.confidence >= 95:
        return False
    product = product_result.value.strip()
    if len(product) < 3:
        return False
    return not any(
        re.search(pattern, product, flags=re.IGNORECASE)
        for pattern in DISCOVERY_EXCLUSIONS
    )


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


def _match_alias(
    text: str,
    aliases: dict[str, str],
    *,
    identity_guard: bool = False,
    version: Any = None,
) -> NormalizationResult | None:
    """Match raw text to an alias by exact or fuzzy comparison."""

    normalized_text = _key(text)
    keyed_aliases = {_key(alias): canonical for alias, canonical in aliases.items()}
    if normalized_text in keyed_aliases:
        return NormalizationResult(
            value=keyed_aliases[normalized_text],
            confidence=100,
            reason="exact",
            trace=_normalization_trace(
                keyed_aliases[normalized_text],
                ["Exact alias match"],
                [],
                100,
            ),
        )

    best_key = ""
    best_score = 0.0
    rejected: list[str] = []
    for alias_key in keyed_aliases:
        score = SequenceMatcher(None, normalized_text, alias_key).ratio()
        if identity_guard and score >= FUZZY_THRESHOLD:
            allowed, reason = _product_identity_compatible(
                text,
                keyed_aliases[alias_key],
                version,
            )
            if not allowed:
                rejected.append(
                    f"{keyed_aliases[alias_key]} ({score:.3f}): {reason}"
                )
                continue
        if score > best_score:
            best_key = alias_key
            best_score = score

    if best_score >= FUZZY_THRESHOLD:
        return NormalizationResult(
            value=keyed_aliases[best_key],
            confidence=95,
            reason="fuzzy",
            trace=_normalization_trace(
                keyed_aliases[best_key],
                [f"Bounded fuzzy alias score {best_score:.3f}"],
                rejected,
                95,
            ),
        )
    if rejected:
        return NormalizationResult(
            value=text,
            confidence=0,
            reason="identity_guard_rejected",
            trace=_normalization_trace(None, [], rejected, 0),
        )
    return None


def _canonical_display_name(value: str, version: Any) -> str:
    """Remove only evidenced packaging, scope and installed-version suffixes."""

    cleaned = value
    suffix = r"\s*(?:\((?:32-bit(?: x86)?|64-bit(?: x64)?|x86|x64|arm64|user|machine|system)\)|\b(?:x86|x64|arm64)\b)\s*$"
    while True:
        reduced = re.sub(suffix, "", cleaned, flags=re.IGNORECASE).strip()
        if reduced == cleaned:
            break
        cleaned = reduced
    installed = str(version or "").strip()
    if installed and re.fullmatch(r"\d+(?:\.\d+)+", installed):
        embedded = re.search(r"\s+(\d+(?:\.\d+)+)$", cleaned)
        if embedded and compare_versions(embedded.group(1), installed) == 0:
            cleaned = cleaned[:embedded.start()].strip()
    return cleaned


def _match_product_pattern(value: str) -> NormalizationResult | None:
    """Match explicit product-family patterns used by registry display names."""

    for pattern, canonical in PRODUCT_PATTERNS:
        if re.search(pattern, value, flags=re.IGNORECASE):
            return NormalizationResult(
                value=canonical,
                confidence=95,
                reason="pattern",
                trace=_normalization_trace(
                    canonical,
                    [f"Validated product-family pattern: {pattern}"],
                    [],
                    95,
                ),
            )
    return None


def _match_exact_alias(
    text: str,
    aliases: dict[str, str],
) -> NormalizationResult | None:
    """Match an exact product alias without invoking fuzzy comparison."""

    keyed_aliases = {
        _key(alias): canonical for alias, canonical in aliases.items()
    }
    canonical = keyed_aliases.get(_key(text))
    if canonical is None:
        return None
    return NormalizationResult(
        value=canonical,
        confidence=100,
        reason="exact",
        trace=_normalization_trace(
            canonical,
            ["Exact product alias match"],
            [],
            100,
        ),
    )


def _guarded_exact_result(
    source: str,
    result: NormalizationResult,
    version: Any,
) -> NormalizationResult:
    """Apply material identity checks even to curated display-name aliases."""

    allowed, reason = _product_identity_compatible(
        source,
        result.value,
        version,
    )
    if allowed:
        return result
    return NormalizationResult(
        value=source,
        confidence=0,
        reason="identity_guard_rejected",
        trace=_normalization_trace(
            result.value,
            [],
            [f"{result.value}: {reason}"],
            0,
        ),
    )


def _visual_cpp_result(value: str, version: Any) -> NormalizationResult | None:
    """Normalize Visual C++ runtimes without crossing release generations."""

    match = re.search(
        r"^microsoft visual c\+\+\s+"
        r"(2015\s*[-–]\s*2022|2012|2013|2015|2017|2019|2022)\b",
        value,
        flags=re.IGNORECASE,
    )
    if match is None:
        return None
    generation = re.sub(r"\s+", "", match.group(1)).replace("–", "-")
    major = _version_major(version)
    expected = "11" if generation == "2012" else "12" if generation == "2013" else "14"
    canonical = f"Microsoft Visual C++ {generation} Redistributable"
    if major and major != expected:
        return NormalizationResult(
            value=value,
            confidence=0,
            reason="identity_guard_rejected",
            trace=_normalization_trace(
                canonical,
                [],
                [
                    f"Visual C++ {generation} expects version family "
                    f"{expected}.x, observed {major}.x"
                ],
                0,
            ),
        )
    evidence = [f"Display name identifies Visual C++ {generation}"]
    if major:
        evidence.append(f"Installed version family {major}.x matches")
    return NormalizationResult(
        value=canonical,
        confidence=95,
        reason="validated_generation_pattern",
        trace=_normalization_trace(canonical, evidence, [], 95),
    )


def _product_identity_compatible(
    source: str,
    candidate: str,
    version: Any,
) -> tuple[bool, str]:
    """Reject aliases that cross a material product identity boundary."""

    source_key = _key(source)
    candidate_key = _key(candidate)
    source_years = set(re.findall(r"\b(?:19|20)\d{2}\b", source_key))
    candidate_years = set(re.findall(r"\b(?:19|20)\d{2}\b", candidate_key))
    if source_years and candidate_years and source_years != candidate_years:
        return False, "Release year or generation differs"

    boundaries = (
        "webview2", "update helper", "updater", "meeting add-in",
        "graphics driver", "gpu display driver", "classic",
    )
    for boundary in boundaries:
        if (boundary in source_key) != (boundary in candidate_key):
            return False, f"Material component or edition differs: {boundary}"

    source_vc = re.search(r"visual c\+\+\s+((?:19|20)\d{2})", source_key)
    candidate_vc = re.search(
        r"visual c\+\+\s+((?:19|20)\d{2})",
        candidate_key,
    )
    if source_vc and candidate_vc and source_vc.group(1) != candidate_vc.group(1):
        return False, "Visual C++ release generation differs"
    if source_vc:
        expected = (
            "11" if source_vc.group(1) == "2012"
            else "12" if source_vc.group(1) == "2013"
            else "14"
        )
        major = _version_major(version)
        if major and major != expected:
            return False, (
                f"Visual C++ {source_vc.group(1)} expects {expected}.x, "
                f"observed {major}.x"
            )
    return True, "Identity-defining fields are compatible"


def _version_major(value: Any) -> str:
    """Return a numeric version major when one is available."""

    match = re.match(r"\s*(\d+)(?:\.|$)", str(value or ""))
    return match.group(1) if match else ""


def _normalization_trace(
    candidate: str | None,
    positive_evidence: list[str],
    rejections: list[str],
    confidence: int,
) -> dict[str, Any]:
    """Build a stable privacy-safe identity decision trace."""

    return {
        "schemaVersion": NORMALIZATION_SCHEMA_VERSION,
        "candidate": candidate,
        "positiveEvidence": positive_evidence,
        "guardrailRejections": rejections,
        "finalConfidence": confidence,
    }


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
