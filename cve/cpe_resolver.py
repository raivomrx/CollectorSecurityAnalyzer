"""CPE resolution for normalized software products."""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

from cve.client import NvdClient
from cve.models import CpeCandidate, CpeMatchStatus
from software.models import SoftwareProduct
from software.version import compare_versions

LOGGER = logging.getLogger(__name__)
DEFAULT_MAPPING_PATH = Path(__file__).resolve().parent.parent / "software" / "cpe_mappings.json"


@dataclass(frozen=True, slots=True)
class ParsedCpe23:
    """Parsed CPE 2.3 well-formed name components."""

    part: str
    vendor: str
    product: str
    version: str
    update: str
    edition: str
    language: str
    sw_edition: str
    target_sw: str
    target_hw: str
    other: str


@dataclass(frozen=True, slots=True)
class CpeResolution:
    """Describe the candidate set and decision made by the resolver."""

    candidate: CpeCandidate | None
    candidate_count: int
    status: str
    reason: str | None = None
    trace: dict[str, Any] = field(default_factory=dict)


class CpeResolver:
    """Resolve software products to CPE 2.3 candidates."""

    def __init__(
        self,
        client: NvdClient | None = None,
        mapping_path: str | Path = DEFAULT_MAPPING_PATH,
        minimum_confidence: int = 80,
        ambiguous_score_difference: int = 5,
    ) -> None:
        """Create a resolver."""

        self.client = client
        self.mappings = _load_mappings(mapping_path)
        self.discovery_aliases = _load_mappings(DEFAULT_MAPPING_PATH.with_name("cpe_discovery_aliases.json"))
        self.metrics = {
            "localMappingSeconds": 0.0, "cpeDiscoverySeconds": 0.0,
            "resolutionMemoryHits": 0, "cpeCatalogHits": 0,
            "cpeCatalogMisses": 0, "remoteCpeQueries": 0,
        }
        self.minimum_confidence = minimum_confidence
        self.ambiguous_score_difference = ambiguous_score_difference
        self._resolution_cache: dict[str, CpeResolution] = {}

    def resolve(self, software: SoftwareProduct) -> CpeCandidate | None:
        """Resolve a software product to a CPE candidate."""

        return self.resolve_with_trace(software).candidate

    def resolve_with_trace(
        self,
        software: SoftwareProduct,
        raw_data: dict[str, Any] | None = None,
    ) -> CpeResolution:
        """Resolve a product and retain the candidate decision for audit."""

        operating_system = _collector_os(raw_data)
        cache_key = (
            f"{software.normalized_vendor}|{software.normalized_product}|"
            f"{software.normalized_version}|{operating_system}"
        ).casefold()
        cached = self._resolution_cache.get(cache_key)
        if cached is not None:
            self.metrics["resolutionMemoryHits"] += 1
            return cached

        started = time.perf_counter()
        local = self._resolve_local(software)
        self.metrics["localMappingSeconds"] += time.perf_counter() - started
        if local is not None:
            LOGGER.info(
                "CPE resolved: %s, confidence=%s, source=%s",
                software.normalized_product,
                local.confidence,
                local.source,
            )
            resolution = CpeResolution(local, 1, "SUCCESS")
            self._resolution_cache[cache_key] = resolution
            return resolution

        if self.client is None:
            resolution = CpeResolution(
                None,
                0,
                "NO_RELIABLE_MAPPING",
                "No validated local mapping and remote lookup is disabled",
            )
            self._resolution_cache[cache_key] = resolution
            return resolution
        trace: dict[str, Any] = {
            "normalizedVendor": software.normalized_vendor,
            "normalizedProduct": software.normalized_product,
            "displayName": software.product, "installedVersion": software.version,
            "queries": [], "topCandidates": [], "candidateCount": 0,
            "selectedCandidate": None, "terminalStatus": "ATTEMPTED",
        }
        started = time.perf_counter()
        try:
            candidates = self._resolve_nvd(software, trace)
        except Exception as error:
            trace["terminalStatus"] = "FAILED"
            trace["rejectionReason"] = "Remote CPE provider failed; see provider status"
            error.discovery_trace = trace
            raise
        finally:
            self.metrics["cpeDiscoverySeconds"] += time.perf_counter() - started
        if not candidates:
            resolution = CpeResolution(
                None,
                0,
                "NO_RELIABLE_MAPPING",
                "NVD candidates did not establish vendor, product and edition identity",
                trace,
            )
            trace.update(terminalStatus=resolution.status, rejectionReason=resolution.reason)
            self._resolution_cache[cache_key] = resolution
            return resolution
        versioned_candidates = candidates
        candidates = _collapse_equivalent_candidates(
            candidates,
            software.version,
        )
        trace["acceptedVersionRowCount"] = len(versioned_candidates)
        trace["canonicalFamilyCount"] = len(candidates)
        candidates.sort(key=lambda candidate: candidate.confidence, reverse=True)
        active = [candidate for candidate in candidates if not candidate.deprecated]
        platform_match = [
            item for item in active
            if operating_system and _target_sw(item) == operating_system
        ]
        generic = [item for item in active if _target_sw(item) == "*"]
        eligible = platform_match or generic
        if not eligible and active:
            reason = (
                "CPE platform is constrained but collector OS does not confirm it"
                if not operating_system else
                "CPE platform differs from the collected operating system"
            )
            trace.update(terminalStatus="NO_RELIABLE_MAPPING", rejectionReason=reason,
                         collectorOperatingSystem=operating_system)
            resolution = CpeResolution(None, len(active), "NO_RELIABLE_MAPPING", reason, trace)
            self._resolution_cache[cache_key] = resolution
            return resolution
        # Prefer an evidenced OS-specific family; otherwise avoid plugin/mobile variants.
        neutral = [item for item in eligible if _is_neutral_family(item)]
        ranked = platform_match or neutral or eligible or candidates
        trace["collectorOperatingSystem"] = operating_system
        best = ranked[0]
        if not active or best.confidence < self.minimum_confidence:
            resolution = CpeResolution(
                None,
                len(ranked),
                "NO_RELIABLE_MAPPING",
                "Only deprecated candidates were found" if not active else
                f"Best CPE confidence {best.confidence} is below {self.minimum_confidence}",
                trace,
            )
            trace.update(terminalStatus=resolution.status, rejectionReason=resolution.reason)
            self._resolution_cache[cache_key] = resolution
            return resolution
        if (
            len(ranked) > 1
            and best.confidence - ranked[1].confidence
            < self.ambiguous_score_difference
        ):
            best.match_status = CpeMatchStatus.AMBIGUOUS
            LOGGER.warning("Ambiguous CPE match for product: %s", software.product)
            resolution = CpeResolution(
                best,
                len(ranked),
                "AMBIGUOUS",
                "Top CPE candidates are too close to select reliably",
                trace,
            )
            trace.update(terminalStatus=resolution.status, rejectionReason=resolution.reason)
            self._resolution_cache[cache_key] = resolution
            return resolution
        selected = parse_cpe23_components(best.cpe_name)
        trace["installedVersionCatalogued"] = any(
            _same_cpe_family(selected, parse_cpe23_components(item.cpe_name))
            and _catalog_version_matches(software.version, item.version)
            for item in versioned_candidates
            if not item.deprecated
        )
        trace.update(terminalStatus="SUCCESS", selectedCandidate=best.cpe_name, rejectionReason=None)
        resolution = CpeResolution(best, len(ranked), "SUCCESS", trace=trace)
        self._resolution_cache[cache_key] = resolution
        return resolution

    def _resolve_local(self, software: SoftwareProduct) -> CpeCandidate | None:
        """Resolve using local audited mappings."""

        key = f"{software.normalized_vendor}|{software.normalized_product}".casefold()
        mapping = self.mappings.get(key)
        if not isinstance(mapping, dict):
            return None
        validated = bool(mapping.get("validated", False))
        confidence = int(mapping.get("confidence", 0))
        if not validated:
            confidence = min(confidence, 85)
        if confidence < self.minimum_confidence:
            return None
        version = None
        cpe_name = build_cpe23(
            part=str(mapping.get("part", "a")),
            vendor=str(mapping["vendor"]),
            product=str(mapping["product"]),
            version="*",
            update=str(mapping.get("update", "*")),
            edition=str(mapping.get("edition", "*")),
            language=str(mapping.get("language", "*")),
            sw_edition=str(mapping.get("sw_edition", "*")),
            target_sw=str(mapping.get("target_sw", "*")),
            target_hw=str(mapping.get("target_hw", "*")),
            other=str(mapping.get("other", "*")),
        )
        status = CpeMatchStatus.EXACT if validated and confidence >= 95 else CpeMatchStatus.ALIAS
        return CpeCandidate(
            cpe_name=cpe_name,
            title=f"{mapping['vendor']} {mapping['product']}",
            vendor=str(mapping["vendor"]),
            product=str(mapping["product"]),
            version=version,
            deprecated=False,
            confidence=confidence,
            match_status=status,
            source="LOCAL_MAPPING",
        )

    def _resolve_nvd(self, software: SoftwareProduct, trace: dict[str, Any]) -> list[CpeCandidate]:
        """Resolve one canonical family query against the persistent CPE catalog."""

        assert self.client is not None
        alias = self.discovery_aliases.get(
            f"{software.normalized_vendor}|{software.normalized_product}".casefold(), {}
        )
        query = str(alias.get("query") or software.normalized_product).strip()
        identity = f"{software.normalized_vendor}|{software.normalized_product}|{query}".casefold()
        catalog = getattr(getattr(self.client, "cache", None), "get_cpe_catalog", None)
        save = getattr(getattr(self.client, "cache", None), "set_cpe_catalog", None)
        candidates: list[CpeCandidate] = []
        seen: set[str] = set()
        attempt = {"query": query, "status": "ATTEMPTED", "candidateCount": 0}
        trace["queries"].append(attempt)
        products = catalog(identity) if callable(catalog) else None
        trace["catalogHit"] = products is not None
        if products is None:
            self.metrics["cpeCatalogMisses"] += 1
            self.metrics["remoteCpeQueries"] += 1
            products = self.client.get_cpes({"keywordSearch": query})
            if callable(save):
                snapshot = []
                for row in products:
                    cpe_data = row.get("cpe", row) if isinstance(row, dict) else None
                    if isinstance(cpe_data, dict):
                        snapshot.append({"cpe": {
                            key: value for key, value in cpe_data.items()
                            if key in {"cpeName", "titles", "deprecated"}
                        }})
                save(identity, snapshot)
        else:
            self.metrics["cpeCatalogHits"] += 1
        attempt.update(status="SUCCESS", candidateCount=len(products))
        for product in products:
            cpe = product.get("cpe", product) if isinstance(product, dict) else None
            if not isinstance(cpe, dict):
                continue
            cpe_name = str(cpe.get("cpeName", ""))
            if cpe_name in seen:
                continue
            seen.add(cpe_name)
            parsed = parse_cpe23_components(cpe_name)
            title = _read_title(cpe)
            confidence, reason = _identity_confidence(software, parsed, title, alias)
            diagnostic = {
                "cpe": cpe_name, "title": title,
                "vendor": parsed.vendor if parsed else "", "product": parsed.product if parsed else "",
                "edition": parsed.edition if parsed else "", "softwareEdition": parsed.sw_edition if parsed else "",
                "confidence": confidence, "deprecated": bool(cpe.get("deprecated", False)),
                "vendorIdentity": "CONFIRMED" if confidence >= 45 else "NOT_CONFIRMED",
                "productIdentity": "CONFIRMED" if reason is None else "NOT_CONFIRMED",
                "installedVersionAvailable": bool(
                    parsed and _catalog_version_matches(software.version, parsed.version)
                ),
                "rejectionReason": reason,
            }
            trace["topCandidates"].append(diagnostic)
            if parsed is None or reason:
                continue
            candidates.append(CpeCandidate(
                cpe_name=cpe_name, title=title, vendor=parsed.vendor, product=parsed.product,
                version=parsed.version if parsed.version not in {"*", "-"} else None,
                deprecated=diagnostic["deprecated"], confidence=confidence,
                match_status=_status_for_confidence(confidence), source="NVD_CPE_API",
            ))
        trace["candidateCount"] = len(seen)
        trace["topCandidates"] = sorted(
            trace["topCandidates"],
            key=lambda item: (
                -item["confidence"],
                -int(item["installedVersionAvailable"]),
                item["cpe"],
            ),
        )[:20]
        trace["aliasSource"] = alias.get("source")
        return candidates


def build_cpe23(
    part: str,
    vendor: str,
    product: str,
    version: str = "*",
    *,
    update: str = "*",
    edition: str = "*",
    language: str = "*",
    sw_edition: str = "*",
    target_sw: str = "*",
    target_hw: str = "*",
    other: str = "*",
) -> str:
    """Build a minimally safe CPE 2.3 well-formed name."""

    fields = [
        "cpe",
        "2.3",
        _escape(part),
        _escape(vendor),
        _escape(product),
        _escape(version),
        _escape(update),
        _escape(edition),
        _escape(language),
        _escape(sw_edition),
        _escape(target_sw),
        _escape(target_hw),
        _escape(other),
    ]
    return ":".join(fields)


def parse_cpe23(cpe_name: str) -> tuple[str, str, str | None]:
    """Parse vendor, product, and version from a CPE 2.3 name."""

    parsed = parse_cpe23_components(cpe_name)
    if parsed is None:
        return "", "", None
    return parsed.vendor, parsed.product, parsed.version


def parse_cpe23_components(cpe_name: str) -> ParsedCpe23 | None:
    """Parse a CPE 2.3 well-formed name into all 11 components."""

    parts = _split_cpe23(cpe_name)
    if parts is None or len(parts) != 13:
        return None
    if parts[0] != "cpe" or parts[1] != "2.3":
        return None

    values = [_unescape(part) for part in parts[2:]]
    return ParsedCpe23(
        part=values[0],
        vendor=values[1],
        product=values[2],
        version=values[3],
        update=values[4],
        edition=values[5],
        language=values[6],
        sw_edition=values[7],
        target_sw=values[8],
        target_hw=values[9],
        other=values[10],
    )


def replace_cpe23_version(cpe_name: str, version: str) -> str | None:
    """Return a CPE 2.3 name with its version component replaced safely."""

    parts = _split_cpe23(cpe_name)
    if parts is None or len(parts) != 13:
        return None
    if parts[0] != "cpe" or parts[1] != "2.3":
        return None
    cleaned_version = version.strip()
    if not cleaned_version:
        return None
    parts[5] = _escape(cleaned_version)
    return ":".join(parts)


def _split_cpe23(cpe_name: str) -> list[str] | None:
    """Split CPE fields on unescaped colons only."""

    parts: list[str] = []
    current: list[str] = []
    escaped = False

    for char in cpe_name:
        if escaped:
            current.append("\\")
            current.append(char)
            escaped = False
            continue

        if char == "\\":
            escaped = True
            continue

        if char == ":":
            parts.append("".join(current))
            current = []
            continue

        current.append(char)

    if escaped:
        return None

    parts.append("".join(current))
    return parts


def _load_mappings(path: str | Path) -> dict[str, Any]:
    """Load local CPE mappings."""

    mapping_path = Path(path)
    if not mapping_path.exists():
        return {}
    return json.loads(mapping_path.read_text(encoding="utf-8"))


def _identity_confidence(
    software: SoftwareProduct, parsed: ParsedCpe23 | None, title: str,
    alias: dict[str, Any],
) -> tuple[int, str | None]:
    """Require vendor AND product identity; titles cannot compensate for either."""

    if parsed is None or parsed.part != "a":
        return 0, "Not a valid application CPE"
    expected_vendor = str(alias.get("vendor", software.normalized_vendor))
    vendor_score = _component_score(expected_vendor, parsed.vendor, exact=50, similar=45)
    if vendor_score < 45:
        return 0, "Vendor identity not established"
    expected_product = str(alias.get("product", software.normalized_product))

    def product_key(value: str) -> str:
        key = _identity_key(value)
        for vendor in (software.normalized_vendor, expected_vendor):
            prefix = _identity_key(vendor) + " "
            if key.startswith(prefix):
                key = key[len(prefix):]
        return key

    if product_key(expected_product) != product_key(parsed.product):
        return vendor_score, "Product family or component identity differs"
    expected_edition = alias.get("sw_edition")
    if expected_edition and parsed.sw_edition != expected_edition:
        return vendor_score, "Required software edition was not established"
    if not expected_edition and parsed.sw_edition not in {"*", "-"}:
        if _identity_key(parsed.sw_edition) not in _identity_key(software.product).split():
            return vendor_score, "Specific software edition is not evidenced by inventory"
    if parsed.edition not in {"*", "-"} and _identity_key(parsed.edition) not in _identity_key(software.product).split():
        return vendor_score, "Specific product edition is not evidenced by inventory"
    # A title corroborates a matched identity, but never establishes one alone.
    title_score = 10 if product_key(expected_product) in product_key(title) else 5
    return min(100, vendor_score + 35 + title_score), None


def _score_candidate(software: SoftwareProduct, vendor: str, product: str, title: str) -> int:
    """Score a CPE API candidate."""

    vendor_score = _component_score(
        software.normalized_vendor,
        vendor,
        exact=50,
        similar=45,
    )
    product_score = _component_score(
        software.normalized_product,
        product,
        exact=35,
        similar=30,
    )
    title_score = int(
        15
        * SequenceMatcher(
            None,
            _identity_key(software.normalized_product),
            _identity_key(title),
        ).ratio()
    )
    return min(100, vendor_score + product_score + title_score)


def _collapse_equivalent_candidates(
    candidates: list[CpeCandidate],
    installed_version: str,
) -> list[CpeCandidate]:
    """Collapse catalog rows after canonical product-family grouping.

    NVD may publish one CPE row per version and may retain equivalent vendor
    spellings for the same family. Neither creates a competing product identity.
    Edition and platform constraints remain part of the identity because they
    can change applicability.
    """

    grouped: dict[tuple[str, ...], list[CpeCandidate]] = {}
    for candidate in candidates:
        parsed = parse_cpe23_components(candidate.cpe_name)
        if parsed is None:
            continue
        key = _canonical_family_key(parsed)
        grouped.setdefault(key, []).append(candidate)

    collapsed: list[CpeCandidate] = []
    for values in grouped.values():
        active = [item for item in values if not item.deprecated]
        available = active or values
        exact = [
            item
            for item in available
            if _catalog_version_matches(installed_version, item.version)
        ]
        available.sort(key=_family_candidate_sort_key)
        exact.sort(key=_family_candidate_sort_key)
        best = (exact or available)[0]
        parsed = parse_cpe23_components(best.cpe_name)
        if parsed is None:
            continue
        selected_cpe = best.cpe_name if exact else build_cpe23(
            parsed.part, parsed.vendor, parsed.product,
            update="*", edition=parsed.edition,
            sw_edition=parsed.sw_edition, target_sw=parsed.target_sw,
            target_hw=parsed.target_hw, language=parsed.language,
            other=parsed.other,
        )
        collapsed.append(
            CpeCandidate(
                cpe_name=selected_cpe,
                title=best.title,
                vendor=best.vendor,
                product=best.product,
                version=best.version if exact else None,
                deprecated=best.deprecated,
                confidence=best.confidence,
                match_status=best.match_status,
                source="NVD_CPE_API_DISCOVERY",
            )
        )
    return collapsed


def _family_candidate_sort_key(candidate: CpeCandidate) -> tuple[Any, ...]:
    """Prefer active, unconstrained and higher-confidence family rows."""

    parsed = parse_cpe23_components(candidate.cpe_name)
    update_rank = 0 if parsed and parsed.update == "*" else 1
    return (
        candidate.deprecated,
        update_rank,
        -candidate.confidence,
        candidate.cpe_name,
    )


def _canonical_family_key(parsed: ParsedCpe23) -> tuple[str, ...]:
    """Return a stable product identity without version/update row noise."""

    return (
        parsed.part,
        _family_identity_key(parsed.vendor),
        _family_identity_key(parsed.product),
        _family_component(parsed.edition),
        _family_component(parsed.sw_edition),
        _family_component(parsed.target_sw),
        _family_component(parsed.target_hw),
        _family_component(parsed.language),
        _family_component(parsed.other),
    )


def _family_component(value: str) -> str:
    """Canonicalize a family constraint while preserving wildcard and NA."""

    return value if value in {"*", "-"} else _family_identity_key(value)


def _family_identity_key(value: str) -> str:
    """Normalize spelling without removing product years or version-like identity."""

    text = _key(value)
    text = re.sub(
        r"\b(?:incorporated|corporation|company|limited|llc|ltd|inc)\b\.?,?",
        " ",
        text,
    )
    return re.sub(r"[^a-z0-9]+", " ", text).strip()


def _is_neutral_family(candidate: CpeCandidate) -> bool:
    """Reject platform/edition-constrained discoveries without collector proof."""

    parsed = parse_cpe23_components(candidate.cpe_name)
    return bool(parsed and all(
        value == "*" for value in (
            parsed.update, parsed.edition, parsed.sw_edition,
            parsed.target_sw, parsed.target_hw, parsed.language, parsed.other,
        )
    ))


def _target_sw(candidate: CpeCandidate) -> str:
    """Return a discovered candidate's explicit target software platform."""

    parsed = parse_cpe23_components(candidate.cpe_name)
    return parsed.target_sw if parsed is not None else ""


def _same_cpe_family(left: ParsedCpe23 | None, right: ParsedCpe23 | None) -> bool:
    """Require the same CPE identity and environment, excluding version."""

    if left is None or right is None:
        return False
    return _canonical_family_key(left) == _canonical_family_key(right)


def _catalog_version_matches(installed: str, catalogued: str | None) -> bool:
    """Compare an installed version with a concrete NVD CPE version."""

    if not catalogued or catalogued in {"*", "-"}:
        return False
    if re.fullmatch(r"\d+(?:\.\d+)+", installed) and re.fullmatch(
        r"\d+(?:\.\d+)+", catalogued
    ):
        return compare_versions(installed, catalogued) == 0
    return installed.casefold() == catalogued.casefold()


def _collector_os(raw_data: dict[str, Any] | None) -> str:
    """Use only explicit collector OS evidence for platform selection."""

    if not isinstance(raw_data, dict):
        return ""
    operating_system = raw_data.get("operatingSystem")
    nested = operating_system.get("name") if isinstance(operating_system, dict) else ""
    value = str(raw_data.get("OS") or raw_data.get("OSName") or nested or "").casefold()
    if "windows" in value:
        return "windows"
    if "linux" in value:
        return "linux"
    return ""


def _component_score(
    left: str,
    right: str,
    *,
    exact: int,
    similar: int,
) -> int:
    """Score exact or strongly similar CPE identity components."""

    left_key = _identity_key(left)
    right_key = _identity_key(right)
    if not left_key or not right_key:
        return 0
    if left_key == right_key:
        return exact
    ratio = SequenceMatcher(None, left_key, right_key).ratio()
    if ratio >= 0.9:
        return similar
    left_tokens = set(left_key.split())
    right_tokens = set(right_key.split())
    if left_tokens and right_tokens and (
        left_tokens <= right_tokens or right_tokens <= left_tokens
    ):
        return similar
    return 0


def _identity_key(value: str) -> str:
    """Return a conservative comparison key for vendor/product discovery."""

    text = _key(value)
    text = re.sub(
        r"\b(?:incorporated|corporation|company|limited|llc|ltd|inc)\b\.?,?",
        " ",
        text,
    )
    text = re.sub(r"\b(?:19|20)\d{2}\b", " ", text)
    text = re.sub(r"\b\d+(?:\.\d+){1,}\b", " ", text)
    return re.sub(r"[^a-z0-9]+", " ", text).strip()


def _status_for_confidence(confidence: int) -> CpeMatchStatus:
    """Return match status for a confidence score."""

    if confidence >= 95:
        return CpeMatchStatus.EXACT
    if confidence >= 80:
        return CpeMatchStatus.ALIAS
    if confidence >= 65:
        return CpeMatchStatus.FUZZY
    return CpeMatchStatus.NOT_FOUND


def _read_title(cpe: dict[str, Any]) -> str:
    """Read the best CPE title."""

    titles = cpe.get("titles", [])
    if isinstance(titles, list):
        for title in titles:
            if isinstance(title, dict) and title.get("lang") == "en":
                return str(title.get("title", ""))
        for title in titles:
            if isinstance(title, dict):
                return str(title.get("title", ""))
    return str(cpe.get("cpeName", ""))


def _escape(value: str) -> str:
    """Bind one logical value as a CPE 2.3 formatted-string component.

    Rebuilt family CPEs must escape all punctuation outside the unquoted CPE
    alphabet. Otherwise identities such as ``notepad\\+\\+`` silently become
    ``notepad++`` and NVD rejects the FAMILY_RANGE query.
    """

    if value in {"*", "-"}:
        return value
    cleaned = value.strip().lower().replace(" ", "_")
    return "".join(
        character
        if character.isascii() and (character.isalnum() or character in "._-")
        else f"\\{character}"
        for character in cleaned
    )


def _unescape(value: str) -> str:
    """Unescape a CPE component."""

    result: list[str] = []
    escaped = False

    for char in value:
        if escaped:
            result.append(char)
            escaped = False
            continue

        if char == "\\":
            escaped = True
            continue

        result.append(char)

    if escaped:
        result.append("\\")

    return "".join(result)


def _key(value: str) -> str:
    """Return a loose comparison key."""

    return value.replace("_", " ").casefold().strip()
