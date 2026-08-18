"""CPE resolution for normalized software products."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

from cve.client import NvdClient
from cve.models import CpeCandidate, CpeMatchStatus
from software.models import SoftwareProduct

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
        self.minimum_confidence = minimum_confidence
        self.ambiguous_score_difference = ambiguous_score_difference
        self._resolution_cache: dict[str, CpeResolution] = {}

    def resolve(self, software: SoftwareProduct) -> CpeCandidate | None:
        """Resolve a software product to a CPE candidate."""

        return self.resolve_with_trace(software).candidate

    def resolve_with_trace(self, software: SoftwareProduct) -> CpeResolution:
        """Resolve a product and retain the candidate decision for audit."""

        cache_key = (
            f"{software.normalized_vendor}|{software.normalized_product}"
        ).casefold()
        cached = self._resolution_cache.get(cache_key)
        if cached is not None:
            return cached

        local = self._resolve_local(software)
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
        candidates = self._resolve_nvd(software)
        if not candidates:
            resolution = CpeResolution(
                None,
                0,
                "NO_RELIABLE_MAPPING",
                "NVD CPE search returned no reliable candidate",
            )
            self._resolution_cache[cache_key] = resolution
            return resolution
        candidates = _collapse_equivalent_candidates(candidates)
        candidates.sort(key=lambda candidate: candidate.confidence, reverse=True)
        active = [candidate for candidate in candidates if not candidate.deprecated]
        ranked = active or candidates
        best = ranked[0]
        if best.confidence < self.minimum_confidence:
            resolution = CpeResolution(
                None,
                len(ranked),
                "NO_RELIABLE_MAPPING",
                f"Best CPE confidence {best.confidence} is below "
                f"{self.minimum_confidence}",
            )
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
            )
            self._resolution_cache[cache_key] = resolution
            return resolution
        resolution = CpeResolution(best, len(ranked), "SUCCESS")
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

    def _resolve_nvd(self, software: SoftwareProduct) -> list[CpeCandidate]:
        """Resolve using the NVD CPE API."""

        assert self.client is not None
        query = f"{software.normalized_vendor} {software.normalized_product}".strip()
        products = self.client.get_cpes({"keywordSearch": query, "keywordExactMatch": ""})
        candidates: list[CpeCandidate] = []
        for product in products:
            cpe = product.get("cpe", product)
            cpe_name = str(cpe.get("cpeName", ""))
            title = _read_title(cpe)
            vendor, cpe_product, version = parse_cpe23(cpe_name)
            confidence = _score_candidate(software, vendor, cpe_product, title)
            if confidence < 65:
                continue
            candidates.append(
                CpeCandidate(
                    cpe_name=cpe_name,
                    title=title,
                    vendor=vendor,
                    product=cpe_product,
                    version=version if version not in {"*", "-"} else None,
                    deprecated=bool(cpe.get("deprecated", False)),
                    confidence=confidence,
                    match_status=_status_for_confidence(confidence),
                    source="NVD_CPE_API",
                )
            )
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
) -> list[CpeCandidate]:
    """Collapse version rows that represent the same CPE product identity."""

    grouped: dict[tuple[str, ...], list[CpeCandidate]] = {}
    for candidate in candidates:
        parsed = parse_cpe23_components(candidate.cpe_name)
        if parsed is None:
            continue
        key = (parsed.part, parsed.vendor, parsed.product)
        grouped.setdefault(key, []).append(candidate)

    collapsed: list[CpeCandidate] = []
    for values in grouped.values():
        values.sort(
            key=lambda item: (item.deprecated, -item.confidence, item.cpe_name)
        )
        best = values[0]
        parsed = parse_cpe23_components(best.cpe_name)
        if parsed is None:
            continue
        wildcard = build_cpe23(
            parsed.part,
            parsed.vendor,
            parsed.product,
        )
        collapsed.append(
            CpeCandidate(
                cpe_name=wildcard,
                title=best.title,
                vendor=best.vendor,
                product=best.product,
                version=None,
                deprecated=best.deprecated,
                confidence=best.confidence,
                match_status=best.match_status,
                source="NVD_CPE_API_DISCOVERY",
            )
        )
    return collapsed


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
    """Escape a CPE 2.3 component conservatively."""

    if value in {"*", "-"}:
        return value
    cleaned = value.strip().lower().replace(" ", "_")
    return re.sub(r"([\\:*?\"<>|])", r"\\\1", cleaned)


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
