"""CVE Program Record Format 5.x enrichment provider."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

import requests

from cve.enrichment_models import (
    AffectedVersionRange,
    ReferenceRecord,
    SourceEnrichment,
    SourceType,
    SsvcDecision,
)
from cve.models import CveDataQuality
from cve.providers.base import VulnerabilityDataProvider

LOGGER = logging.getLogger(__name__)
DEFAULT_RAW_BASE_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"


class CveProgramProvider(VulnerabilityDataProvider):
    """Load CVE Record Format 5.x records from local mirror or remote raw URL."""

    name = "CVE Program"

    def __init__(
        self,
        mode: str = "REMOTE_RECORD",
        local_repository_path: str | Path = "",
        raw_base_url: str = DEFAULT_RAW_BASE_URL,
        enabled: bool = True,
        session: requests.Session | None = None,
        timeout: int = 30,
    ) -> None:
        """Create a CVE Program provider."""

        self.mode = mode.upper()
        self.local_repository_path = Path(local_repository_path) if local_repository_path else Path()
        self.raw_base_url = raw_base_url.rstrip("/")
        self.enabled = enabled
        self.session = session or requests.Session()
        self.timeout = timeout
        self._records_loaded = 0
        self._error_message: str | None = None

    def enrich(self, cve_id: str) -> SourceEnrichment | None:
        """Return CVE Program enrichment for one CVE."""

        if not self.enabled:
            return None
        try:
            payload = self._load_record(cve_id)
            if payload is None:
                return None
            self._records_loaded += 1
            LOGGER.info("CVE Program record loaded: %s", cve_id)
            return parse_cve_program_record(payload)
        except Exception as error:
            LOGGER.warning("CVE Program provider unavailable: %s", error)
            self._error_message = str(error)
            return None

    def status(self):
        """Return provider status."""

        from cve.enrichment_models import ProviderStatus

        return ProviderStatus(
            provider=self.name,
            enabled=self.enabled,
            succeeded=self._error_message is None,
            used_stale_cache=False,
            records_loaded=self._records_loaded,
            error_message=self._error_message,
        )

    def _load_record(self, cve_id: str) -> dict[str, Any] | None:
        """Load one CVE Program record."""

        if self.mode == "LOCAL_MIRROR":
            base = self.local_repository_path
            if base.name != "cves":
                base = base / "cves"
            path = base / cve_record_relative_path(cve_id)
            if not path.exists():
                return None
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None

        url = f"{self.raw_base_url}/{cve_record_relative_path(cve_id).as_posix()}"
        response = self.session.get(url, timeout=self.timeout)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        data = response.json()
        return data if isinstance(data, dict) else None


def cve_record_relative_path(cve_id: str) -> Path:
    """Return cvelistV5 relative path for a CVE ID."""

    parts = cve_id.upper().split("-")
    if len(parts) != 3 or not parts[1].isdigit() or not parts[2].isdigit():
        raise ValueError(f"Invalid CVE ID: {cve_id}")
    year = parts[1]
    sequence = int(parts[2])
    bucket = f"{sequence // 1000}xxx"
    return Path(year) / bucket / f"{cve_id.upper()}.json"


def parse_cve_program_record(record: dict[str, Any]) -> SourceEnrichment:
    """Parse a CVE Record Format 5.x payload."""

    cve_id = str(record.get("cveMetadata", {}).get("cveId", "UNKNOWN"))
    data_version = str(record.get("dataVersion", ""))
    warnings: list[str] = []
    if not data_version.startswith("5."):
        warnings.append(f"Unsupported CVE Record version: {data_version}")
    elif data_version not in {"5.0", "5.1", "5.1.1", "5.2", "5.2.0"}:
        warnings.append(f"Unsupported CVE Record minor version: {data_version}")
        LOGGER.warning("Unsupported CVE Record minor version")

    containers = record.get("containers", {})
    cna = containers.get("cna", {}) if isinstance(containers, dict) else {}
    adp_items = containers.get("adp", []) if isinstance(containers, dict) else []
    cve_program = containers.get("cveProgram", {}) if isinstance(containers, dict) else {}

    enrichments = _parse_container(
        cve_id,
        cna if isinstance(cna, dict) else {},
        SourceType.CNA,
        data_version,
        warnings,
    )

    program_refs: list[ReferenceRecord] = []
    if isinstance(cve_program, dict):
        program_refs.extend(_parse_references(cve_program.get("references", []), SourceType.CVE_PROGRAM_CONTAINER))

    cisa_ssvc = None
    adp_metrics: list[dict[str, Any]] = []
    for adp in adp_items if isinstance(adp_items, list) else []:
        if not isinstance(adp, dict):
            continue
        source = _adp_source(adp)
        program_refs.extend(_parse_references(adp.get("references", []), source))
        adp_metrics.extend(_parse_metrics(adp.get("metrics", [])))
        if source == SourceType.CISA_ADP:
            cisa_ssvc = _parse_ssvc(adp)

    references = _dedupe_references(enrichments.references + program_refs)
    data_quality = CveDataQuality.COMPLETE if not warnings else CveDataQuality.PARTIAL
    if data_version and not data_version.startswith("5."):
        data_quality = CveDataQuality.UNKNOWN

    return SourceEnrichment(
        cve_id=cve_id,
        source=SourceType.CVE_PROGRAM,
        title=enrichments.title,
        descriptions=enrichments.descriptions,
        affected=enrichments.affected,
        metrics=enrichments.metrics + adp_metrics,
        weaknesses=enrichments.weaknesses,
        references=references,
        ssvc=cisa_ssvc,
        provider_name=enrichments.provider_name,
        provider_short_name=enrichments.provider_short_name,
        record_version=data_version,
        date_updated=_parse_datetime(record.get("cveMetadata", {}).get("dateUpdated")),
        raw_available=True,
        data_quality=data_quality,
        warnings=warnings,
    )


def parse_cna_affected(
    affected_items: list[dict[str, Any]],
    source: SourceType = SourceType.CNA,
) -> list[AffectedVersionRange]:
    """Parse CVE Record 5.x affected-version entries."""

    ranges: list[AffectedVersionRange] = []
    for item in affected_items:
        if not isinstance(item, dict):
            continue
        versions = item.get("versions", [])
        if not isinstance(versions, list) or not versions:
            ranges.append(_affected_range(item, {}, source))
            continue
        for version in versions:
            if isinstance(version, dict):
                ranges.append(_affected_range(item, version, source))
    return ranges


def _affected_range(
    item: dict[str, Any],
    version: dict[str, Any],
    source: SourceType,
) -> AffectedVersionRange:
    """Create one affected range from product and version dictionaries."""

    changes = version.get("changes", [])
    return AffectedVersionRange(
        vendor=_optional_str(item.get("vendor")),
        product=_optional_str(item.get("product")),
        package_name=_optional_str(item.get("packageName")),
        package_url=_optional_str(item.get("packageURL")),
        version=_optional_str(version.get("version")),
        status=_optional_str(version.get("status")),
        version_type=_optional_str(version.get("versionType")),
        less_than=_optional_str(version.get("lessThan")),
        less_than_or_equal=_optional_str(version.get("lessThanOrEqual")),
        changes=[{str(k): str(v) for k, v in change.items()} for change in changes if isinstance(change, dict)],
        platforms=[str(value) for value in item.get("platforms", []) if value is not None]
        if isinstance(item.get("platforms"), list)
        else [],
        modules=[str(value) for value in item.get("modules", []) if value is not None]
        if isinstance(item.get("modules"), list)
        else [],
        source=source,
    )


def _parse_container(
    cve_id: str,
    container: dict[str, Any],
    source: SourceType,
    data_version: str,
    warnings: list[str],
) -> SourceEnrichment:
    """Parse a CNA-like CVE Record container."""

    provider = container.get("providerMetadata", {})
    descriptions = [
        str(item.get("value", ""))
        for item in container.get("descriptions", [])
        if isinstance(item, dict) and item.get("value")
    ]
    weaknesses = _parse_problem_types(container.get("problemTypes", []))
    affected = parse_cna_affected(container.get("affected", []), source) if isinstance(container.get("affected", []), list) else []
    if not affected:
        warnings.append("CNA affected data missing")

    return SourceEnrichment(
        cve_id=cve_id,
        source=source,
        title=_optional_str(container.get("title")),
        descriptions=descriptions,
        affected=affected,
        metrics=_parse_metrics(container.get("metrics", [])),
        weaknesses=weaknesses,
        references=_parse_references(container.get("references", []), source),
        provider_name=_optional_str(provider.get("orgId") or provider.get("shortName")),
        provider_short_name=_optional_str(provider.get("shortName")),
        record_version=data_version,
        date_updated=_parse_datetime(provider.get("dateUpdated")),
        raw_available=bool(container),
        data_quality=CveDataQuality.COMPLETE if container else CveDataQuality.UNENRICHED,
        warnings=warnings,
    )


def _parse_references(value: Any, source: SourceType) -> list[ReferenceRecord]:
    """Parse CVE Record reference entries."""

    refs = value.get("referenceData", value) if isinstance(value, dict) else value
    if not isinstance(refs, list):
        return []
    records: list[ReferenceRecord] = []
    for ref in refs:
        if not isinstance(ref, dict) or not ref.get("url"):
            continue
        tags = ref.get("tags", [])
        records.append(
            ReferenceRecord(
                url=str(ref["url"]),
                title=_optional_str(ref.get("name") or ref.get("title")),
                tags=tuple(str(tag) for tag in tags) if isinstance(tags, list) else (),
                source=source,
            )
        )
    return records


def _dedupe_references(references: list[ReferenceRecord]) -> list[ReferenceRecord]:
    """Deduplicate references by normalized URL."""

    seen: set[str] = set()
    deduped: list[ReferenceRecord] = []
    for reference in references:
        key = reference.url.rstrip("/").casefold()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(reference)
    return deduped


def _parse_problem_types(value: Any) -> list[str]:
    """Parse CWE/problem type descriptions."""

    if not isinstance(value, list):
        return []
    problems: list[str] = []
    for item in value:
        descriptions = item.get("descriptions", []) if isinstance(item, dict) else []
        if not isinstance(descriptions, list):
            continue
        for description in descriptions:
            if isinstance(description, dict) and description.get("cweId"):
                problems.append(str(description["cweId"]))
            elif isinstance(description, dict) and description.get("description"):
                problems.append(str(description["description"]))
    return sorted(set(problems))


def _parse_metrics(value: Any) -> list[dict[str, Any]]:
    """Parse metric objects without imposing a schema."""

    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _parse_ssvc(container: dict[str, Any]) -> SsvcDecision | None:
    """Parse CISA ADP SSVC details when present."""

    for metric in _parse_metrics(container.get("metrics", [])):
        ssvc = metric.get("other", {}).get("content", {}).get("ssvc")
        if isinstance(ssvc, dict):
            options = ssvc.get("options", {})
            return SsvcDecision(
                decision=_optional_str(ssvc.get("decision")),
                exploitation=_optional_str(options.get("exploitation") if isinstance(options, dict) else None),
                automatable=_optional_str(options.get("automatable") if isinstance(options, dict) else None),
                technical_impact=_optional_str(options.get("technicalImpact") if isinstance(options, dict) else None),
                timestamp=_parse_datetime(ssvc.get("timestamp")),
                source=SourceType.CISA_ADP,
            )
    return None


def _adp_source(container: dict[str, Any]) -> SourceType:
    """Classify an ADP container."""

    provider = container.get("providerMetadata", {})
    short_name = str(provider.get("shortName", "")).casefold() if isinstance(provider, dict) else ""
    title = str(container.get("title", "")).casefold()
    if "cisa" in short_name or "cisa" in title:
        return SourceType.CISA_ADP
    if "cve" in short_name and "program" in short_name:
        return SourceType.CVE_PROGRAM_CONTAINER
    return SourceType.OTHER_ADP


def _parse_datetime(value: Any) -> datetime | None:
    """Parse CVE Record datetime values."""

    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _optional_str(value: Any) -> str | None:
    """Return a non-empty string or None."""

    if value in (None, ""):
        return None
    return str(value)
