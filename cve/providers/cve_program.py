"""CVE Program Record Format 5.x enrichment provider."""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime
from datetime import timedelta, timezone
from enum import Enum
from pathlib import Path
from sqlite3 import Connection
from typing import Any

import requests

from cve.enrichment_models import (
    AffectedVersionRange,
    ReferenceRecord,
    SourceEnrichment,
    SourceType,
    SsvcDecision,
    SsvcExploitation,
)
from cve.models import CveDataQuality
from cve.providers.base import VulnerabilityDataProvider

LOGGER = logging.getLogger(__name__)
DEFAULT_RAW_BASE_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
DEFAULT_CVE_PROGRAM_CACHE_PATH = Path(__file__).resolve().parents[2] / "cache" / "cve_program_cache.sqlite3"


class CveProgramMode(str, Enum):
    """Supported CVE Program provider modes."""

    LOCAL_MIRROR = "LOCAL_MIRROR"
    REMOTE_RECORD = "REMOTE_RECORD"


class CveProgramCache:
    """SQLite cache for CVE Program records."""

    def __init__(
        self,
        path: str | Path = DEFAULT_CVE_PROGRAM_CACHE_PATH,
        source_identity: str = DEFAULT_RAW_BASE_URL,
    ) -> None:
        """Create the cache."""

        self.path = Path(path)
        self.source_identity = source_identity
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    def get(self, cve_id: str) -> dict[str, Any] | None:
        """Return a fresh cached CVE Program record."""

        row = self._row(cve_id, fresh_only=True)
        return self._decode(row, cve_id)

    def get_stale(self, cve_id: str) -> dict[str, Any] | None:
        """Return any cached CVE Program record, even if expired."""

        row = self._row(cve_id, fresh_only=False)
        return self._decode(row, cve_id)

    def set(self, cve_id: str, payload: dict[str, Any], ttl_hours: int) -> None:
        """Store a CVE Program record."""

        created_at = _utc_now()
        expires_at = created_at + timedelta(hours=ttl_hours)
        version = str(payload.get("dataVersion", "unknown"))
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO cve_program_cache
                (cache_key, cve_id, source_identity, schema_version, response_json, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self._key(cve_id),
                    cve_id.upper(),
                    self.source_identity,
                    version,
                    json.dumps(payload, default=str),
                    created_at.isoformat(),
                    expires_at.isoformat(),
                ),
            )

    def clear_expired(self) -> int:
        """Clear expired records."""

        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM cve_program_cache WHERE expires_at <= ?",
                (_utc_now().isoformat(),),
            )
            return cursor.rowcount

    def clear_all(self) -> None:
        """Clear all records."""

        with self._connect() as connection:
            connection.execute("DELETE FROM cve_program_cache")

    def _row(self, cve_id: str, fresh_only: bool) -> tuple[str] | None:
        """Read a cache row."""

        query = "SELECT response_json FROM cve_program_cache WHERE cache_key = ?"
        params: tuple[Any, ...] = (self._key(cve_id),)
        if fresh_only:
            query += " AND expires_at > ?"
            params = (self._key(cve_id), _utc_now().isoformat())
        with self._connect() as connection:
            return connection.execute(query, params).fetchone()

    def _decode(self, row: tuple[str] | None, cve_id: str) -> dict[str, Any] | None:
        """Decode a cache row safely."""

        if row is None:
            return None
        try:
            payload = json.loads(row[0])
        except json.JSONDecodeError:
            LOGGER.warning("Malformed CVE Program cached record ignored: %s", cve_id)
            return None
        return payload if isinstance(payload, dict) else None

    def _key(self, cve_id: str) -> str:
        """Return a deterministic cache key."""

        return "|".join(["CVE_PROGRAM", cve_id.upper(), self.source_identity, "CVE_RECORD_5X"])

    def _ensure_schema(self) -> None:
        """Create cache schema."""

        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS cve_program_cache (
                    cache_key TEXT PRIMARY KEY,
                    cve_id TEXT NOT NULL,
                    source_identity TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )
                """
            )

    @contextmanager
    def _connect(self) -> Connection:
        """Open and close a SQLite connection."""

        connection = sqlite3.connect(self.path)
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()


class CveProgramProvider(VulnerabilityDataProvider):
    """Load CVE Record Format 5.x records from local mirror or remote raw URL."""

    name = "CVE Program"

    def __init__(
        self,
        mode: str = "REMOTE_RECORD",
        local_repository_path: str | Path = "",
        raw_base_url: str = DEFAULT_RAW_BASE_URL,
        cache_ttl_hours: int = 24,
        allow_stale_cache: bool = True,
        max_retries: int = 3,
        cache: CveProgramCache | None = None,
        enabled: bool = True,
        session: requests.Session | None = None,
        timeout: int = 30,
        sleep=time.sleep,
    ) -> None:
        """Create a CVE Program provider."""

        self._configuration_error: str | None = None
        try:
            self.mode = CveProgramMode(mode.upper())
        except ValueError:
            self.mode = CveProgramMode.REMOTE_RECORD
            self._configuration_error = f"Unsupported CVE Program mode: {mode}"
        self.local_repository_path = Path(local_repository_path) if local_repository_path else Path()
        self.raw_base_url = raw_base_url.rstrip("/")
        self.cache_ttl_hours = cache_ttl_hours
        self.allow_stale_cache = allow_stale_cache
        self.max_retries = max_retries
        self.enabled = enabled
        self.session = session or requests.Session()
        self.timeout = timeout
        self.sleep = sleep
        self.cache = cache or CveProgramCache(source_identity=self._source_identity())
        self._records_loaded = 0
        self._used_stale_cache = False
        self._partial = False
        self._error_message: str | None = None
        if self._configuration_error is None:
            self._configuration_error = self._validate_configuration()
        if self._configuration_error:
            self._error_message = self._configuration_error

    def enrich(self, cve_id: str) -> SourceEnrichment | None:
        """Return CVE Program enrichment for one CVE."""

        if not self.enabled:
            return None
        if self._configuration_error:
            return None
        try:
            payload, used_stale = self._load_record(cve_id)
            if payload is None:
                return None
            self._records_loaded += 1
            LOGGER.info("CVE Program record loaded: %s", cve_id)
            enrichment = parse_cve_program_record(payload)
            if used_stale:
                enrichment.warnings.append("Using stale CVE Program cache")
                self._partial = True
            return enrichment
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
            used_stale_cache=self._used_stale_cache,
            records_loaded=self._records_loaded,
            error_message=self._error_message,
            partial=self._partial,
        )

    def _load_record(self, cve_id: str) -> tuple[dict[str, Any] | None, bool]:
        """Load one CVE Program record."""

        if self.mode == CveProgramMode.LOCAL_MIRROR:
            base = self.local_repository_path
            if base.name != "cves":
                base = base / "cves"
            path = base / cve_record_relative_path(cve_id)
            if not path.exists():
                return None, False
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None, False

        cached = self.cache.get(cve_id)
        if cached is not None:
            return cached, False
        url = f"{self.raw_base_url}/{cve_record_relative_path(cve_id).as_posix()}"
        try:
            data = self._get_remote_json(url)
            if isinstance(data, dict):
                self.cache.set(cve_id, data, self.cache_ttl_hours)
                return data, False
            return None, False
        except Exception:
            stale = self.cache.get_stale(cve_id) if self.allow_stale_cache else None
            if stale is not None:
                LOGGER.warning("Using stale CVE Program cache")
                self._used_stale_cache = True
                self._partial = True
                return stale, True
            raise

    def _get_remote_json(self, url: str) -> dict[str, Any] | None:
        """Fetch one CVE Program remote record with controlled retry semantics."""

        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 404:
                    return None
                if response.status_code == 429 or response.status_code >= 500:
                    retry_after = response.headers.get("Retry-After") if hasattr(response, "headers") else None
                    if retry_after:
                        self._sleep_retry_after(retry_after)
                    raise RuntimeError(f"CVE Program transient HTTP status: {response.status_code}")
                if 400 <= response.status_code < 500:
                    raise ValueError(f"CVE Program permanent HTTP status: {response.status_code}")
                response.raise_for_status()
                data = response.json()
                return data if isinstance(data, dict) else None
            except ValueError:
                raise
            except (requests.Timeout, requests.ConnectionError, RuntimeError) as error:
                last_error = error
                if attempt >= self.max_retries:
                    break
                self.sleep(min(2 ** attempt, 8))
            except requests.RequestException as error:
                raise ValueError("CVE Program permanent request failure") from error
        raise RuntimeError(str(last_error))

    def _sleep_retry_after(self, value: str) -> None:
        """Sleep according to Retry-After seconds when valid."""

        try:
            delay = max(0, int(value))
        except ValueError:
            return
        self.sleep(delay)

    def _validate_configuration(self) -> str | None:
        """Validate provider mode and required paths."""

        if self.mode == CveProgramMode.REMOTE_RECORD:
            return None
        if not str(self.local_repository_path):
            return "CVE Program LOCAL_MIRROR path is not configured"
        if not self.local_repository_path.exists():
            return f"CVE Program LOCAL_MIRROR path does not exist: {self.local_repository_path}"
        cves_dir = self.local_repository_path if self.local_repository_path.name == "cves" else self.local_repository_path / "cves"
        if not cves_dir.exists():
            return f"CVE Program LOCAL_MIRROR cves directory not found: {cves_dir}"
        return None

    def _source_identity(self) -> str:
        """Return cache source identity."""

        if self.mode == CveProgramMode.LOCAL_MIRROR:
            return str(self.local_repository_path.resolve()) if self.local_repository_path else "LOCAL_MIRROR"
        return self.raw_base_url


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
    adp_affected: list[AffectedVersionRange] = []
    adp_weaknesses: list[str] = []
    for adp in adp_items if isinstance(adp_items, list) else []:
        if not isinstance(adp, dict):
            continue
        source = _adp_source(adp)
        program_refs.extend(_parse_references(adp.get("references", []), source))
        adp_metrics.extend(_parse_metrics(adp.get("metrics", [])))
        adp_affected.extend(parse_cna_affected(adp.get("affected", []), source) if isinstance(adp.get("affected", []), list) else [])
        adp_weaknesses.extend(_parse_problem_types(adp.get("problemTypes", [])))
        if _adp_kev_evidence(adp):
            adp_metrics.append({"adpKev": True, "source": source.value})
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
        affected=enrichments.affected + adp_affected,
        metrics=enrichments.metrics + adp_metrics,
        weaknesses=sorted(set(enrichments.weaknesses + adp_weaknesses)),
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
                exploitation=_parse_ssvc_exploitation(options.get("exploitation") if isinstance(options, dict) else None),
                exploitation_raw=_optional_str(options.get("exploitation") if isinstance(options, dict) else None),
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


def _adp_kev_evidence(container: dict[str, Any]) -> bool:
    """Return whether ADP container contains KEV-related metadata."""

    if container.get("knownExploitedVulnerability") is True:
        return True
    tags = container.get("tags", [])
    if isinstance(tags, list) and any("kev" in str(tag).casefold() for tag in tags):
        return True
    return "kev" in str(container.get("title", "")).casefold()


def _parse_ssvc_exploitation(value: Any) -> SsvcExploitation:
    """Normalize SSVC exploitation values."""

    normalised = str(value or "").casefold().strip()
    if normalised in {"active", "exploitation_active", "exploited"}:
        return SsvcExploitation.ACTIVE
    if normalised in {"poc", "proof_of_concept", "proof-of-concept"}:
        return SsvcExploitation.POC
    if normalised in {"none", "no", "not_known"}:
        return SsvcExploitation.NONE
    return SsvcExploitation.UNKNOWN


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


def _utc_now() -> datetime:
    """Return current UTC datetime."""

    return datetime.now(timezone.utc)
