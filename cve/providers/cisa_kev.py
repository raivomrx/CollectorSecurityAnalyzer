"""CISA Known Exploited Vulnerabilities enrichment provider."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests

from cve.enrichment_models import (
    ExploitationStatus,
    KevRecord,
    ProviderStatus,
    RansomwareUse,
    SourceEnrichment,
    SourceType,
)
from cve.models import CveDataQuality
from cve.providers.base import VulnerabilityDataProvider

LOGGER = logging.getLogger(__name__)
DEFAULT_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_KEV_CACHE_PATH = Path(__file__).resolve().parents[2] / "cache" / "cisa_kev_cache.json"


@dataclass(slots=True)
class KevCatalog:
    """Loaded KEV catalog state."""

    records: dict[str, KevRecord]
    loaded: bool
    used_stale_cache: bool
    warnings: list[str]


class CisaKevProvider(VulnerabilityDataProvider):
    """Enrich CVEs with CISA KEV catalog membership."""

    name = "CISA KEV"

    def __init__(
        self,
        feed_url: str = DEFAULT_KEV_FEED_URL,
        cache_ttl_hours: int = 6,
        allow_stale_cache: bool = True,
        enabled: bool = True,
        session: requests.Session | None = None,
        cache_path: str | Path = DEFAULT_KEV_CACHE_PATH,
        timeout: int = 30,
    ) -> None:
        """Create a CISA KEV provider."""

        self.feed_url = feed_url
        self.cache_ttl_hours = cache_ttl_hours
        self.allow_stale_cache = allow_stale_cache
        self.enabled = enabled
        self.session = session or requests.Session()
        self.cache_path = Path(cache_path)
        self.timeout = timeout
        self._catalog: KevCatalog | None = None
        self._status = ProviderStatus(self.name, enabled, False, False, 0, None)

    def enrich(self, cve_id: str) -> SourceEnrichment | None:
        """Return KEV enrichment for one CVE."""

        if not self.enabled:
            return None
        catalog = self._load_catalog()
        if not catalog.loaded:
            return None

        record = catalog.records.get(cve_id.upper())
        warnings = list(catalog.warnings)
        if record is not None:
            return SourceEnrichment(
                cve_id=cve_id,
                source=SourceType.CISA_KEV,
                title=record.vulnerability_name,
                descriptions=[record.short_description] if record.short_description else [],
                weaknesses=record.cwes,
                kev=record,
                provider_name=self.name,
                provider_short_name="CISA",
                raw_available=True,
                data_quality=CveDataQuality.COMPLETE,
                warnings=warnings,
            )

        return SourceEnrichment(
            cve_id=cve_id,
            source=SourceType.CISA_KEV,
            provider_name=self.name,
            provider_short_name="CISA",
            raw_available=True,
            data_quality=CveDataQuality.COMPLETE,
            warnings=warnings,
        )

    def status(self) -> ProviderStatus:
        """Return provider status."""

        return self._status

    def exploitation_status(self, cve_id: str) -> ExploitationStatus:
        """Return KEV membership semantics for one CVE."""

        catalog = self._load_catalog()
        if not catalog.loaded:
            return ExploitationStatus.UNKNOWN
        if cve_id.upper() in catalog.records:
            return ExploitationStatus.KNOWN_EXPLOITED
        return ExploitationStatus.NO_KEV_EVIDENCE

    def _load_catalog(self) -> KevCatalog:
        """Load and cache the KEV catalog once."""

        if self._catalog is not None:
            return self._catalog
        if not self.enabled:
            self._catalog = KevCatalog({}, False, False, ["Provider disabled"])
            return self._catalog

        cached = self._read_cache()
        if cached and not _is_expired(cached.get("cached_at"), self.cache_ttl_hours):
            self._catalog = self._parse_catalog(cached.get("data", {}), used_stale_cache=False)
            return self._catalog

        try:
            response = self.session.get(self.feed_url, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError("KEV feed root is not an object")
            self._write_cache(data)
            self._catalog = self._parse_catalog(data, used_stale_cache=False)
            LOGGER.info("CISA KEV catalog loaded: entries=%s", len(self._catalog.records))
            return self._catalog
        except Exception as error:
            if cached and self.allow_stale_cache:
                LOGGER.warning("Using stale CISA KEV cache")
                self._catalog = self._parse_catalog(cached.get("data", {}), used_stale_cache=True)
                self._catalog.warnings.append("Using stale CISA KEV cache")
                self._status.error_message = str(error)
                return self._catalog

            LOGGER.error("CISA KEV feed unavailable and no cache exists")
            self._status = ProviderStatus(self.name, self.enabled, False, False, 0, str(error))
            self._catalog = KevCatalog({}, False, False, [str(error)])
            return self._catalog

    def _parse_catalog(self, data: dict[str, Any], used_stale_cache: bool) -> KevCatalog:
        """Parse a KEV catalog payload."""

        vulnerabilities = data.get("vulnerabilities", [])
        warnings: list[str] = []
        records: dict[str, KevRecord] = {}
        if not isinstance(vulnerabilities, list):
            warnings.append("KEV vulnerabilities field is not a list")
            vulnerabilities = []

        for item in vulnerabilities:
            if not isinstance(item, dict):
                warnings.append("Malformed KEV record ignored")
                continue
            record = _parse_kev_record(item, warnings)
            if record is None:
                continue
            if record.cve_id in records:
                warnings.append(f"Duplicate KEV CVE ID ignored: {record.cve_id}")
                continue
            records[record.cve_id] = record

        self._status = ProviderStatus(
            provider=self.name,
            enabled=self.enabled,
            succeeded=True,
            used_stale_cache=used_stale_cache,
            records_loaded=len(records),
            error_message=None,
        )
        return KevCatalog(records, True, used_stale_cache, warnings)

    def _read_cache(self) -> dict[str, Any] | None:
        """Read cached KEV feed payload."""

        if not self.cache_path.exists():
            return None
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None
        except (OSError, json.JSONDecodeError):
            LOGGER.warning("Malformed CISA KEV cache ignored")
            return None

    def _write_cache(self, data: dict[str, Any]) -> None:
        """Persist KEV feed payload for later runs."""

        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "feed_url": self.feed_url,
                "schema_version": data.get("catalogVersion") or data.get("version"),
                "cached_at": datetime.now(timezone.utc).isoformat(),
                "data": data,
            }
            self.cache_path.write_text(json.dumps(payload, default=str), encoding="utf-8")
        except OSError:
            LOGGER.warning("Unable to write CISA KEV cache")


def _parse_kev_record(item: dict[str, Any], warnings: list[str]) -> KevRecord | None:
    """Parse one tolerant KEV record."""

    cve_id = str(item.get("cveID", "")).upper().strip()
    if not cve_id:
        warnings.append("KEV record missing cveID")
        return None
    return KevRecord(
        cve_id=cve_id,
        vendor_project=str(item.get("vendorProject", "")),
        product=str(item.get("product", "")),
        vulnerability_name=str(item.get("vulnerabilityName", "")),
        date_added=_parse_date(item.get("dateAdded")),
        short_description=str(item.get("shortDescription", "")),
        required_action=str(item.get("requiredAction", "")),
        due_date=_parse_date(item.get("dueDate")),
        known_ransomware_campaign_use=_parse_ransomware_use(item.get("knownRansomwareCampaignUse")),
        notes=item.get("notes") if isinstance(item.get("notes"), str) else None,
        cwes=_parse_cwes(item.get("cwes")),
    )


def _parse_ransomware_use(value: Any) -> RansomwareUse:
    """Parse KEV ransomware use values conservatively."""

    if value is None or value == "":
        return RansomwareUse.NOT_LISTED
    normalised = str(value).casefold().strip()
    if normalised in {"known", "yes"}:
        return RansomwareUse.KNOWN
    if normalised in {"unknown", "no"}:
        return RansomwareUse.UNKNOWN
    return RansomwareUse.UNKNOWN


def _parse_cwes(value: Any) -> list[str]:
    """Parse KEV CWE field."""

    if isinstance(value, list):
        return [str(item) for item in value if str(item).startswith("CWE-")]
    if isinstance(value, str) and value.startswith("CWE-"):
        return [value]
    return []


def _parse_date(value: Any) -> date | None:
    """Parse a KEV date value."""

    if not value:
        return None
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def _is_expired(cached_at: Any, ttl_hours: int) -> bool:
    """Return whether a cache timestamp is older than TTL."""

    if not cached_at:
        return True
    try:
        timestamp = datetime.fromisoformat(str(cached_at))
    except ValueError:
        return True
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - timestamp > timedelta(hours=ttl_hours)
