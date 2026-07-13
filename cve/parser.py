"""NVD CVE response parser."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from cve.models import CveDataQuality, CveRecord

CVSS_PRIORITY = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)


def parse_cve_items(items: list[dict[str, Any]]) -> list[CveRecord]:
    """Parse NVD vulnerability items into records."""

    records: list[CveRecord] = []
    for item in items:
        cve = item.get("cve", item)
        if isinstance(cve, dict):
            records.append(parse_cve_record(cve))
    return records


def parse_cve_record(cve: dict[str, Any]) -> CveRecord:
    """Parse one NVD CVE object."""

    description, description_partial = _read_description(cve.get("descriptions", []))
    cvss_version, score, severity, vector = _read_cvss(cve.get("metrics", {}))
    configurations = cve.get("configurations", [])
    if not isinstance(configurations, list):
        configurations = []
    quality = _quality(bool(description), score is not None, bool(configurations), description_partial)
    return CveRecord(
        cve_id=str(cve.get("id", "UNKNOWN")),
        description=description,
        published=_parse_datetime(cve.get("published")),
        last_modified=_parse_datetime(cve.get("lastModified")),
        cvss_version=cvss_version,
        cvss_score=score,
        severity=severity,
        vector=vector,
        cwes=_read_cwes(cve.get("weaknesses", [])),
        references=_read_references(cve.get("references", {})),
        configurations=configurations,
        source_identifier=cve.get("sourceIdentifier"),
        vuln_status=cve.get("vulnStatus"),
        data_quality=quality,
    )


def _read_description(descriptions: Any) -> tuple[str, bool]:
    """Read the preferred description."""

    if not isinstance(descriptions, list) or not descriptions:
        return "", True
    for description in descriptions:
        if isinstance(description, dict) and description.get("lang") == "en":
            return str(description.get("value", "")), False
    first = descriptions[0]
    if isinstance(first, dict):
        return str(first.get("value", "")), True
    return "", True


def _read_cvss(metrics: Any) -> tuple[str | None, float | None, str, str | None]:
    """Read the best CVSS metric."""

    if not isinstance(metrics, dict):
        return None, None, "UNKNOWN", None
    for metric_key, version in CVSS_PRIORITY:
        metric_values = metrics.get(metric_key)
        if not isinstance(metric_values, list) or not metric_values:
            continue
        metric = _choose_primary(metric_values)
        data = metric.get("cvssData", {}) if isinstance(metric, dict) else {}
        score = data.get("baseScore")
        severity = metric.get("baseSeverity") or data.get("baseSeverity") or "UNKNOWN"
        vector = data.get("vectorString")
        return version, float(score) if score is not None else None, str(severity), vector
    return None, None, "UNKNOWN", None


def _choose_primary(metrics: list[Any]) -> dict[str, Any]:
    """Choose a primary CVSS metric when available."""

    for metric in metrics:
        if isinstance(metric, dict) and metric.get("type") == "Primary":
            return metric
    for metric in metrics:
        if isinstance(metric, dict):
            return metric
    return {}


def _read_cwes(weaknesses: Any) -> list[str]:
    """Read useful CWE identifiers."""

    cwes: list[str] = []
    if not isinstance(weaknesses, list):
        return cwes
    for weakness in weaknesses:
        descriptions = weakness.get("description", []) if isinstance(weakness, dict) else []
        if not isinstance(descriptions, list):
            continue
        for description in descriptions:
            value = description.get("value") if isinstance(description, dict) else None
            if isinstance(value, str) and value.startswith("CWE-"):
                cwes.append(value)
    return sorted(set(cwes))


def _read_references(references: Any) -> list[str]:
    """Read CVE reference URLs."""

    items = references.get("referenceData", references) if isinstance(references, dict) else references
    if not isinstance(items, list):
        return []
    urls = [item.get("url") for item in items if isinstance(item, dict)]
    return [str(url) for url in urls if url]


def _quality(
    has_description: bool,
    has_cvss: bool,
    has_configurations: bool,
    description_partial: bool,
) -> CveDataQuality:
    """Classify data quality."""

    if has_description and has_cvss and has_configurations and not description_partial:
        return CveDataQuality.COMPLETE
    if has_configurations or has_description or has_cvss:
        return CveDataQuality.PARTIAL
    return CveDataQuality.UNENRICHED


def _parse_datetime(value: Any) -> datetime | None:
    """Parse NVD datetime values."""

    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
