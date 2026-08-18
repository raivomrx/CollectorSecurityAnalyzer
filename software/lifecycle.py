"""Versioned, data-driven software lifecycle assessment."""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from software.models import LifecycleResult, LifecycleStatus, SoftwareProduct

DEFAULT_PACK = Path(__file__).with_name("lifecycle_pack.json")


class LifecycleRepository:
    """Load and evaluate one immutable lifecycle content pack."""

    def __init__(self, path: str | Path = DEFAULT_PACK) -> None:
        """Load lifecycle entries from a versioned JSON pack."""

        document = json.loads(Path(path).read_text(encoding="utf-8"))
        self.data_version = str(document["dataVersion"])
        self.entries = [
            item for item in document["entries"] if isinstance(item, dict)
        ]

    def assess(
        self,
        software: SoftwareProduct,
        *,
        assessed_on: date | None = None,
        nearing_days: int = 180,
    ) -> LifecycleResult:
        """Return a conservative lifecycle result for installed software."""

        today = assessed_on or datetime.now(timezone.utc).date()
        candidates = [
            item
            for item in self.entries
            if _matches_product(software, item)
        ]
        if not candidates:
            return _result(
                software,
                LifecycleStatus.NOT_EVALUATED,
                None,
                None,
                self.data_version,
                0,
                "No lifecycle pack mapping",
            )
        versioned = [
            item for item in candidates if _matches_version(software, item)
        ]
        if not software.normalized_version:
            return _result(
                software,
                LifecycleStatus.UNKNOWN_VERSION,
                None,
                candidates[0].get("source"),
                self.data_version,
                60,
                "Installed version is unavailable",
            )
        if not versioned:
            return _result(
                software,
                LifecycleStatus.NOT_EVALUATED,
                None,
                candidates[0].get("source"),
                self.data_version,
                50,
                "Product is mapped but this version is not covered",
            )
        entry = versioned[0]
        if entry.get("policyType"):
            return _assess_policy(
                software,
                entry,
                today=today,
                data_version=self.data_version,
            )
        end_date = _date(entry.get("endOfSupportDate"))
        if entry.get("supportStatus") == "NOT_EVALUATED":
            status = LifecycleStatus.NOT_EVALUATED
            rationale = "Lifecycle requires a current vendor release feed"
        elif end_date is None:
            status = LifecycleStatus.SUPPORTED
            rationale = "Lifecycle pack marks this release as supported"
        elif today > end_date:
            status = LifecycleStatus.OUT_OF_SUPPORT
            rationale = f"Vendor support ended on {end_date.isoformat()}"
        elif today + timedelta(days=nearing_days) >= end_date:
            status = LifecycleStatus.NEARING_END_OF_SUPPORT
            rationale = f"Vendor support ends within {nearing_days} days"
        else:
            status = LifecycleStatus.SUPPORTED
            rationale = "Vendor support end date is outside the warning window"
        return _result(
            software,
            status,
            end_date,
            entry.get("source"),
            self.data_version,
            int(entry.get("confidence", 90)),
            rationale,
        )

    def assess_inventory(
        self,
        products: list[SoftwareProduct],
    ) -> list[LifecycleResult]:
        """Assess every product in deterministic inventory order."""

        return [self.assess(product) for product in products]


def _matches_product(software: SoftwareProduct, entry: dict[str, Any]) -> bool:
    return (
        _key(software.normalized_vendor) == _key(str(entry.get("vendor", "")))
        and _key(software.normalized_product)
        == _key(str(entry.get("product", "")))
    )


def _matches_version(software: SoftwareProduct, entry: dict[str, Any]) -> bool:
    major = str(entry.get("majorVersion", "")).strip()
    if not major:
        return True
    return software.normalized_version.split(".", 1)[0] == major


def _date(value: Any) -> date | None:
    try:
        return date.fromisoformat(str(value)) if value else None
    except ValueError:
        return None


def _assess_policy(
    software: SoftwareProduct,
    entry: dict[str, Any],
    *,
    today: date,
    data_version: str,
) -> LifecycleResult:
    """Evaluate a version-channel lifecycle policy from pack data."""

    source = entry.get("source")
    confidence = int(entry.get("confidence", 90))
    if entry.get("policyType") != "ADOBE_CREATIVE_CLOUD":
        return _result(
            software,
            LifecycleStatus.NOT_EVALUATED,
            None,
            source,
            data_version,
            0,
            "Lifecycle policy type is unsupported",
        )
    refresh_after = _date(entry.get("refreshAfter"))
    if refresh_after is not None and today > refresh_after:
        return _result(
            software,
            LifecycleStatus.NOT_EVALUATED,
            None,
            source,
            data_version,
            40,
            "Adobe release-channel policy data requires refresh",
        )

    installed_major = _major(software.normalized_version)
    if installed_major is None:
        return _result(
            software,
            LifecycleStatus.UNKNOWN_VERSION,
            None,
            source,
            data_version,
            60,
            "Installed major version is unavailable",
        )
    supported_majors = {
        int(value)
        for value in (
            entry.get("latestMajor"),
            entry.get("previousMajor"),
        )
        if isinstance(value, int) or str(value).isdigit()
    }
    if installed_major in supported_majors:
        return _result(
            software,
            LifecycleStatus.SUPPORTED,
            None,
            source,
            data_version,
            confidence,
            (
                "Adobe Creative Cloud N/N-1 release-channel policy covers "
                "this major version"
            ),
        )

    for lts in entry.get("ltsVersions", []):
        if not isinstance(lts, dict):
            continue
        minimum = str(lts.get("minimumVersion", ""))
        supported_until = _date(lts.get("supportedUntil"))
        if not minimum or _major(minimum) != installed_major:
            continue
        if _version_parts(software.normalized_version) < _version_parts(minimum):
            break
        if supported_until is not None and today <= supported_until:
            return _result(
                software,
                LifecycleStatus.SUPPORTED,
                supported_until,
                source,
                data_version,
                confidence,
                "Adobe-designated LTS branch is within its support window",
            )
        break

    return _result(
        software,
        LifecycleStatus.OUT_OF_SUPPORT,
        None,
        source,
        data_version,
        confidence,
        (
            "Installed release is outside Adobe Creative Cloud "
            "N/N-1/LTS policy"
        ),
    )


def _major(value: str) -> int | None:
    """Return the numeric major component of a normalized version."""

    first = value.split(".", 1)[0]
    return int(first) if first.isdigit() else None


def _version_parts(value: str) -> tuple[int, ...]:
    """Return numeric version parts for policy threshold comparison."""

    return tuple(
        int(part) for part in value.split(".") if part.isdigit()
    )


def _result(
    software: SoftwareProduct,
    status: LifecycleStatus,
    end_date: date | None,
    source: Any,
    data_version: str,
    confidence: int,
    rationale: str,
) -> LifecycleResult:
    return LifecycleResult(
        vendor=software.normalized_vendor,
        product=software.normalized_product,
        installed_version=software.normalized_version,
        status=status,
        end_of_support_date=end_date,
        source=str(source) if source else None,
        data_version=data_version,
        confidence=confidence,
        rationale=rationale,
    )


def _key(value: str) -> str:
    return "".join(character for character in value.casefold() if character.isalnum())
