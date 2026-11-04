"""CNA affected-version applicability evaluation."""

from __future__ import annotations

import re

from cve.enrichment_models import AffectedVersionRange
from cve.environment import architecture_identity, platform_matches
from cve.models import ApplicabilityStatus
from software.models import SoftwareProduct
from software.version import compare_applicability_versions, version_evidence


def evaluate_cna_applicability(
    software: SoftwareProduct, affected: list[AffectedVersionRange], operating_system: str | None = None,
) -> tuple[ApplicabilityStatus, str, int]:
    if not affected:
        return ApplicabilityStatus.NOT_EVALUATED, "MISSING_AUTHORITATIVE_PRODUCT_MAPPING: CNA affected-version data is unavailable", 0
    matching = [item for item in affected if _product_matches(software, item)]
    if not matching:
        return _unknown("MISSING_AUTHORITATIVE_PRODUCT_MAPPING", "CNA data does not cover the installed product")
    evidence = version_evidence(software.vendor, software.product, software.version)
    if evidence.reason or evidence.interpreted is None:
        return _unknown(evidence.reason or "VERSION_INCOMPARABLE", "Installed version could not be established")
    installed = evidence.interpreted
    scoped = []
    exclusions = []
    for item in matching:
        applies, reason = _platform_matches(software, operating_system, item.platforms)
        if applies is None:
            return _unknown(reason, "CNA platform constraint cannot be confirmed")
        if applies:
            scoped.append(item)
        else:
            exclusions.append(reason)
    if not scoped:
        return ApplicabilityStatus.NOT_AFFECTED, f"{exclusions[0]}: CNA platform is disjoint from collected evidence", 90

    statuses = set()
    for item in scoped:
        if item.modules:
            return _unknown("APPLICABILITY_INCOMPLETE", "CNA module constraint cannot be confirmed")
        scheme = item.version_type.casefold() if item.version_type else evidence.scheme
        if scheme == "pep440" and evidence.scheme == "cpython":
            scheme = "cpython"
        result = compare_applicability_versions(installed, installed, scheme)
        if result.reason:
            return _unknown(result.reason, "Installed version cannot be evaluated in the CNA version scheme")
        if item.version is None and item.status is None and item.default_status is not None:
            continue
        matches, reason = _version_matches(installed, item, scheme)
        if matches is None:
            return _unknown(reason, "CNA version range cannot be compared reliably")
        if matches:
            status, reason = _effective_status(installed, item, scheme)
            if status is None:
                return _unknown(reason, "CNA version changes cannot be compared reliably")
            statuses.add(status)
    if not statuses:
        statuses = {(item.default_status or "unknown").casefold() for item in scoped}
    if statuses == {"affected"}:
        return ApplicabilityStatus.AFFECTED, "CNA explicitly includes the installed version", 90
    if statuses == {"unaffected"}:
        return ApplicabilityStatus.NOT_AFFECTED, "CNA explicitly marks the installed version unaffected", 90
    return _unknown("APPLICABILITY_INCOMPLETE", "CNA status is missing, unknown or conflicting for the installed version")


def _platform_matches(
    software: SoftwareProduct, observed_os: str | None, platforms: list[str],
) -> tuple[bool | None, str]:
    if not platforms:
        return True, ""
    unknown = None
    mismatch = "PLATFORM_MISMATCH_CONFIRMED"
    for platform in platforms:
        # A combined label is a conjunction. Keep the architecture separate
        # from the OS name so a Windows host cannot establish an ARM64 match.
        combined = re.fullmatch(r"(.+?)[\s(/_-]+(x64|x86_64|amd64|x86|i[36]86|arm64|aarch64|arm32|armv7)\)?", platform, re.I)
        required_arch = architecture_identity(combined[2] if combined else platform)
        os_match = platform_matches(combined[1], observed_os, exact_product=True) if combined else True
        if required_arch:
            actual_arch = architecture_identity(software.architecture)
            if os_match is False:
                mismatch = "PLATFORM_MISMATCH_CONFIRMED"
                continue
            if os_match is True and required_arch == actual_arch:
                return True, ""
            if actual_arch is None:
                unknown = "ARCH_UNKNOWN"
            elif os_match is None and required_arch == actual_arch:
                unknown = "PLATFORM_UNKNOWN"
            mismatch = "ARCH_MISMATCH_CONFIRMED"
        else:
            result = platform_matches(platform, observed_os, exact_product=True)
            if result is True:
                return True, ""
            if result is None:
                unknown = "PLATFORM_UNKNOWN"
            mismatch = "PLATFORM_MISMATCH_CONFIRMED"
    return (None, unknown) if unknown else (False, mismatch)


def _version_matches(installed: str, item: AffectedVersionRange, scheme: str) -> tuple[bool | None, str]:
    if item.less_than is not None and item.less_than_or_equal is not None:
        return None, "APPLICABILITY_INCOMPLETE"
    bound = item.less_than if item.less_than is not None else item.less_than_or_equal
    if item.version is None or (item.version == "*" and bound is None):
        return None, "APPLICABILITY_INCOMPLETE"
    start = compare_applicability_versions(installed, item.version, scheme) if item.version != "*" else None
    if start is not None and start.order is None:
        return None, start.reason or "VERSION_INCOMPARABLE"
    if bound is None:
        return start is not None and start.order == 0, ""
    if bound == "*":
        return start is None or start.order >= 0, ""
    end = compare_applicability_versions(installed, bound, scheme)
    if end.order is None:
        return None, end.reason or "VERSION_INCOMPARABLE"
    if start is not None:
        bounds = compare_applicability_versions(item.version, bound, scheme)
        if bounds.order is None or bounds.order > 0 or (bounds.order == 0 and item.less_than is not None):
            return None, bounds.reason or "APPLICABILITY_INCOMPLETE"
    return (start is None or start.order >= 0) and (end.order < 0 or end.order == 0 and item.less_than is None), ""


def _effective_status(installed: str, item: AffectedVersionRange, scheme: str) -> tuple[str | None, str]:
    status = (item.status or "unknown").casefold()
    latest = None
    for change in item.changes:
        at = change.get("at")
        changed_status = str(change.get("status", "")).casefold()
        if not at or changed_status not in {"affected", "unaffected", "unknown"}:
            return None, "APPLICABILITY_INCOMPLETE"
        comparison = compare_applicability_versions(installed, at, scheme)
        if comparison.order is None:
            return None, comparison.reason or "VERSION_INCOMPARABLE"
        if comparison.order >= 0:
            if latest is not None:
                ordering = compare_applicability_versions(at, latest, scheme)
                if ordering.order is None:
                    return None, ordering.reason or "VERSION_INCOMPARABLE"
                if ordering.order == 0 and status != changed_status:
                    return None, "APPLICABILITY_INCOMPLETE"
                if ordering.order < 0:
                    continue
            latest, status = at, changed_status
    return status, ""


def _product_matches(software: SoftwareProduct, item: AffectedVersionRange) -> bool:
    vendor_ok = bool(item.vendor) and _key(item.vendor) == _key(software.normalized_vendor)
    package = item.package_url.rstrip("/").split("/")[-1] if item.package_url else None
    return vendor_ok and any(
        candidate and _key(candidate) == _key(software.normalized_product)
        for candidate in (item.product, item.package_name, package)
    )


def _key(value: str) -> str:
    return value.replace("_", " ").replace("-", " ").casefold().strip()


def _unknown(code: str, reason: str) -> tuple[ApplicabilityStatus, str, int]:
    return ApplicabilityStatus.NOT_EVALUATED, f"{code}: {reason}", 30
