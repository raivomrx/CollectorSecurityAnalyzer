"""CNA affected-version applicability evaluation."""

from __future__ import annotations

from cve.enrichment_models import AffectedVersionRange
from cve.models import ApplicabilityStatus
from software.models import SoftwareProduct
from software.version import compare_versions, parse_version


def evaluate_cna_applicability(
    software: SoftwareProduct,
    affected: list[AffectedVersionRange],
) -> tuple[ApplicabilityStatus, str, int]:
    """Evaluate CNA affected-version data for one installed product."""

    matching = [item for item in affected if _product_matches(software, item)]
    if not matching:
        return ApplicabilityStatus.NOT_AFFECTED, "CNA affected data does not match product", 80
    if not parse_version(software.version).parts:
        return ApplicabilityStatus.NOT_EVALUATED, "Installed version could not be compared with CNA data", 30

    saw_uncertain = False
    for item in matching:
        platform_result = _platform_matches(software, item)
        if platform_result == ApplicabilityStatus.NOT_AFFECTED:
            continue
        if platform_result == ApplicabilityStatus.NOT_EVALUATED:
            saw_uncertain = True
            continue

        status, uncertain_changes = _effective_status(software.version, item)
        if uncertain_changes:
            saw_uncertain = True
            continue
        if status == "unaffected":
            return ApplicabilityStatus.NOT_AFFECTED, "CNA marks installed version unaffected", 90
        if status == "affected" and _version_matches(software.version, item):
            return ApplicabilityStatus.AFFECTED, "CNA affected versions include installed version", 90
        if status not in {"affected", "unaffected", "unknown"}:
            saw_uncertain = True

    if saw_uncertain:
        return ApplicabilityStatus.NOT_EVALUATED, "CNA affected data has unconfirmed constraints", 35
    return ApplicabilityStatus.NOT_AFFECTED, "CNA affected versions do not include installed version", 85


def _product_matches(software: SoftwareProduct, item: AffectedVersionRange) -> bool:
    """Return whether CNA vendor/product fields match normalized software."""

    vendor_ok = item.vendor is None or _key(item.vendor) == _key(software.normalized_vendor)
    product_candidates = [item.product, item.package_name, _product_from_purl(item.package_url)]
    product_ok = any(candidate and _key(candidate) == _key(software.normalized_product) for candidate in product_candidates)
    return vendor_ok and product_ok


def _platform_matches(
    software: SoftwareProduct,
    item: AffectedVersionRange,
) -> ApplicabilityStatus:
    """Evaluate CNA platform constraints from software architecture only."""

    if not item.platforms:
        return ApplicabilityStatus.AFFECTED
    if not software.architecture:
        return ApplicabilityStatus.NOT_EVALUATED
    observed = _key(software.architecture)
    return (
        ApplicabilityStatus.AFFECTED
        if any(_key(platform) in observed or observed in _key(platform) for platform in item.platforms)
        else ApplicabilityStatus.NOT_AFFECTED
    )


def _version_matches(installed: str, item: AffectedVersionRange) -> bool:
    """Return whether installed version matches one CNA range."""

    if item.less_than:
        return compare_versions(installed, item.less_than) < 0 and _start_matches(installed, item)
    if item.less_than_or_equal:
        return compare_versions(installed, item.less_than_or_equal) <= 0 and _start_matches(installed, item)
    if item.version in {None, "*"}:
        return True
    return compare_versions(installed, item.version) == 0


def _start_matches(installed: str, item: AffectedVersionRange) -> bool:
    """Return whether installed version is at or above the CNA start version."""

    if item.version in {None, "*"}:
        return True
    return compare_versions(installed, item.version) >= 0


def _effective_status(installed: str, item: AffectedVersionRange) -> tuple[str, bool]:
    """Return CNA status after applying version changes."""

    status = (item.status or "unknown").casefold()
    sortable_changes: list[tuple[str, dict[str, str]]] = []
    for change in item.changes:
        at = change.get("at")
        if not at or not change.get("status"):
            continue
        try:
            parse_version(at)
        except Exception:
            return status, True
        if not parse_version(at).parts:
            return status, True
        sortable_changes.append((at, change))

    sortable_changes.sort(key=lambda item_pair: parse_version(item_pair[0]))
    for at, change in sortable_changes:
        if compare_versions(installed, at) >= 0:
            status = str(change["status"]).casefold()
    return status, False


def _product_from_purl(package_url: str | None) -> str | None:
    """Extract a best-effort product name from a package URL."""

    if not package_url:
        return None
    return package_url.rstrip("/").split("/")[-1]


def _key(value: str) -> str:
    """Return a loose comparison key."""

    return value.replace("_", " ").replace("-", " ").casefold().strip()
