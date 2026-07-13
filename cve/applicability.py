"""Version-aware CVE applicability evaluation."""

from __future__ import annotations

from typing import Any

from cve.cpe_resolver import parse_cpe23
from cve.models import ApplicabilityStatus, CpeCandidate, CpeMatchStatus, CveRecord
from software.models import SoftwareProduct
from software.version import compare_versions, parse_version


def evaluate_applicability(
    software: SoftwareProduct,
    cpe: CpeCandidate,
    cve: CveRecord,
) -> tuple[ApplicabilityStatus, str, int, list[str]]:
    """Evaluate whether an installed software version is affected by a CVE."""

    if cpe.match_status in {CpeMatchStatus.AMBIGUOUS, CpeMatchStatus.NOT_FOUND}:
        return ApplicabilityStatus.POSSIBLY_AFFECTED, "CPE match is uncertain", 40, []
    if cpe.confidence < 80:
        return ApplicabilityStatus.POSSIBLY_AFFECTED, "CPE confidence is below threshold", 40, []
    if not cve.configurations:
        return ApplicabilityStatus.NOT_EVALUATED, "NVD record has no applicability configuration", 30, []
    if not parse_version(software.version).parts:
        return ApplicabilityStatus.NOT_EVALUATED, "Installed version could not be compared reliably", 30, []

    statuses: list[tuple[ApplicabilityStatus, str, int, list[str]]] = []
    for configuration in cve.configurations:
        statuses.append(_evaluate_configuration(software, cpe, configuration))

    affected = [status for status in statuses if status[0] == ApplicabilityStatus.AFFECTED]
    if affected:
        matched = [criteria for item in affected for criteria in item[3]]
        return ApplicabilityStatus.AFFECTED, "Installed version is within vulnerable CPE criteria", 95, matched

    possible = [status for status in statuses if status[0] == ApplicabilityStatus.POSSIBLY_AFFECTED]
    if possible:
        matched = [criteria for item in possible for criteria in item[3]]
        return ApplicabilityStatus.POSSIBLY_AFFECTED, possible[0][1], 50, matched

    not_evaluated = [status for status in statuses if status[0] == ApplicabilityStatus.NOT_EVALUATED]
    if not_evaluated:
        return not_evaluated[0]

    return ApplicabilityStatus.NOT_AFFECTED, "Installed version is not within vulnerable criteria", 90, []


def _evaluate_configuration(
    software: SoftwareProduct,
    cpe: CpeCandidate,
    configuration: dict[str, Any],
) -> tuple[ApplicabilityStatus, str, int, list[str]]:
    """Evaluate one NVD configuration."""

    nodes = configuration.get("nodes", [])
    if not isinstance(nodes, list):
        return ApplicabilityStatus.NOT_EVALUATED, "Invalid NVD configuration", 20, []
    return _evaluate_nodes(software, cpe, nodes)


def _evaluate_nodes(
    software: SoftwareProduct,
    cpe: CpeCandidate,
    nodes: list[dict[str, Any]],
) -> tuple[ApplicabilityStatus, str, int, list[str]]:
    """Evaluate a list of nodes."""

    results = [_evaluate_node(software, cpe, node) for node in nodes if isinstance(node, dict)]
    if any(result[0] == ApplicabilityStatus.AFFECTED for result in results):
        matched = [criteria for result in results for criteria in result[3]]
        return ApplicabilityStatus.AFFECTED, "OR node matched vulnerable criteria", 95, matched
    if any(result[0] == ApplicabilityStatus.POSSIBLY_AFFECTED for result in results):
        return ApplicabilityStatus.POSSIBLY_AFFECTED, "Potential CPE criteria match requires verification", 50, []
    if any(result[0] == ApplicabilityStatus.NOT_EVALUATED for result in results):
        return ApplicabilityStatus.NOT_EVALUATED, "Configuration could not be fully evaluated", 30, []
    return ApplicabilityStatus.NOT_AFFECTED, "No vulnerable criteria matched", 90, []


def _evaluate_node(
    software: SoftwareProduct,
    cpe: CpeCandidate,
    node: dict[str, Any],
) -> tuple[ApplicabilityStatus, str, int, list[str]]:
    """Evaluate one NVD configuration node."""

    operator = str(node.get("operator", "OR")).upper()
    cpe_matches = node.get("cpeMatch", [])
    children = node.get("children", [])
    if operator == "AND" and children:
        return ApplicabilityStatus.NOT_EVALUATED, "Complex AND configuration requires manual evaluation", 30, []

    results: list[tuple[ApplicabilityStatus, str, int, list[str]]] = []
    if isinstance(cpe_matches, list):
        for match in cpe_matches:
            if isinstance(match, dict):
                results.append(_evaluate_cpe_match(software, cpe, match))
    if isinstance(children, list) and children:
        results.append(_evaluate_nodes(software, cpe, children))

    if operator == "AND":
        if any(result[0] == ApplicabilityStatus.NOT_AFFECTED for result in results):
            return ApplicabilityStatus.NOT_AFFECTED, "AND criteria did not fully match", 90, []
        return ApplicabilityStatus.NOT_EVALUATED, "Simple AND configuration requires corroborating context", 30, []

    if any(result[0] == ApplicabilityStatus.AFFECTED for result in results):
        matched = [criteria for result in results for criteria in result[3]]
        return ApplicabilityStatus.AFFECTED, "Vulnerable CPE criteria matched", 95, matched
    if any(result[0] == ApplicabilityStatus.POSSIBLY_AFFECTED for result in results):
        return ApplicabilityStatus.POSSIBLY_AFFECTED, "Potential CPE criteria match requires verification", 50, []
    if any(result[0] == ApplicabilityStatus.NOT_EVALUATED for result in results):
        return ApplicabilityStatus.NOT_EVALUATED, "CPE criteria could not be evaluated", 30, []
    return ApplicabilityStatus.NOT_AFFECTED, "No CPE criteria matched", 90, []


def _evaluate_cpe_match(
    software: SoftwareProduct,
    cpe: CpeCandidate,
    match: dict[str, Any],
) -> tuple[ApplicabilityStatus, str, int, list[str]]:
    """Evaluate one cpeMatch block."""

    if match.get("vulnerable") is False:
        return ApplicabilityStatus.NOT_AFFECTED, "CPE criteria is marked not vulnerable", 90, []
    criteria = str(match.get("criteria", ""))
    vendor, product, criteria_version = parse_cpe23(criteria)
    if _key(vendor) != _key(cpe.vendor) or _key(product) != _key(cpe.product):
        return ApplicabilityStatus.NOT_AFFECTED, "CPE product mismatch", 90, []

    if any(key in match for key in (
        "versionStartIncluding",
        "versionStartExcluding",
        "versionEndIncluding",
        "versionEndExcluding",
    )):
        return _evaluate_range(software, match, criteria)

    if criteria_version == "*":
        return ApplicabilityStatus.POSSIBLY_AFFECTED, "Wildcard CPE version requires range confirmation", 50, [criteria]
    if criteria_version == "-":
        return ApplicabilityStatus.NOT_EVALUATED, "CPE version has NA semantics", 30, [criteria]
    if compare_versions(software.version, criteria_version) == 0:
        return ApplicabilityStatus.AFFECTED, "Installed version matches vulnerable CPE version", 95, [criteria]
    return ApplicabilityStatus.NOT_AFFECTED, "Installed version does not match vulnerable CPE version", 90, []


def _evaluate_range(
    software: SoftwareProduct,
    match: dict[str, Any],
    criteria: str,
) -> tuple[ApplicabilityStatus, str, int, list[str]]:
    """Evaluate version range criteria."""

    try:
        if "versionStartIncluding" in match and compare_versions(software.version, match["versionStartIncluding"]) < 0:
            return ApplicabilityStatus.NOT_AFFECTED, "Installed version below vulnerable range", 90, []
        if "versionStartExcluding" in match and compare_versions(software.version, match["versionStartExcluding"]) <= 0:
            return ApplicabilityStatus.NOT_AFFECTED, "Installed version below vulnerable range", 90, []
        if "versionEndIncluding" in match and compare_versions(software.version, match["versionEndIncluding"]) > 0:
            return ApplicabilityStatus.NOT_AFFECTED, "Installed version above vulnerable range", 90, []
        if "versionEndExcluding" in match and compare_versions(software.version, match["versionEndExcluding"]) >= 0:
            return ApplicabilityStatus.NOT_AFFECTED, "Installed version above vulnerable range", 90, []
    except Exception:
        return ApplicabilityStatus.POSSIBLY_AFFECTED, "Installed version could not be compared reliably", 45, [criteria]
    return ApplicabilityStatus.AFFECTED, "Installed version is within vulnerable range", 95, [criteria]


def _key(value: str) -> str:
    """Return a loose comparison key."""

    return value.replace("_", " ").casefold().strip()
