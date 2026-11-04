"""Version- and evidence-aware NVD CVE applicability."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cve.cpe_resolver import ParsedCpe23, parse_cpe23_components
from cve.environment import ARCH_KEYS, OS_KEYS, architecture_identity, environment_key, platform_matches, read_environment
from cve.models import ApplicabilityStatus, CpeCandidate, CpeMatchStatus, CveRecord
from software.models import SoftwareProduct
from software.version import compare_applicability_versions, version_evidence

ENVIRONMENT_COMPONENTS = {
    "update": ("Update", "OSUpdate", "CpeUpdate"),
    "edition": ("Edition", "OSEdition", "WindowsEdition", "operatingSystem.edition"),
    "language": ("Language", "OSLanguage", "Locale", "operatingSystem.language"),
    "sw_edition": ("SoftwareEdition", "SWEdition", "SwEdition"),
}
OS_VERSION_KEYS = ("OSVersion", "OperatingSystemVersion", "operatingSystem.version")
START = ("versionStartIncluding", "versionStartExcluding")
END = ("versionEndIncluding", "versionEndExcluding")


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    status: ApplicabilityStatus
    reason: str
    confidence: int
    matched_criteria: list[str]
    has_vulnerable_match: bool = False
    reason_code: str = "APPLICABILITY_INCOMPLETE"


def evaluate_applicability(
    software: SoftwareProduct, cpe: CpeCandidate, cve: CveRecord,
    environment_data: dict[str, Any] | None = None,
) -> tuple[ApplicabilityStatus, str, int, list[str]]:
    result = evaluate_applicability_result(software, cpe, cve, environment_data)
    return result.status, result.reason, result.confidence, result.matched_criteria


def evaluate_applicability_result(
    software: SoftwareProduct, cpe: CpeCandidate, cve: CveRecord,
    environment_data: dict[str, Any] | None = None,
) -> EvaluationResult:
    identity = parse_cpe23_components(cpe.cpe_name)
    if cpe.deprecated or cpe.match_status in {CpeMatchStatus.AMBIGUOUS, CpeMatchStatus.NOT_FOUND} or cpe.confidence < 80 or identity is None:
        return _unknown("MISSING_AUTHORITATIVE_PRODUCT_MAPPING", "CPE product identity is uncertain")
    version = version_evidence(software.vendor, software.product, software.version)
    if version.reason:
        return _unknown(version.reason, "Installed version evidence could not be established")
    if not cve.configurations:
        return _unknown("APPLICABILITY_INCOMPLETE", "NVD record has no applicability configuration")
    if str(cve.vuln_status).casefold() == "rejected" or cve.cve_id == "UNKNOWN":
        return _unknown("APPLICABILITY_INCOMPLETE", "NVD record has no active CVE identity")
    result = _combine("OR", [
        _evaluate_node(software, cpe, identity, config, environment_data)
        for config in cve.configurations
    ])
    if result.status == ApplicabilityStatus.AFFECTED and not result.has_vulnerable_match:
        return _unknown("APPLICABILITY_INCOMPLETE", "CVE configuration contains no confirmed vulnerable software criteria", result.matched_criteria)
    return result


def _evaluate_node(
    software: SoftwareProduct, cpe: CpeCandidate, identity: ParsedCpe23,
    node: Any, environment: dict[str, Any] | None,
) -> EvaluationResult:
    if not isinstance(node, dict) or node.get("negate", False) is not False:
        return _unknown("APPLICABILITY_INCOMPLETE", "Invalid or negated NVD applicability node")
    operator = str(node.get("operator", "OR")).upper()
    if operator not in {"AND", "OR"}:
        return _unknown("APPLICABILITY_INCOMPLETE", "Unsupported NVD applicability operator")
    results = []
    for key in ("nodes", "children", "cpeMatch"):
        values = node.get(key, [])
        if not isinstance(values, list):
            return _unknown("APPLICABILITY_INCOMPLETE", "Malformed NVD applicability criteria")
        for value in values:
            if key == "cpeMatch":
                results.append(_evaluate_match(software, cpe, identity, value, environment))
            else:
                results.append(_evaluate_node(software, cpe, identity, value, environment))
    return _combine(operator, results)


def _evaluate_match(
    software: SoftwareProduct, cpe: CpeCandidate, identity: ParsedCpe23,
    match: Any, environment: dict[str, Any] | None,
) -> EvaluationResult:
    if not isinstance(match, dict) or type(match.get("vulnerable")) is not bool:
        return _unknown("APPLICABILITY_INCOMPLETE", "Invalid NVD vulnerability criterion")
    criteria = str(match.get("criteria", ""))
    parsed = parse_cpe23_components(criteria)
    if parsed is None:
        return _unknown("APPLICABILITY_INCOMPLETE", "CPE criteria could not be parsed")
    vulnerable = match["vulnerable"]
    if parsed.part == "o" and not vulnerable:
        platform = platform_matches(parsed.product, read_environment(environment, OS_KEYS), exact_product=True)
        if platform is None:
            return _unknown("PLATFORM_UNKNOWN", "Operating-system applicability constraint cannot be confirmed", [criteria])
        if not platform:
            return _excluded("PLATFORM_MISMATCH_CONFIRMED", "Collected operating system excludes the required platform", criteria)
        installed, scheme = read_environment(environment, OS_VERSION_KEYS), "numeric"
    else:
        if parsed.part not in {"a", "o"} or any(value in {"*", "-"} for value in (parsed.vendor, parsed.product)):
            return _unknown("MISSING_AUTHORITATIVE_PRODUCT_MAPPING", "CPE criterion has no concrete product identity", [criteria])
        if parsed.part != identity.part or (environment_key(parsed.vendor), environment_key(parsed.product)) != (
            environment_key(cpe.vendor), environment_key(cpe.product)
        ):
            if vulnerable:
                return _excluded("PRODUCT_MISMATCH_CONFIRMED", "Vulnerable criterion describes a different product", criteria)
            return _unknown("MISSING_AUTHORITATIVE_PRODUCT_MAPPING", "Prerequisite application is outside the evaluated product", [criteria])
        evidence = version_evidence(software.vendor, software.product, software.version)
        installed, scheme = evidence.interpreted, evidence.scheme

    exact = parsed.version
    if parsed.part == "o" and not vulnerable and exact == "-" and not any(key in match for key in (*START, *END)):
        # This platform prerequisite names an OS family without a version axis.
        exact = "*"
    version = _evaluate_version(installed, scheme, exact, match, criteria, vulnerable)
    environment_result = _evaluate_environment(parsed, software, identity, environment, criteria)
    return _combine("AND", [version, environment_result]) if environment_result else version


def _evaluate_version(
    installed: str | None, scheme: str, exact: str, match: dict[str, Any], criteria: str, vulnerable: bool,
) -> EvaluationResult:
    if exact == "-":
        return _unknown("CPE_VERSION_NA", "CPE version has NA semantics", [criteria])
    starts, ends = ([key for key in keys if key in match] for keys in (START, END))
    if len(starts) > 1 or len(ends) > 1:
        return _unknown("APPLICABILITY_INCOMPLETE", "NVD range contains duplicate bounds", [criteria])
    if starts and ends:
        order = compare_applicability_versions(match[starts[0]], match[ends[0]], scheme)
        if order.order is None:
            return _unknown(order.reason or "VERSION_INCOMPARABLE", "NVD range bounds use incompatible version evidence", [criteria])
        if order.order > 0 or (order.order == 0 and (starts[0].endswith("Excluding") or ends[0].endswith("Excluding"))):
            return _unknown("APPLICABILITY_INCOMPLETE", "NVD range bounds are contradictory", [criteria])
    if exact == "*" and not starts and not ends and vulnerable:
        return _unknown("APPLICABILITY_INCOMPLETE", "Wildcard CPE version has no reliable affected-version range", [criteria])
    tests = [(match[key], allowed) for key, allowed in (
        (START[0], {0, 1}), (START[1], {1}), (END[0], {-1, 0}), (END[1], {-1})
    ) if key in match]
    if exact != "*":
        tests.append((exact, {0}))
    comparisons = [(compare_applicability_versions(installed, bound, scheme), allowed) for bound, allowed in tests]
    for comparison, _ in comparisons:
        if comparison.order is None:
            return _unknown(comparison.reason or "VERSION_INCOMPARABLE", "Installed version cannot be compared reliably with NVD version criteria", [criteria])
    if any(comparison.order not in allowed for comparison, allowed in comparisons):
        return _excluded("VERSION_OUTSIDE_RANGE", "Installed version is outside the NVD version criteria", criteria)
    return EvaluationResult(ApplicabilityStatus.AFFECTED, "Installed version matches vulnerable NVD criteria" if vulnerable else "NVD prerequisite matched", 95, [criteria], vulnerable, "VERSION_MATCH")


def _evaluate_environment(
    parsed: ParsedCpe23, software: SoftwareProduct, identity: ParsedCpe23,
    environment: dict[str, Any] | None, criteria: str,
) -> EvaluationResult | None:
    unknown = None
    if parsed.target_sw != "*":
        platform = platform_matches(parsed.target_sw, read_environment(environment, OS_KEYS + ("TargetSW",)), exact_product=True)
        if platform is False:
            return _excluded("PLATFORM_MISMATCH_CONFIRMED", "Collected operating system excludes the required platform", criteria)
        if platform is None:
            unknown = _unknown("PLATFORM_UNKNOWN", "CPE platform (target_sw) cannot be confirmed", [criteria])
    if parsed.target_hw != "*":
        observed = software.architecture if parsed.part == "a" else read_environment(environment, ARCH_KEYS)
        actual, expected = architecture_identity(observed), architecture_identity(parsed.target_hw)
        if actual and expected and actual != expected:
            return _excluded("ARCH_MISMATCH_CONFIRMED", "Collected product architecture excludes the required architecture", criteria)
        if not (actual and expected) and unknown is None:
            unknown = _unknown("ARCH_UNKNOWN", "CPE architecture (target_hw) cannot be confirmed from the relevant product evidence", [criteria])
    for component, keys in ENVIRONMENT_COMPONENTS.items():
        expected_value = getattr(parsed, component)
        if expected_value == "*":
            continue
        if component == "sw_edition" and parsed.part == "a" and identity.sw_edition not in {"*", "-"}:
            if expected_value != "-" and environment_key(identity.sw_edition) != environment_key(expected_value):
                return _excluded("EDITION_MISMATCH_CONFIRMED", "CPE software edition differs from the validated product identity", criteria)
            observed_value = identity.sw_edition
        else:
            observed_value = read_environment(environment, keys)
        if component == "edition" and observed_value:
            editions = {"professional": "pro", "pro": "pro", "enterprise": "enterprise", "education": "education", "home": "home"}
            expected_edition = editions.get(environment_key(expected_value))
            actual_edition = editions.get(environment_key(observed_value))
            if expected_edition and actual_edition:
                if expected_edition != actual_edition:
                    return _excluded("EDITION_MISMATCH_CONFIRMED", "Observed edition excludes the required CPE edition", criteria)
                continue
        if not observed_value or expected_value == "-" or environment_key(observed_value) != environment_key(expected_value):
            if unknown is None:
                unknown = _unknown("EDITION_UNKNOWN" if "edition" in component else "APPLICABILITY_INCOMPLETE",
                                   f"CPE environment component {component} cannot be confirmed", [criteria])
    if parsed.other != "*" and unknown is None:
        unknown = _unknown("APPLICABILITY_INCOMPLETE", "CPE other component cannot be confirmed", [criteria])
    return unknown


def _combine(operator: str, results: list[EvaluationResult]) -> EvaluationResult:
    if not results:
        return _unknown("APPLICABILITY_INCOMPLETE", "NVD configuration has no evaluable criteria")
    if operator == "AND":
        excluded = next((item for item in results if item.status == ApplicabilityStatus.NOT_AFFECTED), None)
        if excluded:
            return excluded
        unknown = next((item for item in results if item.status != ApplicabilityStatus.AFFECTED), None)
        if unknown:
            return _unknown(unknown.reason_code, f"AND constraint unresolved: {unknown.reason}", unknown.matched_criteria)
        affected = results
    else:
        affected = [item for item in results if item.status == ApplicabilityStatus.AFFECTED and item.has_vulnerable_match]
        if not affected:
            unknown = next((item for item in results if item.status == ApplicabilityStatus.NOT_EVALUATED), None)
            if unknown:
                return unknown
            if all(item.status == ApplicabilityStatus.NOT_AFFECTED for item in results):
                return results[0]
            affected = [item for item in results if item.status == ApplicabilityStatus.AFFECTED]
    return EvaluationResult(
        ApplicabilityStatus.AFFECTED, affected[0].reason, 95,
        [criterion for item in affected for criterion in item.matched_criteria],
        any(item.has_vulnerable_match for item in affected), affected[0].reason_code,
    )


def _unknown(code: str, reason: str, criteria: list[str] | None = None) -> EvaluationResult:
    return EvaluationResult(ApplicabilityStatus.NOT_EVALUATED, reason, 30, criteria or [], reason_code=code)


def _excluded(code: str, reason: str, criteria: str) -> EvaluationResult:
    return EvaluationResult(ApplicabilityStatus.NOT_AFFECTED, reason, 90, [criteria], reason_code=code)
