"""Version-aware CVE applicability evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cve.cpe_resolver import parse_cpe23_components
from cve.models import ApplicabilityStatus, CpeCandidate, CpeMatchStatus, CveRecord
from software.models import SoftwareProduct
from software.version import compare_versions, parse_version

ENVIRONMENT_COMPONENTS = {
    "update": ("Update", "OSUpdate", "CpeUpdate"),
    "edition": ("Edition", "OSEdition", "WindowsEdition"),
    "language": ("Language", "OSLanguage", "Locale"),
    "sw_edition": ("SoftwareEdition", "SWEdition", "SwEdition", "OSEdition"),
    "target_sw": ("OS", "OSName", "OperatingSystem", "Operating System", "TargetSW"),
    "target_hw": ("Architecture", "OSArchitecture", "SystemType", "TargetHW", "MachineArchitecture"),
}


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    """Internal applicability evaluation result."""

    status: ApplicabilityStatus
    reason: str
    confidence: int
    matched_criteria: list[str]


def evaluate_applicability(
    software: SoftwareProduct,
    cpe: CpeCandidate,
    cve: CveRecord,
    environment_data: dict[str, Any] | None = None,
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

    results = [
        _evaluate_configuration(software, cpe, configuration, environment_data)
        for configuration in cve.configurations
    ]
    combined = _combine_or(results, "CVE configuration")
    return combined.status, combined.reason, combined.confidence, combined.matched_criteria


def _evaluate_configuration(
    software: SoftwareProduct,
    cpe: CpeCandidate,
    configuration: dict[str, Any],
    environment_data: dict[str, Any] | None,
) -> EvaluationResult:
    """Evaluate one NVD configuration object."""

    nodes = configuration.get("nodes", [])
    if not isinstance(nodes, list):
        return _not_evaluated("Invalid NVD configuration")

    operator = _operator(configuration.get("operator", "OR"))
    results = [
        _evaluate_node(software, cpe, node, environment_data)
        for node in nodes
        if isinstance(node, dict)
    ]
    return _combine(operator, results, "Configuration")


def _evaluate_node(
    software: SoftwareProduct,
    cpe: CpeCandidate,
    node: dict[str, Any],
    environment_data: dict[str, Any] | None,
) -> EvaluationResult:
    """Evaluate one NVD configuration node."""

    operator = _operator(node.get("operator", "OR"))
    results: list[EvaluationResult] = []

    cpe_matches = node.get("cpeMatch", [])
    if isinstance(cpe_matches, list):
        results.extend(
            _evaluate_cpe_match(software, cpe, match, environment_data)
            for match in cpe_matches
            if isinstance(match, dict)
        )

    children = node.get("children", [])
    if isinstance(children, list):
        results.extend(
            _evaluate_node(software, cpe, child, environment_data)
            for child in children
            if isinstance(child, dict)
        )

    return _combine(operator, results, "Node")


def _evaluate_cpe_match(
    software: SoftwareProduct,
    cpe: CpeCandidate,
    match: dict[str, Any],
    environment_data: dict[str, Any] | None,
) -> EvaluationResult:
    """Evaluate one cpeMatch block."""

    criteria = str(match.get("criteria", ""))
    parsed = parse_cpe23_components(criteria)
    if parsed is None:
        return _not_evaluated("CPE criteria could not be parsed", [criteria] if criteria else [])

    if match.get("vulnerable") is False:
        return _not_evaluated(
            "Non-vulnerable platform or environment criteria cannot be confirmed",
            [criteria],
        )

    if _key(parsed.vendor) != _key(cpe.vendor) or _key(parsed.product) != _key(cpe.product):
        return _not_affected("CPE product mismatch")

    environment_result = _evaluate_environment(parsed, environment_data)
    if environment_result is not None:
        return environment_result

    if any(
        key in match
        for key in (
            "versionStartIncluding",
            "versionStartExcluding",
            "versionEndIncluding",
            "versionEndExcluding",
        )
    ):
        return _evaluate_range(software, match, criteria)

    if parsed.version == "*":
        return EvaluationResult(
            ApplicabilityStatus.POSSIBLY_AFFECTED,
            "Wildcard CPE version requires range confirmation",
            50,
            [criteria],
        )
    if parsed.version == "-":
        return _not_evaluated("CPE version has NA semantics", [criteria])
    if compare_versions(software.version, parsed.version) == 0:
        return EvaluationResult(
            ApplicabilityStatus.AFFECTED,
            "Installed version matches vulnerable CPE version",
            95,
            [criteria],
        )
    return _not_affected("Installed version does not match vulnerable CPE version")


def _evaluate_range(
    software: SoftwareProduct,
    match: dict[str, Any],
    criteria: str,
) -> EvaluationResult:
    """Evaluate version range criteria."""

    try:
        if "versionStartIncluding" in match and compare_versions(software.version, match["versionStartIncluding"]) < 0:
            return _not_affected("Installed version below vulnerable range")
        if "versionStartExcluding" in match and compare_versions(software.version, match["versionStartExcluding"]) <= 0:
            return _not_affected("Installed version below vulnerable range")
        if "versionEndIncluding" in match and compare_versions(software.version, match["versionEndIncluding"]) > 0:
            return _not_affected("Installed version above vulnerable range")
        if "versionEndExcluding" in match and compare_versions(software.version, match["versionEndExcluding"]) >= 0:
            return _not_affected("Installed version above vulnerable range")
    except Exception:
        return EvaluationResult(
            ApplicabilityStatus.POSSIBLY_AFFECTED,
            "Installed version could not be compared reliably",
            45,
            [criteria],
        )
    return EvaluationResult(
        ApplicabilityStatus.AFFECTED,
        "Installed version is within vulnerable range",
        95,
        [criteria],
    )


def _evaluate_environment(
    parsed: Any,
    environment_data: dict[str, Any] | None,
) -> EvaluationResult | None:
    """Evaluate CPE environment components that constrain applicability."""

    for component, keys in ENVIRONMENT_COMPONENTS.items():
        criteria_value = str(getattr(parsed, component))
        if criteria_value == "*":
            continue

        observed = _read_environment_value(environment_data, keys)
        if observed is None:
            return _not_evaluated(f"CPE environment component {component} cannot be confirmed")
        if not _environment_matches(component, criteria_value, observed):
            return _not_affected(f"CPE environment component {component} does not match collector data")

    return None


def _read_environment_value(
    environment_data: dict[str, Any] | None,
    keys: tuple[str, ...],
) -> str | None:
    """Read a trusted collector environment value by any known alias."""

    if not environment_data:
        return None

    lowered = {str(key).casefold(): value for key, value in environment_data.items()}
    for key in keys:
        value = lowered.get(key.casefold())
        if value is not None and str(value).strip():
            return str(value)
    return None


def _environment_matches(component: str, criteria_value: str, observed_value: str) -> bool:
    """Return whether collector data satisfies a CPE environment component."""

    criteria = _normalise_environment(criteria_value)
    observed = _normalise_environment(observed_value)
    if component == "target_hw":
        criteria = _normalise_architecture(criteria)
        observed = _normalise_architecture(observed)
        return criteria == observed or criteria in observed
    if component == "target_sw":
        return criteria == observed or criteria in observed
    return criteria == observed or criteria in observed


def _normalise_architecture(value: str) -> str:
    """Normalize common architecture names."""

    aliases = {
        "amd64": "x64",
        "x86 64": "x64",
        "x86_64": "x64",
        "64 bit": "x64",
        "64bit": "x64",
        "i386": "x86",
        "i686": "x86",
        "32 bit": "x86",
        "32bit": "x86",
    }
    return aliases.get(value, value)


def _normalise_environment(value: str) -> str:
    """Normalize CPE and collector environment values for comparison."""

    return (
        value.replace("_", " ")
        .replace("-", " ")
        .casefold()
        .strip()
    )


def _combine(operator: str, results: list[EvaluationResult], scope: str) -> EvaluationResult:
    """Combine node/configuration results according to NVD operator semantics."""

    if operator == "AND":
        return _combine_and(results, scope)
    return _combine_or(results, scope)


def _combine_or(results: list[EvaluationResult], scope: str) -> EvaluationResult:
    """Combine OR results."""

    if not results:
        return _not_evaluated(f"{scope} has no evaluable criteria")

    affected = [result for result in results if result.status == ApplicabilityStatus.AFFECTED]
    if affected:
        return EvaluationResult(
            ApplicabilityStatus.AFFECTED,
            "Installed version is within vulnerable CPE criteria",
            95,
            _criteria(affected),
        )

    possible = [result for result in results if result.status == ApplicabilityStatus.POSSIBLY_AFFECTED]
    if possible:
        return EvaluationResult(
            ApplicabilityStatus.POSSIBLY_AFFECTED,
            possible[0].reason,
            50,
            _criteria(possible),
        )

    not_evaluated = [result for result in results if result.status == ApplicabilityStatus.NOT_EVALUATED]
    if not_evaluated:
        return EvaluationResult(
            ApplicabilityStatus.NOT_EVALUATED,
            not_evaluated[0].reason,
            30,
            _criteria(not_evaluated),
        )

    not_affected = [result for result in results if result.status == ApplicabilityStatus.NOT_AFFECTED]
    if not_affected:
        return _not_affected(not_affected[0].reason)
    return _not_affected("No vulnerable criteria matched")


def _combine_and(results: list[EvaluationResult], scope: str) -> EvaluationResult:
    """Combine AND results without over-confirming partial matches."""

    if not results:
        return _not_evaluated(f"{scope} has no evaluable criteria")

    if all(result.status == ApplicabilityStatus.AFFECTED for result in results):
        return EvaluationResult(
            ApplicabilityStatus.AFFECTED,
            "All AND criteria matched vulnerable CPE criteria",
            95,
            _criteria(results),
        )

    if any(result.status == ApplicabilityStatus.NOT_EVALUATED for result in results):
        return EvaluationResult(
            ApplicabilityStatus.NOT_EVALUATED,
            "AND configuration depends on criteria CSA cannot confirm",
            30,
            _criteria(results),
        )

    if any(result.status == ApplicabilityStatus.POSSIBLY_AFFECTED for result in results):
        return EvaluationResult(
            ApplicabilityStatus.POSSIBLY_AFFECTED,
            "AND configuration has uncertain criteria",
            45,
            _criteria(results),
        )

    if any(result.status == ApplicabilityStatus.AFFECTED for result in results):
        return EvaluationResult(
            ApplicabilityStatus.NOT_EVALUATED,
            "AND configuration has a partial vulnerable match only",
            30,
            _criteria(results),
        )

    return _not_affected("No AND criteria matched")


def _criteria(results: list[EvaluationResult]) -> list[str]:
    """Collect matched criteria from child results."""

    return [criteria for result in results for criteria in result.matched_criteria]


def _operator(value: object) -> str:
    """Return a supported NVD operator."""

    operator = str(value).upper()
    if operator not in {"AND", "OR"}:
        return "OR"
    return operator


def _not_evaluated(reason: str, criteria: list[str] | None = None) -> EvaluationResult:
    """Create a not-evaluated result."""

    return EvaluationResult(ApplicabilityStatus.NOT_EVALUATED, reason, 30, criteria or [])


def _not_affected(reason: str) -> EvaluationResult:
    """Create a not-affected result."""

    return EvaluationResult(ApplicabilityStatus.NOT_AFFECTED, reason, 90, [])


def _key(value: str) -> str:
    """Return a loose comparison key."""

    return value.replace("_", " ").casefold().strip()
