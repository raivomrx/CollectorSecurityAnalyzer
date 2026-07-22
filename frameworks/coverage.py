"""Coverage metrics for framework pack evaluations."""

from __future__ import annotations

from collections import Counter

from frameworks.enums import (
    AutomationCapability,
    FrameworkControlLevel,
    FrameworkControlStatus,
    MappingStatus,
)
from frameworks.models import FrameworkControlResult, FrameworkCoverage, FrameworkPack


def calculate_coverage(
    pack: FrameworkPack,
    results: tuple[FrameworkControlResult, ...],
) -> FrameworkCoverage:
    """Calculate named metrics without presenting an overall compliance percent."""

    total = len(pack.controls)
    mapped = sum(
        any(mapping.status != MappingStatus.DEPRECATED for mapping in control.mappings)
        for control in pack.controls
    )
    validated_mapped = sum(
        any(mapping.status == MappingStatus.VALIDATED for mapping in control.mappings)
        for control in pack.controls
    )
    automated = sum(
        control.automation == AutomationCapability.AUTOMATED for control in pack.controls
    )
    partial = sum(
        control.automation == AutomationCapability.PARTIAL for control in pack.controls
    )
    manual = sum(control.automation == AutomationCapability.MANUAL for control in pack.controls)
    technical = [
        control for control in pack.controls
        if control.level == FrameworkControlLevel.TECHNICAL
    ]
    technical_automated = sum(
        control.automation == AutomationCapability.AUTOMATED for control in technical
    )
    result_by_id = {result.control_id: result for result in results}
    assessable_ids = {
        control.control_id
        for control in pack.controls
        if control.automation not in {
            AutomationCapability.MANUAL,
            AutomationCapability.NOT_APPLICABLE,
        }
        and any(mapping.status == MappingStatus.VALIDATED for mapping in control.mappings)
        and result_by_id.get(control.control_id, None) is not None
        and result_by_id[control.control_id].status != FrameworkControlStatus.NOT_APPLICABLE
    }
    evaluated_statuses = {
        FrameworkControlStatus.SATISFIED,
        FrameworkControlStatus.NOT_SATISFIED,
        FrameworkControlStatus.PARTIALLY_SATISFIED,
    }
    evaluated = [
        result for result in results
        if result.control_id in assessable_ids and result.status in evaluated_statuses
    ]
    counts = Counter(result.status for result in results)
    return FrameworkCoverage(
        framework_control_count=total,
        mapped_control_count=mapped,
        validated_mapped_control_count=validated_mapped,
        unmapped_control_count=total - mapped,
        automated_control_count=automated,
        partially_automated_control_count=partial,
        manual_control_count=manual,
        assessable_control_count=len(assessable_ids),
        evaluated_control_count=len(evaluated),
        satisfied_control_count=counts[FrameworkControlStatus.SATISFIED],
        not_satisfied_control_count=counts[FrameworkControlStatus.NOT_SATISFIED],
        partially_satisfied_control_count=counts[FrameworkControlStatus.PARTIALLY_SATISFIED],
        not_assessable_control_count=counts[FrameworkControlStatus.NOT_ASSESSABLE],
        mapping_coverage_percent=_percent(mapped, total),
        validated_mapping_coverage_percent=_percent(validated_mapped, total),
        traceability_coverage_percent=_percent(mapped, total),
        formal_assessment_coverage_percent=_percent(len(evaluated), len(assessable_ids)),
        technical_automation_coverage_percent=_percent(technical_automated, len(technical)),
        assessment_coverage_percent=_percent(len(evaluated), len(assessable_ids)),
        satisfied_assessable_controls_percent=_percent(
            sum(result.status == FrameworkControlStatus.SATISFIED for result in evaluated),
            len(evaluated),
        ),
    )


def _percent(numerator: int, denominator: int) -> float:
    """Return a bounded percentage with an explicit zero denominator."""

    return round(numerator / denominator * 100, 1) if denominator else 0.0
