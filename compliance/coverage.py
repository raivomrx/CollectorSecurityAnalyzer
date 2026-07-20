"""Compliance evidence coverage helpers."""

from __future__ import annotations

from compliance.models import ControlAssessment


def evidence_coverage(controls: list[ControlAssessment]) -> float:
    """Calculate evidence coverage for applicable controls."""

    requirements = 0
    covered = 0
    for control in controls:
        if not control.applicable:
            continue
        requirements += control.evidence_requirement_count
        covered += control.covered_evidence_requirement_count
    if requirements == 0:
        return 0.0
    return round((covered / requirements) * 100, 1)
