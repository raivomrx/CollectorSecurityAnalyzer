"""Compliance evidence coverage helpers."""

from __future__ import annotations

from compliance.enums import EvidenceResult
from compliance.models import ControlAssessment


def evidence_coverage(controls: list[ControlAssessment]) -> float:
    """Calculate evidence coverage for applicable controls."""

    requirements = 0
    covered = 0
    for control in controls:
        if not control.applicable:
            continue
        for evidence in control.evidence:
            requirements += 1
            if evidence.result not in {EvidenceResult.MISSING, EvidenceResult.NOT_APPLICABLE}:
                covered += 1
    if requirements == 0:
        return 0.0
    return round((covered / requirements) * 100, 1)
