"""Deterministic vulnerability prioritization separate from CVSS."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from cve.enrichment_models import ExploitationStatus, RansomwareUse, SsvcExploitation
from cve.models import ApplicabilityStatus, CveAssessment
from cve.provenance import ConflictType, DataConflict


class PriorityLevel(str, Enum):
    """CSA vulnerability priority levels."""

    P1_IMMEDIATE = "P1_IMMEDIATE"
    P2_URGENT = "P2_URGENT"
    P3_PLANNED = "P3_PLANNED"
    P4_MONITOR = "P4_MONITOR"
    MANUAL_REVIEW = "MANUAL_REVIEW"


@dataclass(slots=True)
class VulnerabilityPriority:
    """Represent priority score and rationale."""

    level: PriorityLevel
    score: int
    reasons: list[str] = field(default_factory=list)


DEFAULT_WEIGHTS = {
    "KevWeight": 50,
    "RansomwareWeight": 15,
    "AffectedWeight": 20,
    "PossibleWeight": 10,
    "CriticalCvssWeight": 15,
    "HighCvssWeight": 10,
    "MediumCvssWeight": 5,
    "CnaConfirmationWeight": 10,
    "AdpExploitationWeight": 5,
    "AdpPocWeight": 0,
    "ConflictPenalty": 20,
}


def calculate_priority(
    assessment: CveAssessment,
    exploitation_status: ExploitationStatus,
    ransomware_use: RansomwareUse,
    cna_applicability: ApplicabilityStatus,
    conflicts: list[DataConflict],
    adp_exploitation_evidence: bool = False,
    adp_exploitation_status: SsvcExploitation = SsvcExploitation.UNKNOWN,
    weights: dict[str, Any] | None = None,
) -> VulnerabilityPriority:
    """Calculate a deterministic vulnerability priority."""

    active_weights = dict(DEFAULT_WEIGHTS)
    if weights:
        active_weights.update({key: int(value) for key, value in weights.items() if key in active_weights})

    score = 0
    reasons: list[str] = []

    if exploitation_status == ExploitationStatus.KNOWN_EXPLOITED:
        score += active_weights["KevWeight"]
        reasons.append("CISA KEV membership")
    if ransomware_use == RansomwareUse.KNOWN:
        score += active_weights["RansomwareWeight"]
        reasons.append("Known ransomware campaign use")
    if assessment.applicability == ApplicabilityStatus.AFFECTED:
        score += active_weights["AffectedWeight"]
        reasons.append("NVD applicability confirmed affected")
    elif assessment.applicability == ApplicabilityStatus.POSSIBLY_AFFECTED:
        score += active_weights["PossibleWeight"]
        reasons.append("NVD applicability possibly affected")

    cvss = assessment.cve.cvss_score
    if cvss is not None:
        if cvss >= 9.0:
            score += active_weights["CriticalCvssWeight"]
            reasons.append("CVSS critical")
        elif cvss >= 7.0:
            score += active_weights["HighCvssWeight"]
            reasons.append("CVSS high")
        elif cvss >= 4.0:
            score += active_weights["MediumCvssWeight"]
            reasons.append("CVSS medium")

    if cna_applicability == ApplicabilityStatus.AFFECTED:
        score += active_weights["CnaConfirmationWeight"]
        reasons.append("CNA confirms affected version")
    if adp_exploitation_status == SsvcExploitation.ACTIVE:
        score += active_weights["AdpExploitationWeight"]
        reasons.append("ADP exploitation evidence")
    elif adp_exploitation_status == SsvcExploitation.POC and active_weights["AdpPocWeight"]:
        score += active_weights["AdpPocWeight"]
        reasons.append("ADP proof-of-concept exploitation evidence")

    manual_conflicts = [conflict for conflict in conflicts if conflict.requires_manual_review]
    if manual_conflicts:
        score -= active_weights["ConflictPenalty"]
        reasons.append("Source conflict requires manual review")
    score = max(0, score)

    if _requires_manual_review(assessment, manual_conflicts):
        return VulnerabilityPriority(PriorityLevel.MANUAL_REVIEW, score, reasons)
    if score >= 70:
        return VulnerabilityPriority(PriorityLevel.P1_IMMEDIATE, score, reasons)
    if score >= 50:
        return VulnerabilityPriority(PriorityLevel.P2_URGENT, score, reasons)
    if score >= 25:
        return VulnerabilityPriority(PriorityLevel.P3_PLANNED, score, reasons)
    return VulnerabilityPriority(PriorityLevel.P4_MONITOR, score, reasons)


def _requires_manual_review(
    assessment: CveAssessment,
    conflicts: list[DataConflict],
) -> bool:
    """Return whether conflicts block a reliable priority decision."""

    if not conflicts:
        return False
    return any(
        conflict.conflict_type == ConflictType.AFFECTED_VERSION_DISAGREEMENT
        and assessment.applicability != ApplicabilityStatus.AFFECTED
        for conflict in conflicts
    )
