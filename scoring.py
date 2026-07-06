"""Security scoring helpers for Collector Security Analyzer."""

from __future__ import annotations

import logging
from collections.abc import Iterable

from risk import Finding, Severity, Status

LOGGER = logging.getLogger(__name__)
DEFAULT_BASE_SCORE = 100
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: -30,
    Severity.HIGH: -20,
    Severity.MEDIUM: -10,
    Severity.LOW: -5,
    Severity.INFO: 0,
}


def calculate_score(findings: Iterable[Finding], base_score: int = DEFAULT_BASE_SCORE) -> int:
    """Calculate the overall security score from findings."""

    score = base_score
    for finding in findings:
        if finding.status == Status.PASS:
            delta = 0
        elif finding.score is not None:
            delta = -abs(int(finding.score))
        else:
            delta = SEVERITY_WEIGHTS.get(finding.severity, 0)
        score += delta

    bounded_score = max(0, min(100, score))
    LOGGER.debug("Calculated security score: %s", bounded_score)
    return bounded_score
