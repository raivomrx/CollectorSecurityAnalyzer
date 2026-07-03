"""Security scoring helpers for Collector Security Analyzer."""

from __future__ import annotations

import logging
from collections.abc import Iterable

from risk import Finding

LOGGER = logging.getLogger(__name__)
DEFAULT_BASE_SCORE = 100
SEVERITY_WEIGHTS = {
    "HIGH": -20,
    "MEDIUM": -10,
    "LOW": -5,
    "INFO": 0,
    "PASS": 0,
}


def calculate_score(findings: Iterable[Finding], base_score: int = DEFAULT_BASE_SCORE) -> int:
    """Calculate the overall security score from findings."""

    score = base_score
    for finding in findings:
        if finding.status.upper() == "PASS":
            delta = 0
        elif finding.score is not None:
            delta = -abs(int(finding.score))
        else:
            delta = SEVERITY_WEIGHTS.get(finding.severity.upper(), 0)
        score += delta

    bounded_score = max(0, min(100, score))
    LOGGER.debug("Calculated security score: %s", bounded_score)
    return bounded_score
