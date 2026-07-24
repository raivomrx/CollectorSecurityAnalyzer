"""Capability-aware endpoint collection coverage."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from csa_console.capabilities import CapabilityRegistry, CollectionProfile
from csa_console.enums import CapabilityStatus, CoverageDomain
from csa_console.models import AssessmentCoverage, CoverageLimitation


def calculate_coverage(
    capability_results: list[dict[str, Any]],
    registry: CapabilityRegistry | None = None,
    profile: CollectionProfile | None = None,
) -> AssessmentCoverage:
    """Calculate domain coverage without turning unknowns into failures."""

    active_registry = registry or CapabilityRegistry()
    active_profile = profile or CollectionProfile.load(registry=active_registry)
    by_id = {
        str(item.get("capabilityId")): item for item in capability_results
    }
    domain_values: dict[CoverageDomain, list[float]] = defaultdict(list)
    limitations: list[CoverageLimitation] = []
    for capability_id in active_profile.capability_ids:
        definition = active_registry.get(capability_id)
        result = by_id.get(capability_id)
        score = 0.0
        reason = "NOT_COLLECTED"
        if result is not None:
            status = CapabilityStatus(str(result.get("status")))
            if status == CapabilityStatus.COLLECTED:
                score = 100.0
            elif status == CapabilityStatus.COLLECTED_PARTIAL:
                expected = int(result.get("expectedEvidenceCount", 0) or 0)
                collected = int(result.get("evidenceCount", 0) or 0)
                score = (
                    round(min(100.0, collected * 100.0 / expected), 1)
                    if expected > 0
                    else 50.0
                )
            else:
                reason = str(
                    result.get("limitationCode")
                    or status.value.removeprefix("NOT_COLLECTED_")
                )
        domain_values[definition.coverage_domain].append(score)
        if score < 100.0:
            limitations.append(
                CoverageLimitation(
                    capability_id=capability_id,
                    domain=definition.coverage_domain,
                    reason=reason if score == 0.0 else "PARTIAL",
                )
            )
    coverage_by_domain: dict[str, float] = {}
    for domain in CoverageDomain:
        values = domain_values.get(domain, [])
        coverage_by_domain[domain.value] = (
            round(sum(values) / len(values), 1) if values else 0.0
        )
    collection_domains = [
        value
        for domain, values in domain_values.items()
        if domain != CoverageDomain.ACTIVE_VALIDATION
        for value in values
    ]
    overall = (
        round(sum(collection_domains) / len(collection_domains), 1)
        if collection_domains
        else 0.0
    )
    limitations.sort(key=lambda item: (item.domain.value, item.capability_id))
    return AssessmentCoverage(
        overall_coverage_percent=overall,
        coverage_by_domain=coverage_by_domain,
        limitations=limitations,
    )
