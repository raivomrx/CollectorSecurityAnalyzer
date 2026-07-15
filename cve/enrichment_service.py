"""Multi-source CVE enrichment orchestration."""

from __future__ import annotations

import logging
from typing import Any

from cve.cna_applicability import evaluate_cna_applicability
from cve.enrichment_models import (
    EnrichedCveAssessment,
    EnrichedCveScanSummary,
    ExploitationStatus,
    KevRecord,
    ProviderExecutionState,
    ProviderStatus,
    RansomwareUse,
    ReferenceRecord,
    SourceEnrichment,
    SourceType,
    SsvcDecision,
    SsvcExploitation,
)
from cve.models import ApplicabilityStatus, CveAssessment, CveScanSummary
from cve.prioritization import PriorityLevel, calculate_priority
from cve.providers.base import VulnerabilityDataProvider
from cve.provenance import ConflictType, DataConflict, ProvenanceRecord, retrieved_now

LOGGER = logging.getLogger(__name__)
ENRICHED_STATUSES = {
    ApplicabilityStatus.AFFECTED,
    ApplicabilityStatus.POSSIBLY_AFFECTED,
    ApplicabilityStatus.NOT_EVALUATED,
}


class VulnerabilityEnrichmentService:
    """Enrich NVD CVE assessments with additional official sources."""

    def __init__(
        self,
        providers: list[VulnerabilityDataProvider],
        prioritization_weights: dict[str, Any] | None = None,
        enrich_not_affected: bool = False,
    ) -> None:
        """Create an enrichment service."""

        self.providers = providers
        self.prioritization_weights = prioritization_weights or {}
        self.enrich_not_affected = enrich_not_affected

    def enrich_summary(self, summary: CveScanSummary) -> EnrichedCveScanSummary:
        """Enrich a CVE scan summary."""

        cache: dict[str, list[SourceEnrichment]] = {}
        execution_states = {
            provider.name: ProviderExecutionState(provider=provider.name)
            for provider in self.providers
        }
        enriched: list[EnrichedCveAssessment] = []
        eligible_ids: set[str] = set()
        enriched_ids: set[str] = set()
        for assessment in summary.assessments:
            if not self.enrich_not_affected and assessment.applicability not in ENRICHED_STATUSES:
                continue
            cve_id = assessment.cve.cve_id
            eligible_ids.add(cve_id)
            if cve_id not in cache:
                cache[cve_id] = self._load_enrichments(cve_id, execution_states)
            if cache[cve_id]:
                enriched_ids.add(cve_id)
            enriched.append(self._enrich_assessment(assessment, cache[cve_id]))

        provider_statuses = [_provider_status(state) for state in execution_states.values()]
        unique_enriched_cves = len({item.base_assessment.cve.cve_id for item in enriched})
        enriched_assessment_count = len(enriched)
        unique_known_exploited_cves = len(
            {
                item.base_assessment.cve.cve_id
                for item in enriched
                if item.exploitation_status == ExploitationStatus.KNOWN_EXPLOITED
            }
        )
        known_exploited_count = sum(
            1 for item in enriched if item.exploitation_status == ExploitationStatus.KNOWN_EXPLOITED
        )
        unique_ransomware_cves = len(
            {
                item.base_assessment.cve.cve_id
                for item in enriched
                if item.kev and item.kev.known_ransomware_campaign_use == RansomwareUse.KNOWN
            }
        )
        ransomware_known_count = sum(
            1 for item in enriched
            if item.kev and item.kev.known_ransomware_campaign_use == RansomwareUse.KNOWN
        )
        cna_confirmed_count = sum(
            1 for item in enriched if item.cna_applicability == ApplicabilityStatus.AFFECTED
        )
        conflict_count = sum(len(item.conflicts) for item in enriched)
        manual_review_count = sum(
            1
            for item in enriched
            if item.priority.level == PriorityLevel.MANUAL_REVIEW
            or any(conflict.requires_manual_review for conflict in item.conflicts)
        )
        enrichment_coverage_percent = 100.0
        if eligible_ids:
            enrichment_coverage_percent = round((len(enriched_ids) / len(eligible_ids)) * 100, 1)
        enrichment_complete = (
            enrichment_coverage_percent == 100.0
            and all(status.succeeded and not status.partial and not status.error_message for status in provider_statuses if status.enabled)
        )
        LOGGER.info(
            "Enrichment completed: kev=%s, conflicts=%s",
            known_exploited_count,
            conflict_count,
        )
        return EnrichedCveScanSummary(
            base_summary=summary,
            assessments=enriched,
            unique_enriched_cves=unique_enriched_cves,
            enriched_assessment_count=enriched_assessment_count,
            unique_known_exploited_cves=unique_known_exploited_cves,
            known_exploited_assessment_count=known_exploited_count,
            unique_ransomware_cves=unique_ransomware_cves,
            ransomware_assessment_count=ransomware_known_count,
            known_exploited_count=known_exploited_count,
            ransomware_known_count=ransomware_known_count,
            cna_confirmed_count=cna_confirmed_count,
            conflict_count=conflict_count,
            manual_review_count=manual_review_count,
            provider_statuses=provider_statuses,
            enrichment_complete=enrichment_complete,
            enrichment_coverage_percent=enrichment_coverage_percent,
        )

    def _load_enrichments(
        self,
        cve_id: str,
        execution_states: dict[str, ProviderExecutionState],
    ) -> list[SourceEnrichment]:
        """Load all provider enrichments for one CVE ID."""

        enrichments: list[SourceEnrichment] = []
        for provider in self.providers:
            state = execution_states[provider.name]
            state.attempts += 1
            try:
                enrichment = provider.enrich(cve_id)
                if enrichment is not None:
                    enrichments.append(enrichment)
                    if enrichment.warnings:
                        state.partial = True
                _merge_provider_status(state, provider)
            except Exception:
                LOGGER.exception("Provider failed for CVE ID")
                state.succeeded = False
                state.errors.append(f"{cve_id}: provider exception")
        return enrichments

    def _enrich_assessment(
        self,
        assessment: CveAssessment,
        source_enrichments: list[SourceEnrichment],
    ) -> EnrichedCveAssessment:
        """Merge source enrichments onto one assessment."""

        kev = _first_kev(source_enrichments)
        ssvc = _first_ssvc(source_enrichments)
        cna_affected = [
            affected
            for enrichment in source_enrichments
            for affected in enrichment.affected
            if affected.source == SourceType.CNA
        ]
        cna_status, cna_reason, _ = evaluate_cna_applicability(assessment.software, cna_affected)
        if cna_status == ApplicabilityStatus.AFFECTED:
            LOGGER.info("CNA applicability confirmed: AFFECTED")

        exploitation_status = _exploitation_status(source_enrichments)
        conflicts = _detect_conflicts(assessment, cna_status, source_enrichments, exploitation_status)
        ransomware_use = kev.known_ransomware_campaign_use if kev else RansomwareUse.NOT_LISTED
        priority = calculate_priority(
            assessment=assessment,
            exploitation_status=exploitation_status,
            ransomware_use=ransomware_use,
            cna_applicability=cna_status,
            conflicts=conflicts,
            adp_exploitation_status=ssvc.exploitation if ssvc else SsvcExploitation.UNKNOWN,
            weights=self.prioritization_weights,
        )
        LOGGER.info("Vulnerability priority calculated: %s", priority.level.value)

        provenance = _build_provenance(assessment, source_enrichments, kev, ssvc, cna_status)
        return EnrichedCveAssessment(
            base_assessment=assessment,
            exploitation_status=exploitation_status,
            kev=kev,
            ssvc=ssvc,
            cna_affected=cna_affected,
            cna_applicability=cna_status,
            cna_applicability_reason=cna_reason,
            merged_references=_dedupe_references(_nvd_references(assessment) + _source_references(source_enrichments)),
            source_enrichments=source_enrichments,
            priority=priority,
            conflicts=conflicts,
            provenance=provenance,
            enrichment_complete=all(enrichment.data_quality.value != "UNKNOWN" for enrichment in source_enrichments),
        )


def _first_kev(enrichments: list[SourceEnrichment]) -> KevRecord | None:
    """Return the first KEV record in source enrichments."""

    for enrichment in enrichments:
        if enrichment.kev is not None:
            return enrichment.kev
    return None


def _merge_provider_status(
    state: ProviderExecutionState,
    provider: VulnerabilityDataProvider,
) -> None:
    """Merge provider-reported status into orchestrator state when available."""

    try:
        status = provider.status()
    except Exception as error:
        state.succeeded = False
        state.errors.append(str(error))
        return
    state.used_stale_cache = state.used_stale_cache or status.used_stale_cache
    state.records_loaded = max(state.records_loaded, status.records_loaded)
    state.partial = state.partial or getattr(status, "partial", False)
    if status.error_message:
        state.succeeded = False
        state.errors.append(status.error_message)
    elif not status.succeeded:
        state.succeeded = False


def _provider_status(state: ProviderExecutionState) -> ProviderStatus:
    """Convert execution state to public provider status."""

    return ProviderStatus(
        provider=state.provider,
        enabled=True,
        succeeded=state.succeeded,
        used_stale_cache=state.used_stale_cache,
        records_loaded=state.records_loaded,
        error_message="; ".join(state.errors) if state.errors else None,
        partial=state.partial,
        attempts=state.attempts,
    )


def _first_ssvc(enrichments: list[SourceEnrichment]) -> SsvcDecision | None:
    """Return the first SSVC decision in source enrichments."""

    for enrichment in enrichments:
        if enrichment.ssvc is not None:
            return enrichment.ssvc
    return None


def _exploitation_status(enrichments: list[SourceEnrichment]) -> ExploitationStatus:
    """Derive KEV semantics from CISA KEV source availability."""

    cisa = [enrichment for enrichment in enrichments if enrichment.source == SourceType.CISA_KEV]
    if not cisa:
        return ExploitationStatus.UNKNOWN
    if any(enrichment.kev is not None for enrichment in cisa):
        return ExploitationStatus.KNOWN_EXPLOITED
    return ExploitationStatus.NO_KEV_EVIDENCE


def _detect_conflicts(
    assessment: CveAssessment,
    cna_status: ApplicabilityStatus,
    source_enrichments: list[SourceEnrichment],
    exploitation_status: ExploitationStatus,
) -> list[DataConflict]:
    """Detect source disagreements that require visibility."""

    conflicts: list[DataConflict] = []
    if assessment.applicability == ApplicabilityStatus.AFFECTED and cna_status == ApplicabilityStatus.NOT_AFFECTED:
        conflicts.append(
            DataConflict(
                conflict_type=ConflictType.AFFECTED_VERSION_DISAGREEMENT,
                description="NVD marks the installed version affected but CNA affected data does not.",
                sources=[SourceType.NVD, SourceType.CNA],
                requires_manual_review=True,
            )
        )
    elif assessment.applicability == ApplicabilityStatus.NOT_AFFECTED and cna_status == ApplicabilityStatus.AFFECTED:
        conflicts.append(
            DataConflict(
                conflict_type=ConflictType.AFFECTED_VERSION_DISAGREEMENT,
                description="CNA marks the installed version affected but NVD applicability does not.",
                sources=[SourceType.NVD, SourceType.CNA],
                requires_manual_review=True,
            )
        )
    if _has_adp_kev_evidence(source_enrichments) and exploitation_status != ExploitationStatus.KNOWN_EXPLOITED:
        conflicts.append(
            DataConflict(
                conflict_type=ConflictType.OTHER,
                description="CISA ADP contains KEV-related metadata but direct CISA KEV feed did not confirm membership.",
                sources=[SourceType.CISA_ADP, SourceType.CISA_KEV],
                requires_manual_review=True,
            )
        )
    if conflicts:
        LOGGER.warning("NVD and CNA affected-version disagreement")
    return conflicts


def _has_adp_kev_evidence(enrichments: list[SourceEnrichment]) -> bool:
    """Return whether ADP metadata contains KEV evidence."""

    return any(
        metric.get("adpKev") is True
        for enrichment in enrichments
        for metric in enrichment.metrics
        if isinstance(metric, dict)
    )


def _build_provenance(
    assessment: CveAssessment,
    enrichments: list[SourceEnrichment],
    kev: KevRecord | None,
    ssvc: SsvcDecision | None,
    cna_status: ApplicabilityStatus,
) -> list[ProvenanceRecord]:
    """Build provenance records for enriched fields."""

    now = retrieved_now()
    records = [
        ProvenanceRecord("nvd_applicability", assessment.applicability.value, SourceType.NVD, "NVD", now),
        ProvenanceRecord("cvss_score", str(assessment.cve.cvss_score), SourceType.NVD, "NVD", now),
    ]
    if kev:
        records.append(ProvenanceRecord("known_exploited", kev.cve_id, SourceType.CISA_KEV, "CISA KEV", now))
    if ssvc:
        records.append(ProvenanceRecord("ssvc_decision", str(ssvc.decision), ssvc.source, "CISA ADP", now))
        records.append(ProvenanceRecord("ssvc_exploitation", str(ssvc.exploitation_raw), ssvc.source, "CISA ADP", now))
    if cna_status != ApplicabilityStatus.NOT_AFFECTED:
        records.append(ProvenanceRecord("cna_applicability", cna_status.value, SourceType.CNA, "CVE Program", now))
    for enrichment in enrichments:
        if enrichment.affected:
            records.append(
                ProvenanceRecord(
                    "affected_versions",
                    str(len(enrichment.affected)),
                    enrichment.source,
                    enrichment.provider_short_name or enrichment.provider_name,
                    now,
                )
            )
    return records


def _nvd_references(assessment: CveAssessment) -> list[ReferenceRecord]:
    """Convert NVD references to ReferenceRecord values."""

    return [
        ReferenceRecord(url=url, title=None, tags=(), source=SourceType.NVD)
        for url in assessment.cve.references
    ]


def _source_references(enrichments: list[SourceEnrichment]) -> list[ReferenceRecord]:
    """Collect source references."""

    return [reference for enrichment in enrichments for reference in enrichment.references]


def _dedupe_references(references: list[ReferenceRecord]) -> list[ReferenceRecord]:
    """Deduplicate references by normalized URL."""

    seen: set[str] = set()
    deduped: list[ReferenceRecord] = []
    for reference in references:
        key = reference.url.rstrip("/").casefold()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(reference)
    return deduped
