"""Provider interface for vulnerability enrichment sources."""

from __future__ import annotations

from abc import ABC, abstractmethod

from cve.enrichment_models import ProviderStatus, SourceEnrichment


class VulnerabilityDataProvider(ABC):
    """Base interface for CVE enrichment data providers."""

    name: str

    @abstractmethod
    def enrich(self, cve_id: str) -> SourceEnrichment | None:
        """Return source-specific enrichment for one CVE."""

        raise NotImplementedError

    def status(self) -> ProviderStatus:
        """Return provider execution status."""

        return ProviderStatus(
            provider=self.name,
            enabled=True,
            succeeded=True,
            used_stale_cache=False,
            records_loaded=0,
            error_message=None,
        )
