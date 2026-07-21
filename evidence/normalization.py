"""Normalize collector documents into evidence registries."""

from __future__ import annotations

from collector_schema.models import CollectorDocument
from evidence.registry import WindowsEvidenceRegistry


def normalize_windows_evidence(document: CollectorDocument) -> WindowsEvidenceRegistry:
    """Return the normalized Windows evidence registry for a collector document."""

    settings = list(document.security.settings)
    settings.extend(document.updates.settings)
    return WindowsEvidenceRegistry(settings)
