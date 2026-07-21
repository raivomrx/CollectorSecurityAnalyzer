"""Windows security evidence models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from collector_schema.enums import CollectionStatus, ConfigurationSource


@dataclass(slots=True)
class SecuritySettingEvidence:
    """Represent one normalized Windows security setting."""

    setting_id: str
    category: str
    configured_value: Any
    effective_value: Any
    source: ConfigurationSource
    collection_status: CollectionStatus
    confidence: int
    collected_at: datetime
    provider: str
    source_path: str | None
    error_code: str | None
    error_message: str | None
    metadata: dict[str, Any] = field(default_factory=dict)
