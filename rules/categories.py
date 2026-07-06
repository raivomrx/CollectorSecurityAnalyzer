"""Rule category definitions."""

from __future__ import annotations

from enum import Enum


class RuleCategory(str, Enum):
    """Supported categories for analyzer rules."""

    ENCRYPTION = "Encryption"
    DEFENDER = "Defender"
    FIREWALL = "Firewall"
    UPDATES = "Updates"
    NETWORK = "Network"
    SOFTWARE = "Software"
    IDENTITY = "Identity"
    LOCAL_ADMINS = "Local Admins"
    SERVICES = "Services"
    SCHEDULED_TASKS = "Scheduled Tasks"
    COMPLIANCE = "Compliance"
