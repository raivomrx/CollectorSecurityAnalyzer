"""Server-owned distribution authorization, independent of Join/browser flags."""
from dataclasses import dataclass
from enum import Enum
import ipaddress


class DistributionState(str, Enum):
    DEVELOPMENT_UNSIGNED = "DEVELOPMENT_UNSIGNED"
    TRUST_ENROLLMENT_PENDING = "TRUST_ENROLLMENT_PENDING"
    PILOT_APPROVED = "PILOT_APPROVED"
    RELEASE_APPROVED = "RELEASE_APPROVED"


class DistributionDenied(ValueError):
    def __init__(self):
        super().__init__("TRUST_NOT_ESTABLISHED")


@dataclass(frozen=True)
class DistributionPolicy:
    state: DistributionState = DistributionState.TRUST_ENROLLMENT_PENDING
    development_sources: tuple[str, ...] = ()

    @classmethod
    def from_session(cls, session):
        # Only the authenticated localhost assessor API writes this configuration.
        # Pilot/release approval cannot be asserted in the session JSON or a URL.
        value = session.report_configuration.get("distribution", {})
        if (not isinstance(value, dict) or value.get("mode") != DistributionState.DEVELOPMENT_UNSIGNED.value
                or value.get("assessorOnly") is not True):
            return cls()
        entries = value.get("allowedSources")
        if not isinstance(entries, list) or not 1 <= len(entries) <= 32 or not all(isinstance(item, str) for item in entries):
            return cls()
        try:
            sources = tuple(str(ipaddress.ip_address(item)) for item in entries)
        except ValueError:
            return cls()
        return cls(DistributionState.DEVELOPMENT_UNSIGNED, sources)

    def require_legacy(self, source):
        try:
            allowed = str(ipaddress.ip_address(source)) in self.development_sources
        except ValueError:
            allowed = False
        if self.state != DistributionState.DEVELOPMENT_UNSIGNED or not allowed:
            raise DistributionDenied()
