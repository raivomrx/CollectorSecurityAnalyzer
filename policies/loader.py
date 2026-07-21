"""Policy profile loading for analyzer thresholds."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class WindowsEndpointPolicy:
    """Represent Windows endpoint policy thresholds."""

    policy_id: str
    version: str
    thresholds: dict[str, int]
    approved_remote_access_products: list[str] = field(default_factory=list)
    required_firewall_logging: bool = True
    require_credential_guard: bool = False
    require_memory_integrity: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


DEFAULT_POLICY_PATH = Path(__file__).resolve().parent / "windows_endpoint_default.json"


def load_policy_profile(path_or_id: str | Path | None = None) -> WindowsEndpointPolicy:
    """Load a Windows endpoint policy profile by path or default ID."""

    if path_or_id in (None, "", "WINDOWS_ENDPOINT_DEFAULT"):
        path = DEFAULT_POLICY_PATH
    else:
        path = Path(path_or_id)
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            data = json.load(handle)
    except OSError as error:
        raise ValueError(f"Unknown policy profile: {path_or_id}") from error
    if not isinstance(data, dict):
        raise ValueError("Policy profile root must be an object")
    thresholds = data.get("thresholds", {})
    if not isinstance(thresholds, dict):
        raise ValueError("Policy thresholds must be an object")
    return WindowsEndpointPolicy(
        policy_id=str(data.get("policyId", "UNKNOWN")),
        version=str(data.get("version", "")),
        thresholds={str(key): int(value) for key, value in thresholds.items()},
        approved_remote_access_products=[
            str(item) for item in data.get("approvedRemoteAccessProducts", [])
        ],
        required_firewall_logging=bool(data.get("requiredFirewallLogging", True)),
        require_credential_guard=bool(data.get("requireCredentialGuard", False)),
        require_memory_integrity=bool(data.get("requireMemoryIntegrity", False)),
        metadata=data.get("metadata", {}) if isinstance(data.get("metadata", {}), dict) else {},
    )
