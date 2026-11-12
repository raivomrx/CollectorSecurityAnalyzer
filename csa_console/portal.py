"""Assessment-bound Collector download portal state and authorization."""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from csa_console.audit import ConsoleAuditLog
from csa_console.distribution import DistributionPolicy, DistributionState
from csa_console.canonical import write_canonical_json
from csa_console.enums import SessionStatus
from csa_console.network import source_is_allowed
from csa_console.sessions import AssessmentSessionService
from csa_console.storage import AssessmentStorage


JOIN_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
JOIN_CODE_LENGTH = 8


def normalize_join_code(value: str) -> str:
    """Return the canonical human-readable join-code representation."""

    normalized = value.strip().upper()
    if len(normalized) == JOIN_CODE_LENGTH + 1:
        if normalized[4] != "-":
            return ""
        compact = normalized[:4] + normalized[5:]
    elif len(normalized) == JOIN_CODE_LENGTH and "-" not in normalized:
        compact = normalized
    else:
        return ""
    if len(compact) != JOIN_CODE_LENGTH or any(
        character not in JOIN_CODE_ALPHABET for character in compact
    ):
        return ""
    return f"{compact[:4]}-{compact[4:]}"


@dataclass(slots=True)
class PortalBinding:
    """Bind one opaque join code to the session's Collector transports."""

    assessment_id: str
    session_id: str
    join_code_hash: str
    collector_path: Path
    expires_at: str
    maximum_downloads: int
    storage: AssessmentStorage
    script_collector_path: Path | None = None
    launcher_bytes: bytes = field(default=b"", repr=False)
    launcher_token_hash: str = field(default="", repr=False)
    download_count: int = 0
    maximum_failed_attempts: int = 5
    failure_window_seconds: float = 60.0
    throttle_seconds: float = 30.0
    failed_authorization_count: int = 0
    distribution_policy: DistributionPolicy = field(default_factory=DistributionPolicy)
    throttled_authorization_count: int = 0
    _failed_attempts: dict[str, list[float]] = field(
        default_factory=dict, repr=False, compare=False
    )
    _blocked_until: dict[str, float] = field(
        default_factory=dict, repr=False, compare=False
    )
    _lock: threading.Lock = field(
        default_factory=threading.Lock, repr=False, compare=False
    )

    def authorize(self, join_code: str, source_address: str) -> bool:
        """Validate code, session, expiry, source scope and download budget."""

        now = time.monotonic()
        with self._lock:
            if now < self._blocked_until.get(source_address, 0.0):
                self.throttled_authorization_count += 1
                return False

        normalized = normalize_join_code(join_code)
        supplied = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(supplied, self.join_code_hash):
            self._record_failed_authorization(source_address, now)
            return False
        return self._authorize_session(source_address)

    def authorize_launcher(self, credential: str, source_address: str) -> bool:
        """Check a download-only header credential; never use a secret URL."""
        now = time.monotonic()
        with self._lock:
            if now < self._blocked_until.get(source_address, 0.0):
                self.throttled_authorization_count += 1
                return False
        supplied = hashlib.sha256(credential.encode("utf-8")).hexdigest()
        if not self.launcher_token_hash or not hmac.compare_digest(supplied, self.launcher_token_hash):
            self._record_failed_authorization(source_address, now)
            return False
        return self._authorize_session(source_address)

    def _authorize_session(self, source_address: str) -> bool:
        """Apply the same source, state, expiry and budget to all transports."""
        now = time.monotonic()
        session = AssessmentSessionService(self.storage).load_session(
            self.assessment_id, self.session_id
        )
        if session.status != SessionStatus.OPEN:
            return False
        if datetime.now(timezone.utc) >= datetime.fromisoformat(
            self.expires_at.replace("Z", "+00:00")
        ):
            return False
        if not source_is_allowed(session, source_address):
            self._record_failed_authorization(source_address, now)
            return False
        with self._lock:
            return self.download_count < self.maximum_downloads

    def _record_failed_authorization(
        self, source_address: str, now: float
    ) -> None:
        """Count a failed attempt without retaining attacker-supplied data."""

        with self._lock:
            cutoff = now - self.failure_window_seconds
            attempts = [
                attempt
                for attempt in self._failed_attempts.get(source_address, [])
                if attempt >= cutoff
            ]
            attempts.append(now)
            self._failed_attempts[source_address] = attempts
            self.failed_authorization_count += 1
            if len(attempts) >= self.maximum_failed_attempts:
                self._blocked_until[source_address] = now + self.throttle_seconds
                self.throttled_authorization_count += 1
        ConsoleAuditLog(
            self.storage.path(self.assessment_id, "audit", "audit.jsonl")
        ).append(
            "collector_portal_authorization_failed",
            {
                "sessionId": self.session_id,
                "sourceAddressHash": "sha256:" + hashlib.sha256(source_address.encode("utf-8")).hexdigest(),
                "failedAttemptCount": self.failed_authorization_count,
            },
        )

    def record_download(self, source_address: str) -> None:
        """Atomically count and audit a successful download without the code."""

        with self._lock:
            if self.download_count >= self.maximum_downloads:
                raise ValueError("Collector download limit reached")
            self.download_count += 1
            count = self.download_count
            write_canonical_json(
                self.storage.path(
                    self.assessment_id,
                    "sessions",
                    f"{self.session_id}.portal.json",
                ),
                {
                    "assessmentId": self.assessment_id,
                    "sessionId": self.session_id,
                    "expiresAt": self.expires_at,
                    "maximumDownloads": self.maximum_downloads,
                    "downloadCount": count,
                    "active": True,
                },
            )
        ConsoleAuditLog(
            self.storage.path(self.assessment_id, "audit", "audit.jsonl")
        ).append(
            "collector_downloaded",
            {
                "sessionId": self.session_id,
                "sourceAddressHash": "sha256:" + hashlib.sha256(source_address.encode("utf-8")).hexdigest(),
                "downloadCount": count,
            },
        )

    def render_page(self, assessment_name: str, network_options=None, *, development_available=False) -> bytes:
        """The customer sees methods and short instructions only."""
        from csa_console.customer_launch import render
        return render(assessment_name, network_options=network_options,
                      development=development_available and self.distribution_policy.state == DistributionState.DEVELOPMENT_UNSIGNED)

    @staticmethod
    def render_error_page(correlation_id: str) -> bytes:
        from csa_console.customer_launch import render
        return render("")

    @staticmethod
    def render_unavailable_page() -> bytes:
        from csa_console.customer_launch import render
        return render("")
