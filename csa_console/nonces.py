"""Persistent one-use submission nonce management."""

from __future__ import annotations

import hmac
import threading
from datetime import timedelta

from csa_console.identifiers import random_token, utc_now, utc_text
from csa_console.models import AssessmentSession, SubmissionNonce
from csa_console.serde import model_to_dict
from csa_console.storage import AssessmentStorage


class NonceError(ValueError):
    """Report invalid, expired or replayed submission nonces."""


class NonceService:
    """Issue and atomically consume session-bound nonces."""

    def __init__(self, storage: AssessmentStorage) -> None:
        """Create a nonce service."""

        self.storage = storage
        self._lock = threading.Lock()

    def issue(
        self,
        session: AssessmentSession,
        submission_id: str,
        source_address: str,
        ttl_seconds: int = 120,
    ) -> SubmissionNonce:
        """Issue a fresh nonce for one submission and source."""

        record = SubmissionNonce(
            session_id=session.session_id,
            submission_id=submission_id,
            nonce=random_token(),
            issued_at=utc_text(),
            expires_at=utc_text(utc_now() + timedelta(seconds=ttl_seconds)),
            source_address=source_address,
        )
        self.storage.write_json(
            session.assessment_id,
            ("nonces", f"{submission_id}.json"),
            model_to_dict(record),
        )
        return record

    def consume(
        self,
        session: AssessmentSession,
        submission_id: str,
        nonce: str,
        source_address: str,
    ) -> None:
        """Consume a nonce exactly once before package processing."""

        with self._lock:
            data = self.storage.read_json(
                session.assessment_id, "nonces", f"{submission_id}.json"
            )
            if (
                data.get("sessionId") != session.session_id
                or data.get("submissionId") != submission_id
                or not hmac.compare_digest(str(data.get("nonce", "")), nonce)
                or data.get("sourceAddress") != source_address
            ):
                raise NonceError("Submission nonce binding is invalid")
            if bool(data.get("used")):
                raise NonceError("Submission nonce has already been used")
            from datetime import datetime

            expiry = datetime.fromisoformat(
                str(data["expiresAt"]).replace("Z", "+00:00")
            )
            if utc_now() >= expiry:
                raise NonceError("Submission nonce has expired")
            data["used"] = True
            self.storage.write_json(
                session.assessment_id,
                ("nonces", f"{submission_id}.json"),
                data,
            )
