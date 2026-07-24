"""Session-bound submission validation and storage pipeline."""

from __future__ import annotations

import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from csa_console.audit import ConsoleAuditLog
from csa_console.canonical import sha256_bytes, write_canonical_json
from csa_console.enums import SubmissionState
from csa_console.identifiers import random_id, utc_now, utc_text
from csa_console.models import AssessmentSession, SubmissionReceipt
from csa_console.network import source_is_allowed
from csa_console.nonces import NonceError, NonceService
from csa_console.package import (
    EvidencePackageValidator,
    PackageValidationError,
    ValidatedPackage,
)
from csa_console.receipts import sign_receipt
from csa_console.serde import model_to_dict
from csa_console.sessions import AssessmentSessionService, SessionError
from csa_console.storage import AssessmentStorage


class SubmissionRejected(ValueError):
    """Expose only a structured submission rejection state."""

    def __init__(self, state: SubmissionState, safe_message: str) -> None:
        """Create a rejection without retaining raw package content."""

        super().__init__(safe_message)
        self.state = state
        self.safe_message = safe_message


class SubmissionService:
    """Issue nonces and process endpoint packages through one trust boundary."""

    def __init__(self, storage: AssessmentStorage | None = None) -> None:
        """Create a submission service."""

        self.storage = storage or AssessmentStorage()
        self.sessions = AssessmentSessionService(self.storage)
        self.nonces = NonceService(self.storage)
        self._lock = threading.Lock()

    def request_nonce(
        self,
        assessment_id: str,
        session_id: str,
        submission_id: str,
        enrollment_token: str,
        source_address: str,
    ) -> str:
        """Authenticate a collector and issue a one-use nonce."""

        session = self.sessions.load_session(assessment_id, session_id)
        self._require_source(session, source_address)
        try:
            self.sessions.verify_token(session, enrollment_token)
        except SessionError as error:
            raise SubmissionRejected(
                SubmissionState.REJECTED_TOKEN, str(error)
            ) from error
        nonce = self.nonces.issue(session, submission_id, source_address)
        self._audit(assessment_id).append(
            "submission_requested",
            {
                "sessionId": session_id,
                "submissionId": submission_id,
                "sourceAddressHash": sha256_bytes(source_address.encode("utf-8")),
            },
        )
        return nonce.nonce

    def accept(
        self,
        *,
        assessment_id: str,
        session_id: str,
        submission_id: str,
        enrollment_token: str,
        nonce: str,
        source_address: str,
        archive_bytes: bytes,
    ) -> tuple[SubmissionReceipt, ValidatedPackage, Path]:
        """Validate, store and acknowledge one endpoint package."""

        received_digest = sha256_bytes(archive_bytes)
        session = self.sessions.load_session(assessment_id, session_id)
        self._audit(assessment_id).append(
            "submission_received",
            {
                "sessionId": session_id,
                "submissionId": submission_id,
                "transportDigest": received_digest,
            },
        )
        self._require_source(session, source_address)
        try:
            self.sessions.verify_token(session, enrollment_token)
        except SessionError as error:
            self._reject(
                assessment_id,
                submission_id,
                SubmissionState.REJECTED_TOKEN,
                received_digest,
            )
            raise SubmissionRejected(
                SubmissionState.REJECTED_TOKEN, str(error)
            ) from error
        try:
            self.nonces.consume(
                session, submission_id, nonce, source_address
            )
        except NonceError as error:
            self._reject(
                assessment_id,
                submission_id,
                SubmissionState.REJECTED_REPLAY,
                received_digest,
            )
            raise SubmissionRejected(
                SubmissionState.REJECTED_REPLAY, str(error)
            ) from error
        if len(archive_bytes) > session.maximum_package_size:
            self._reject(
                assessment_id,
                submission_id,
                SubmissionState.REJECTED_PACKAGE_LIMIT,
                received_digest,
            )
            raise SubmissionRejected(
                SubmissionState.REJECTED_PACKAGE_LIMIT,
                "Package exceeds the session size limit",
            )
        quarantine_path = self.storage.path(
            assessment_id,
            "submissions",
            "quarantine",
            f"{submission_id}.csa.zip",
        )
        quarantine_path.write_bytes(archive_bytes)
        quarantine_path.chmod(0o600)
        self._audit(assessment_id).append(
            "submission_quarantined",
            {"submissionId": submission_id, "transportDigest": received_digest},
        )
        validator = EvidencePackageValidator(
            maximum_package_size=session.maximum_package_size
        )
        try:
            package = validator.validate(
                archive_bytes,
                enrollment_token=enrollment_token,
                expected_assessment_id=assessment_id,
                expected_session_id=session_id,
                expected_submission_id=submission_id,
                expected_nonce=nonce,
                expected_profile_digest=session.collection_profile_digest,
            )
        except PackageValidationError as error:
            quarantine_path.unlink(missing_ok=True)
            state = _submission_state(error.state)
            self._reject(
                assessment_id, submission_id, state, received_digest
            )
            raise SubmissionRejected(state, error.safe_message) from error
        trusted_builds = {
            str(item)
            for item in session.report_configuration.get(
                "trustedCollectorBuildDigests", []
            )
        }
        if package.manifest.get("collectorBuildDigest") not in trusted_builds:
            quarantine_path.unlink(missing_ok=True)
            self._reject(
                assessment_id,
                submission_id,
                SubmissionState.REJECTED_UNTRUSTED_COLLECTOR,
                package.package_digest,
            )
            raise SubmissionRejected(
                SubmissionState.REJECTED_UNTRUSTED_COLLECTOR,
                "Collector build digest is not trusted for this session",
            )
        with self._lock:
            index = self._load_index(assessment_id)
            duplicate = any(
                item.get("submissionId") == submission_id
                or item.get("packageDigest") == package.package_digest
                for item in index
            )
            if duplicate:
                quarantine_path.unlink(missing_ok=True)
                self._reject(
                    assessment_id,
                    submission_id,
                    SubmissionState.REJECTED_REPLAY,
                    package.package_digest,
                )
                raise SubmissionRejected(
                    SubmissionState.REJECTED_REPLAY,
                    "Duplicate submission ID or package digest",
                )
            accepted_path = self.storage.path(
                assessment_id,
                "submissions",
                "accepted",
                f"{submission_id}.csa.zip",
            )
            quarantine_path.replace(accepted_path)
            index.append(
                {
                    "assessmentId": assessment_id,
                    "sessionId": session_id,
                    "submissionId": submission_id,
                    "deviceId": package.manifest["deviceId"],
                    "packageDigest": package.package_digest,
                    "transportDigest": received_digest,
                    "state": SubmissionState.EVIDENCE_ACCEPTED.value,
                    "receivedAt": utc_text(),
                    "sourceAddressHash": sha256_bytes(
                        source_address.encode("utf-8")
                    ),
                }
            )
            index.sort(key=lambda item: str(item["submissionId"]))
            self.storage.write_json(
                assessment_id, ("submissions", "index.json"), {"items": index}
            )
            self.sessions.record_token_use(session)
        receipt_unsigned: dict[str, Any] = {
            "assessmentId": assessment_id,
            "sessionId": session_id,
            "submissionId": submission_id,
            "receivedAt": utc_text(),
            "packageDigest": package.package_digest,
            "validationStatus": "ACCEPTED",
            "serverReceiptId": random_id("RCP-"),
            "cleanupConfirmed": None,
        }
        if not session.tls_private_key_path:
            raise RuntimeError("Session receipt signing key is unavailable")
        receipt_unsigned["serverSignature"] = sign_receipt(
            receipt_unsigned, session.tls_private_key_path
        )
        receipt = SubmissionReceipt(
            assessment_id=assessment_id,
            session_id=session_id,
            submission_id=submission_id,
            received_at=str(receipt_unsigned["receivedAt"]),
            package_digest=package.package_digest,
            validation_status="ACCEPTED",
            server_receipt_id=str(receipt_unsigned["serverReceiptId"]),
            server_signature=str(receipt_unsigned["serverSignature"]),
        )
        self.storage.write_json(
            assessment_id,
            ("submissions", "accepted", f"{submission_id}.receipt.json"),
            model_to_dict(receipt),
        )
        self._audit(assessment_id).append(
            "submission_accepted",
            {
                "sessionId": session_id,
                "submissionId": submission_id,
                "packageDigest": package.package_digest,
                "receiptId": receipt.server_receipt_id,
            },
        )
        return receipt, package, accepted_path

    def list_submissions(self, assessment_id: str) -> list[dict[str, Any]]:
        """Return accepted submission metadata in deterministic order."""

        return self._load_index(assessment_id)

    def remove_submission(
        self,
        assessment_id: str,
        submission_id: str,
    ) -> None:
        """Remove one explicitly selected endpoint submission and derived data."""

        with self._lock:
            index = self._load_index(assessment_id)
            remaining = [
                item
                for item in index
                if item.get("submissionId") != submission_id
            ]
            if len(remaining) == len(index):
                raise ValueError("Submission was not found")
            for components in (
                ("submissions", "accepted", f"{submission_id}.csa.zip"),
                ("submissions", "accepted", f"{submission_id}.evidence.json"),
                ("submissions", "accepted", f"{submission_id}.receipt.json"),
                ("normalized", f"{submission_id}.json"),
                ("findings", f"{submission_id}.json"),
            ):
                self.storage.path(assessment_id, *components).unlink(
                    missing_ok=True
                )
            report_root = self.storage.path(
                assessment_id, "reports", "endpoints"
            )
            for path in report_root.glob(f"{submission_id}*"):
                if path.is_file():
                    path.unlink()
            self.storage.write_json(
                assessment_id,
                ("submissions", "index.json"),
                {"items": remaining},
            )
        self._audit(assessment_id).append(
            "submission_removed",
            {"submissionId": submission_id},
        )

    def _require_source(
        self, session: AssessmentSession, source_address: str
    ) -> None:
        """Enforce the session source network contract."""

        if utc_now() >= _parse_utc(session.expires_at):
            raise SubmissionRejected(
                SubmissionState.REJECTED_EXPIRED, "Assessment session has expired"
            )
        if not source_is_allowed(session, source_address):
            raise SubmissionRejected(
                SubmissionState.REJECTED_UNAUTHORIZED_SOURCE,
                "Submission source is outside the session scope",
            )

    def _load_index(self, assessment_id: str) -> list[dict[str, Any]]:
        """Load the accepted submission index."""

        path = self.storage.path(
            assessment_id, "submissions", "index.json"
        )
        if not path.exists():
            return []
        data = self.storage.read_json(
            assessment_id, "submissions", "index.json"
        )
        return [
            item for item in data.get("items", []) if isinstance(item, dict)
        ]

    def _reject(
        self,
        assessment_id: str,
        submission_id: str,
        state: SubmissionState,
        digest: str,
    ) -> None:
        """Persist only safe rejection metadata and audit state."""

        metadata = {
            "submissionId": submission_id,
            "state": state.value,
            "digest": digest,
            "rejectedAt": utc_text(),
        }
        write_canonical_json(
            self.storage.path(
                assessment_id,
                "submissions",
                "rejected",
                f"{submission_id}.json",
            ),
            metadata,
        )
        self._audit(assessment_id).append(
            "submission_rejected",
            {
                "submissionId": submission_id,
                "state": state.value,
                "digest": digest,
            },
        )

    def _audit(self, assessment_id: str) -> ConsoleAuditLog:
        """Return the assessment audit log."""

        return ConsoleAuditLog(
            self.storage.path(assessment_id, "audit", "audit.jsonl")
        )


def _submission_state(value: str) -> SubmissionState:
    """Convert validator state text to a known rejection state."""

    try:
        return SubmissionState(value)
    except ValueError:
        return SubmissionState.REJECTED_SCHEMA


def _parse_utc(value: str) -> datetime:
    """Parse a UTC timestamp."""

    return datetime.fromisoformat(value.replace("Z", "+00:00"))
