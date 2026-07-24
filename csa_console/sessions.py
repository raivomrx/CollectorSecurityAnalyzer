"""Assessment and collection session lifecycle services."""

from __future__ import annotations

import hmac
from dataclasses import fields
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, TypeVar

from csa_console.audit import ConsoleAuditLog
from csa_console.canonical import sha256_bytes
from csa_console.capabilities import CollectionProfile
from csa_console.enums import (
    AssessmentStatus,
    CollectorMode,
    SessionStatus,
)
from csa_console.identifiers import random_id, random_token, utc_now, utc_text
from csa_console.models import Assessment, AssessmentSession
from csa_console.serde import model_to_dict
from csa_console.storage import AssessmentStorage
from csa_console.tls import generate_offline_keypair, generate_session_certificate

T = TypeVar("T")
DEFAULT_FRAMEWORK_PACKS = [
    "CIS_WINDOWS_11_ENTERPRISE:5.0.1",
    "EITS:2026",
    "CSA_WINDOWS_11_MICROSOFT_GUIDANCE:CSA-WIN11-2026.1",
    "NIS2_TECHNICAL_TRACEABILITY:EU-2022-2555",
]


class SessionError(ValueError):
    """Report invalid assessment session operations."""


class AssessmentSessionService:
    """Create assessments and enforce bounded session lifecycles."""

    def __init__(self, storage: AssessmentStorage | None = None) -> None:
        """Create a session service."""

        self.storage = storage or AssessmentStorage()

    def create_assessment(
        self,
        name: str,
        customer_reference: str,
        created_by: str = "assessment-operator",
        assessment_id: str | None = None,
    ) -> Assessment:
        """Create and persist a new assessment."""

        identifier = assessment_id or (
            f"CSA-{utc_now().year}-{random_id()[-8:]}"
        )
        root = self.storage.assessment_path(identifier)
        if root.exists():
            raise SessionError(f"Assessment already exists: {identifier}")
        self.storage.ensure_assessment(identifier)
        assessment = Assessment(
            assessment_id=identifier,
            name=name,
            customer_reference=customer_reference,
            created_at=utc_text(),
            created_by=created_by,
        )
        self.storage.write_json(
            identifier, ("assessment.json",), model_to_dict(assessment)
        )
        self._audit(identifier).append(
            "assessment_created",
            {"assessmentId": identifier, "customerReference": customer_reference},
        )
        return assessment

    def load_assessment(self, assessment_id: str) -> Assessment:
        """Load an assessment from storage."""

        data = self.storage.read_json(assessment_id, "assessment.json")
        return _from_camel_dataclass(Assessment, data)

    def open_session(
        self,
        assessment_id: str,
        profile_path: str | Path | None = None,
        expected_devices: int = 13,
        allowed_submissions: int = 20,
        expires_in_hours: int = 10,
        allowed_source_networks: list[str] | None = None,
        allowed_source_addresses: list[str] | None = None,
        listen_address: str = "127.0.0.1",
        listen_port: int = 8443,
        created_by: str = "assessment-operator",
    ) -> tuple[AssessmentSession, str]:
        """Open a session and return its one-time-visible enrollment token."""

        assessment = self.load_assessment(assessment_id)
        if assessment.status != AssessmentStatus.OPEN:
            raise SessionError("Assessment is not open")
        profile = (
            CollectionProfile.load(profile_path)
            if profile_path is not None
            else CollectionProfile.load()
        )
        if profile.collector_mode != CollectorMode.STANDARD_USER_COLLECTION.value:
            raise SessionError("Sprint 5.0 default profile must be standard-user")
        session_id = random_id("SES-")
        token_id = random_id("TOK-")
        token_secret = random_token()
        enrollment_token = f"{token_id}.{token_secret}"
        created_at = utc_now()
        expires_at = created_at + timedelta(hours=expires_in_hours)
        root = self.storage.ensure_assessment(assessment_id)
        certificate_path = root / "keys" / f"{session_id}.cert.pem"
        private_key_path = root / "keys" / f"{session_id}.tls-key.pem"
        offline_public = root / "keys" / f"{session_id}.offline-public.xml"
        offline_private = root / "keys" / f"{session_id}.offline-private.pem"
        fingerprint = generate_session_certificate(
            certificate_path,
            private_key_path,
            listen_address,
            validity_hours=expires_in_hours + 1,
        )
        generate_offline_keypair(offline_public, offline_private)
        session = AssessmentSession(
            assessment_id=assessment_id,
            session_id=session_id,
            customer_reference=assessment.customer_reference,
            assessment_name=assessment.name,
            created_at=utc_text(created_at),
            expires_at=utc_text(expires_at),
            collector_mode=CollectorMode.STANDARD_USER_COLLECTION,
            expected_device_count=expected_devices,
            allowed_submission_count=allowed_submissions,
            allowed_source_networks=allowed_source_networks or [],
            allowed_source_addresses=allowed_source_addresses or [],
            framework_packs=list(DEFAULT_FRAMEWORK_PACKS),
            collection_profile=profile.profile_id,
            collection_profile_digest=profile.digest,
            created_by=created_by,
            status=SessionStatus.OPEN,
            token_id=token_id,
            token_hash=sha256_bytes(enrollment_token.encode("utf-8")),
            token_expires_at=utc_text(expires_at),
            token_max_uses=allowed_submissions,
            token_uses=0,
            listen_address=listen_address,
            listen_port=listen_port,
            maximum_package_size=25 * 1024 * 1024,
            request_timeout=60,
            tls_certificate_path=str(certificate_path),
            tls_private_key_path=str(private_key_path),
            tls_fingerprint=fingerprint,
            offline_public_key_path=str(offline_public),
            offline_private_key_path=str(offline_private),
            report_configuration={
                "privacyMode": "strict",
                "frameworkPackDigests": _framework_pack_digests(
                    DEFAULT_FRAMEWORK_PACKS
                ),
            },
            audit_chain_start=self._audit(assessment_id).final_hash(),
        )
        self._write_session(session)
        self._audit(assessment_id).append(
            "session_opened",
            {
                "assessmentId": assessment_id,
                "sessionId": session_id,
                "expiresAt": session.expires_at,
                "collectorMode": session.collector_mode.value,
            },
        )
        return session, enrollment_token

    def load_session(
        self, assessment_id: str, session_id: str
    ) -> AssessmentSession:
        """Load a session from storage."""

        data = self.storage.read_json(
            assessment_id, "sessions", f"{session_id}.json"
        )
        return _from_camel_dataclass(AssessmentSession, data)

    def set_session_status(
        self,
        assessment_id: str,
        session_id: str,
        status: SessionStatus,
    ) -> AssessmentSession:
        """Transition a session to an operator-selected state."""

        session = self.load_session(assessment_id, session_id)
        allowed = {
            SessionStatus.OPEN: {SessionStatus.PAUSED, SessionStatus.CLOSED},
            SessionStatus.PAUSED: {SessionStatus.OPEN, SessionStatus.CLOSED},
            SessionStatus.CLOSED: {SessionStatus.ARCHIVED},
        }
        if status not in allowed.get(session.status, set()):
            raise SessionError(
                f"Invalid session transition: {session.status.value} -> {status.value}"
            )
        session.status = status
        self._write_session(session)
        self._audit(assessment_id).append(
            f"session_{status.value.casefold()}",
            {"assessmentId": assessment_id, "sessionId": session_id},
        )
        return session

    def verify_token(
        self,
        session: AssessmentSession,
        enrollment_token: str,
    ) -> None:
        """Validate a submission-only token without storing its plaintext."""

        if session.status != SessionStatus.OPEN:
            raise SessionError("Session is not open")
        if utc_now() >= _parse_utc(session.token_expires_at):
            raise SessionError("Enrollment token has expired")
        if session.token_uses >= min(
            session.token_max_uses, session.allowed_submission_count
        ):
            raise SessionError("Enrollment token use limit reached")
        token_id = enrollment_token.partition(".")[0]
        supplied_hash = sha256_bytes(enrollment_token.encode("utf-8"))
        if token_id != session.token_id or not hmac.compare_digest(
            supplied_hash, session.token_hash
        ):
            raise SessionError("Enrollment token is invalid")

    def record_token_use(self, session: AssessmentSession) -> None:
        """Increment a token only after an accepted submission."""

        current = self.load_session(session.assessment_id, session.session_id)
        if current.token_uses >= min(
            current.token_max_uses, current.allowed_submission_count
        ):
            raise SessionError("Enrollment token use limit reached")
        current.token_uses += 1
        self._write_session(current)
        session.token_uses = current.token_uses

    def trust_collector_build(
        self,
        session: AssessmentSession,
        collector_build_digest: str,
    ) -> None:
        """Allow one Console-generated Collector build for this session."""

        values = [
            str(item)
            for item in session.report_configuration.get(
                "trustedCollectorBuildDigests", []
            )
        ]
        if collector_build_digest not in values:
            values.append(collector_build_digest)
        session.report_configuration["trustedCollectorBuildDigests"] = sorted(values)
        self._write_session(session)
        self._audit(session.assessment_id).append(
            "collector_build_trusted",
            {
                "sessionId": session.session_id,
                "collectorBuildDigest": collector_build_digest,
            },
        )

    def close_assessment(self, assessment_id: str) -> Assessment:
        """Close an assessment to further session creation."""

        assessment = self.load_assessment(assessment_id)
        assessment.status = AssessmentStatus.CLOSED
        self.storage.write_json(
            assessment_id, ("assessment.json",), model_to_dict(assessment)
        )
        self._audit(assessment_id).append(
            "assessment_closed", {"assessmentId": assessment_id}
        )
        return assessment

    def _write_session(self, session: AssessmentSession) -> Path:
        """Persist a session atomically."""

        return self.storage.write_json(
            session.assessment_id,
            ("sessions", f"{session.session_id}.json"),
            model_to_dict(session),
        )

    def _audit(self, assessment_id: str) -> ConsoleAuditLog:
        """Return the assessment audit log."""

        path = self.storage.path(assessment_id, "audit", "audit.jsonl")
        return ConsoleAuditLog(path)


def _from_camel_dataclass(model: type[T], data: dict[str, Any]) -> T:
    """Load a supported model from its camel-case JSON representation."""

    values: dict[str, Any] = {}
    for field in fields(model):
        camel = field.name.split("_")[0] + "".join(
            part[:1].upper() + part[1:] for part in field.name.split("_")[1:]
        )
        if camel in data:
            values[field.name] = data[camel]
    if model is Assessment:
        values["status"] = AssessmentStatus(values["status"])
    elif model is AssessmentSession:
        values["collector_mode"] = CollectorMode(values["collector_mode"])
        values["status"] = SessionStatus(values["status"])
    return model(**values)


def _parse_utc(value: str) -> datetime:
    """Parse a UTC timestamp."""

    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _framework_pack_digests(selections: list[str]) -> dict[str, str]:
    """Resolve configured content packs to immutable content digests."""

    from frameworks.registry import FrameworkPackRegistry

    registry = FrameworkPackRegistry()
    result: dict[str, str] = {}
    for selection in selections:
        framework_id, separator, version = selection.partition(":")
        pack = registry.resolve(framework_id, version if separator else "latest")
        result[f"{pack.framework_id}:{pack.version}"] = pack.content_hash_sha256
    return dict(sorted(result.items()))
