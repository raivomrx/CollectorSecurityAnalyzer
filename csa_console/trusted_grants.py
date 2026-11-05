"""Atomic one-use authorization for independently signed session handoffs."""
from contextlib import contextmanager
import re
import sqlite3
import time

from csa_console.audit import ConsoleAuditLog
from csa_console.canonical import path_lock, sha256_bytes
from csa_console.sessions import AssessmentSessionService


class TrustedGrantStore:
    def __init__(self, storage):
        self.storage = storage
        self.sessions = AssessmentSessionService(storage)

    def _path(self, session):
        return self.storage.path(session.assessment_id, "sessions", "trusted-grants", session.session_id + ".sqlite3")

    def required(self, session):
        return bool(session.report_configuration.get("trustedEnvelopeRequired") or self._path(session).exists())

    @contextmanager
    def _transaction(self, session, *, create=False):
        path = self._path(session)
        if not create and not path.is_file():
            raise ValueError("CSA-TRUST-SESSION")
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = None
        try:
            connection = sqlite3.connect(path, timeout=5, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN IMMEDIATE")
            if create:
                connection.execute("""CREATE TABLE IF NOT EXISTS grants (
                    envelopeId TEXT PRIMARY KEY, nonceDigest TEXT NOT NULL UNIQUE,
                    recipientId TEXT NOT NULL, expiresAt INTEGER NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0 CHECK (used IN (0,1)),
                    submissionId TEXT, transport TEXT)""")
            yield connection
            connection.commit()
        except sqlite3.IntegrityError as error:
            raise ValueError("CSA-TRUST-REPLAY") from error
        except sqlite3.Error as error:
            raise ValueError("CSA-TRUST-STORAGE") from error
        finally:
            if connection is not None:
                connection.close()  # Roll back an incomplete transaction.

    def issue(self, session, envelope):
        if (envelope.get("assessmentId") != session.assessment_id
                or envelope.get("sessionId") != session.session_id
                or type(envelope.get("expiresAt")) is not int or envelope["expiresAt"] <= time.time()
                or any(not isinstance(envelope.get(field), str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", envelope[field])
                       for field in ("envelopeId", "nonce", "recipientId"))):
            raise ValueError("CSA-TRUST-SESSION")
        session_path = self.storage.path(session.assessment_id, "sessions", session.session_id + ".json")
        with path_lock(session_path), self._transaction(session, create=True) as connection:
            current = self.sessions.load_session(session.assessment_id, session.session_id)
            current.report_configuration["trustedEnvelopeRequired"] = True
            self.sessions._write_session(current)
            connection.execute("INSERT INTO grants (envelopeId,nonceDigest,recipientId,expiresAt) VALUES (?,?,?,?)",
                (envelope["envelopeId"], sha256_bytes(envelope["nonce"].encode("ascii")), envelope["recipientId"], envelope["expiresAt"]))
        self._audit(session).append("trusted_session_envelope_issued", {
            "sessionId": session.session_id, "envelopeId": envelope["envelopeId"], "expiresAt": envelope["expiresAt"]})

    def consume(self, session, envelope_id, nonce, submission_id, transport):
        if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", nonce) or (
                envelope_id and not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", envelope_id)):
            raise ValueError("CSA-TRUST-SESSION")
        with self._transaction(session) as connection:
            row = connection.execute("SELECT * FROM grants WHERE nonceDigest=? AND (?='' OR envelopeId=?)",
                                     (sha256_bytes(nonce.encode("ascii")), envelope_id, envelope_id)).fetchone()
            if row is None or row["expiresAt"] <= time.time():
                raise ValueError("CSA-TRUST-SESSION")
            if row["used"]:
                raise ValueError("CSA-TRUST-REPLAY")
            updated = connection.execute("UPDATE grants SET used=1,submissionId=?,transport=? WHERE envelopeId=? AND used=0",
                                         (submission_id, transport, row["envelopeId"]))
            if updated.rowcount != 1:
                raise ValueError("CSA-TRUST-REPLAY")
            accepted_id = row["envelopeId"]
        self._audit(session).append("trusted_session_envelope_consumed", {
            "sessionId": session.session_id, "envelopeId": accepted_id, "submissionId": submission_id, "transport": transport})

    def require_authorized_submission(self, session, submission_id):
        """A previously issued legacy nonce cannot bypass the trusted session gate."""
        with self._transaction(session) as connection:
            count = connection.execute("SELECT COUNT(*) FROM grants WHERE used=1 AND submissionId=? AND transport='HTTPS' AND expiresAt>?",
                                       (submission_id, time.time())).fetchone()[0]
            if count != 1:
                raise ValueError("CSA-TRUST-SESSION")

    def _audit(self, session):
        return ConsoleAuditLog(self.storage.path(session.assessment_id, "audit", "audit.jsonl"))
