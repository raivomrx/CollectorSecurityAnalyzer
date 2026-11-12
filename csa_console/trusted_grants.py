"""Durable issuance and atomic one-use ADR 565 authorization; no cross-store atomicity claim."""
from contextlib import contextmanager
import hmac
import json
from pathlib import Path
import re
import secrets
import sqlite3
import time

from csa_console.audit import ConsoleAuditLog
from csa_console.canonical import path_lock, sha256_bytes
from csa_console.sessions import AssessmentSessionService
from csa_console.trust_evidence import VerifiedTrustEvidence


def _digest(value):
    return sha256_bytes(value.encode("ascii"))


def _locator(value):
    return isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z0-9_-]{16,128}", value))


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
            connection.execute("""CREATE TABLE IF NOT EXISTS grants (
                envelopeId TEXT PRIMARY KEY, nonceDigest TEXT NOT NULL UNIQUE,
                recipientId TEXT NOT NULL, expiresAt INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0 CHECK (used IN (0,1)), submissionId TEXT, transport TEXT)""")
            columns = {row[1] for row in connection.execute("PRAGMA table_info(grants)")}
            for name, declaration in {
                "operationState": "TEXT NOT NULL DEFAULT 'READY'", "reasonCode": "TEXT",
                "details": "TEXT NOT NULL DEFAULT '{}'", "buildDigest": "TEXT",
                "provenance": "TEXT", "bundlePath": "TEXT", "networkEnabled": "INTEGER NOT NULL DEFAULT 0",
                "authSecretDigest": "TEXT", "authUsed": "INTEGER NOT NULL DEFAULT 0",
                "requestedMode": "TEXT NOT NULL DEFAULT 'NOT_RECORDED'",
                "approvedSources": "TEXT",
            }.items():
                if name not in columns:
                    connection.execute("ALTER TABLE grants ADD COLUMN " + name + " " + declaration)
            connection.execute("""CREATE TABLE IF NOT EXISTS challenges (
                challengeId TEXT PRIMARY KEY,envelopeId TEXT NOT NULL,nonceDigest TEXT NOT NULL,
                expiresAt REAL NOT NULL,used INTEGER NOT NULL DEFAULT 0)""")
            connection.execute("""CREATE TABLE IF NOT EXISTS tickets (
                tokenDigest TEXT PRIMARY KEY,envelopeId TEXT NOT NULL,expiresAt REAL NOT NULL,remaining INTEGER NOT NULL)""")
            connection.execute("""CREATE TABLE IF NOT EXISTS downloads (
                tokenDigest TEXT PRIMARY KEY,envelopeId TEXT NOT NULL,expiresAt REAL NOT NULL,used INTEGER NOT NULL DEFAULT 0)""")
            yield connection
            connection.commit()
        except sqlite3.IntegrityError as error:
            raise ValueError("CSA-TRUST-REPLAY") from error
        except sqlite3.Error as error:
            raise ValueError("CSA-TRUST-STORAGE") from error
        finally:
            if connection is not None:
                connection.close()

    def begin_issue(self, session, envelope, *, private_proof=None, authorization_secret=None):
        proof = private_proof or envelope["nonce"]
        if (envelope.get("assessmentId") != session.assessment_id or envelope.get("sessionId") != session.session_id
                or type(envelope.get("expiresAt")) is not int or envelope["expiresAt"] <= time.time()
                or not all(_locator(envelope.get(field)) for field in ("envelopeId", "nonce", "recipientId"))
                or not _locator(proof) or authorization_secret is not None and not _locator(authorization_secret)):
            raise ValueError("CSA-TRUST-SESSION")
        # Commit PREPARING before any session JSON, publication or audit effects.
        with self._transaction(session, create=True) as connection:
            connection.execute("""INSERT INTO grants (envelopeId,nonceDigest,recipientId,expiresAt,
                operationState,details,authSecretDigest) VALUES (?,?,?,?,'PREPARING',?,?)""",
                (envelope["envelopeId"], _digest(proof), envelope["recipientId"], envelope["expiresAt"],
                 json.dumps({key: envelope.get(key) for key in ("assessmentId", "sessionId", "publisherManifestDigest",
                    "packageDigest", "sessionManifestDigest", "profileDigest", "privacyPolicyDigest", "tlsFingerprint", "origin")}),
                 _digest(authorization_secret) if authorization_secret is not None else None))

    def finish_issue(self, session, envelope, *, build_digest=None, provenance=None, bundle_path=None, network=False, approved_sources=None):
        try:
            if provenance is not None:
                if not isinstance(provenance, VerifiedTrustEvidence):
                    raise ValueError("CSA-TRUST-ATTESTATION-SCOPE")
                provenance.bind(session, envelope)
                if build_digest != provenance.facts["collectorBuildDigest"]:
                    raise ValueError("CSA-TRUST-ATTESTATION-SCOPE")
            if network and (provenance is None or envelope.get("schemaVersion") != 2 or bundle_path is None):
                raise ValueError("CSA-TRUST-ENROLLMENT")
            session_path = self.storage.path(session.assessment_id, "sessions", session.session_id + ".json")
            with path_lock(session_path):
                current = self.sessions.load_session(session.assessment_id, session.session_id)
                current.report_configuration["trustedEnvelopeRequired"] = True
                if build_digest:
                    values = set(current.report_configuration.get("trustedCollectorBuildDigests", []))
                    current.report_configuration["trustedCollectorBuildDigests"] = sorted(values | {build_digest})
                self.sessions._write_session(current)
            # Audit preparation precedes READY; audit failure can never activate authority.
            self._audit(session).append("trusted_session_envelope_prepared", {
                "sessionId": session.session_id, "envelopeId": envelope["envelopeId"], "expiresAt": envelope["expiresAt"],
                "operationState": "PREPARING", "assurance": provenance.assurance if provenance else "NOT_EVALUATED"})
            with self._transaction(session) as connection:
                updated = connection.execute("""UPDATE grants SET operationState='READY',buildDigest=?,provenance=?,
                    bundlePath=?,networkEnabled=?,approvedSources=?,expiresAt=?,reasonCode=NULL WHERE envelopeId=? AND operationState='PREPARING' AND used=0""",
                    (build_digest, json.dumps(provenance.record()) if provenance else None,
                     str(bundle_path) if bundle_path else None, int(network),
                     json.dumps(approved_sources) if approved_sources else None,
                     min(envelope["expiresAt"], provenance.facts["expiresAt"]) if provenance else envelope["expiresAt"], envelope["envelopeId"]))
                if updated.rowcount != 1:
                    raise ValueError("CSA-TRUST-ISSUANCE-STATE")
        except Exception:
            self.fail_issue(session, envelope["envelopeId"], "CSA-TRUST-ISSUANCE-FAILED")
            raise

    def fail_issue(self, session, envelope_id, code):
        try:
            with self._transaction(session) as connection:
                connection.execute("UPDATE grants SET operationState='FAILED',reasonCode=? WHERE envelopeId=? AND operationState='PREPARING' AND used=0",
                                   (code, envelope_id))
        except (ValueError, OSError, sqlite3.Error):
            # The persistent PREPARING row is already nonconsumable; never reset it.
            pass

    def issue(self, session, envelope, **options):
        self.begin_issue(session, envelope, private_proof=options.pop("private_proof", None),
                         authorization_secret=options.pop("authorization_secret", None))
        self.finish_issue(session, envelope, **options)

    def reconcile(self, session):
        with self._transaction(session, create=True) as connection:
            connection.execute("UPDATE grants SET operationState='FAILED',reasonCode='CSA-TRUST-ISSUANCE-INTERRUPTED' WHERE operationState='PREPARING' AND used=0")
            for ready in connection.execute("SELECT envelopeId,bundlePath FROM grants WHERE operationState='READY' AND used=0 AND bundlePath IS NOT NULL").fetchall():
                if not all((Path(ready["bundlePath"]) / name).is_file() for name in
                           ("publisher-manifest.json", "publisher-manifest.p7s", "session-envelope.json", "session-envelope.p7s", "collector.zip")):
                    connection.execute("UPDATE grants SET operationState='FAILED',reasonCode='CSA-TRUST-PUBLICATION-MISSING' WHERE envelopeId=? AND used=0",
                                       (ready["envelopeId"],))
            rows = [dict(row) for row in connection.execute("SELECT envelopeId,operationState,used,reasonCode FROM grants")]
        path = self.storage.path(session.assessment_id, "sessions", session.session_id + ".json")
        with path_lock(path):
            current = self.sessions.load_session(session.assessment_id, session.session_id)
            current.report_configuration["trustedEnvelopeRequired"] = True
            self.sessions._write_session(current)
        self._audit(session).append("trusted_issuance_reconciled", {"sessionId": session.session_id,
            "failedOperations": sum(row["operationState"] == "FAILED" for row in rows), "consumedOperations": sum(row["used"] for row in rows)})
        return {"items": rows, "action": "ISSUE_NEW_ENVELOPE", "legacyFallbackAllowed": False}

    def consume(self, session, envelope_id, nonce, submission_id, transport, source_address=None, requested_execution_mode="NOT_RECORDED"):
        if not _locator(nonce) or envelope_id and not _locator(envelope_id):
            raise ValueError("CSA-TRUST-SESSION")
        with self._transaction(session) as connection:
            row = connection.execute("SELECT * FROM grants WHERE nonceDigest=? AND (?='' OR envelopeId=?)",
                                     (_digest(nonce), envelope_id, envelope_id)).fetchone()
            if row is None or row["expiresAt"] <= time.time() or row["operationState"] != "READY":
                raise ValueError("CSA-TRUST-SESSION")
            if row["used"]:
                raise ValueError("CSA-TRUST-REPLAY")
            if row["provenance"]:
                proof = json.loads(row["provenance"])
                if proof.get("assurance") == "ASSESSOR_VERIFIED_PILOT":
                    if proof["facts"]["expiresAt"] <= time.time():
                        raise ValueError("CSA-TRUST-EXPIRED")
                    if transport == "HTTPS" and source_address not in json.loads(row["approvedSources"] or "[]"):
                        raise ValueError("CSA-TRUST-SOURCE")
                    if requested_execution_mode in {"EXE", "POWERSHELL_STANDARD_POLICY", "STANDARD_POLICY", "QUICK_RUN_PROCESS_BYPASS"}:
                        connection.execute("UPDATE grants SET requestedMode=? WHERE envelopeId=?", (requested_execution_mode, row["envelopeId"]))
            if row["networkEnabled"] and not row["authUsed"]:
                raise ValueError("CSA-TRUST-AUTHORIZATION")
            connection.execute("UPDATE grants SET used=1,submissionId=?,transport=? WHERE envelopeId=? AND used=0",
                               (submission_id, transport, row["envelopeId"]))
            accepted_id = row["envelopeId"]
        self._audit(session).append("trusted_session_envelope_consumed", {
            "sessionId": session.session_id, "envelopeId": accepted_id, "submissionId": submission_id, "transport": transport})

    def require_authorized_submission(self, session, submission_id):
        with self._transaction(session) as connection:
            count = connection.execute("SELECT COUNT(*) FROM grants WHERE operationState='READY' AND used=1 AND submissionId=? AND transport='HTTPS' AND expiresAt>?",
                                       (submission_id, time.time())).fetchone()[0]
            if count != 1:
                raise ValueError("CSA-TRUST-SESSION")

    def record(self, session, envelope_id):
        with self._transaction(session) as connection:
            row = connection.execute("SELECT * FROM grants WHERE envelopeId=?", (envelope_id,)).fetchone()
            if row is None or row["operationState"] != "READY" or row["expiresAt"] <= time.time():
                raise ValueError("CSA-TRUST-SESSION")
            return dict(row)

    def network_records(self, session):
        if not self._path(session).exists():
            return []
        with self._transaction(session) as connection:
            return [dict(row) for row in connection.execute("SELECT * FROM grants WHERE operationState='READY' AND networkEnabled=1 AND authUsed=0 AND used=0 AND expiresAt>?", (time.time(),))]

    def challenge(self, session, envelope_id, envelope_digest):
        row = self.record(session, envelope_id)
        if not row["networkEnabled"] or row["authUsed"] or row["used"]:
            raise ValueError("CSA-TRUST-AUTHORIZATION")
        identifier, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(32)
        expires = min(time.time() + 90, row["expiresAt"])
        with self._transaction(session) as connection:
            connection.execute("DELETE FROM challenges WHERE expiresAt<=? OR used=1", (time.time(),))
            if connection.execute("SELECT COUNT(*) FROM challenges WHERE envelopeId=?", (envelope_id,)).fetchone()[0] >= 32:
                raise ValueError("CSA-TRUST-CHALLENGE")
            connection.execute("INSERT INTO challenges VALUES (?,?,?,?,0)", (identifier, envelope_id, _digest(nonce), expires))
        return {"challengeId": identifier, "nonce": nonce, "envelopeId": envelope_id, "recipientId": row["recipientId"],
                "assessmentId": session.assessment_id, "sessionId": session.session_id, "envelopeDigest": envelope_digest,
                "purpose": "COLLECTOR_DOWNLOAD", "expiresAt": int(expires)}

    def authorize(self, session, envelope_id, challenge_id, challenge_nonce, recipient_id, secret, requested_mode="STANDARD_POLICY"):
        if not all(_locator(value) for value in (envelope_id, challenge_id, challenge_nonce, recipient_id, secret)):
            raise ValueError("CSA-TRUST-AUTHORIZATION")
        if not isinstance(requested_mode, str) or requested_mode not in {"STANDARD_POLICY", "QUICK_RUN_PROCESS_BYPASS"}:
            raise ValueError("CSA-TRUST-MODE")
        ticket = secrets.token_urlsafe(32)
        with self._transaction(session) as connection:
            row = connection.execute("SELECT * FROM grants WHERE envelopeId=?", (envelope_id,)).fetchone()
            challenge = connection.execute("SELECT * FROM challenges WHERE challengeId=? AND envelopeId=?", (challenge_id, envelope_id)).fetchone()
            now = time.time()
            if (row is None or row["operationState"] != "READY" or not row["networkEnabled"] or row["authUsed"] or row["used"]
                    or row["expiresAt"] <= now or row["recipientId"] != recipient_id or not row["authSecretDigest"]
                    or not hmac.compare_digest(row["authSecretDigest"], _digest(secret)) or challenge is None
                    or challenge["used"] or challenge["expiresAt"] <= now or not hmac.compare_digest(challenge["nonceDigest"], _digest(challenge_nonce))):
                raise ValueError("CSA-TRUST-AUTHORIZATION")
            connection.execute("UPDATE challenges SET used=1 WHERE challengeId=?", (challenge_id,))
            connection.execute("UPDATE grants SET authUsed=1,requestedMode=? WHERE envelopeId=?", (requested_mode, envelope_id))
            expires = min(now + 120, row["expiresAt"])
            connection.execute("INSERT INTO tickets VALUES (?,?,?,3)", (_digest(ticket), envelope_id, expires))
        self._audit(session).append("trusted_endpoint_authorized", {"sessionId": session.session_id, "envelopeId": envelope_id,
            "purpose": "COLLECTOR_DOWNLOAD", "expiresAt": int(expires), "requestedExecutionMode": requested_mode,
            "executionModeEvidence": "CLIENT_REQUEST_NOT_POLICY_ATTESTATION"})
        return {"authorizationTicket": ticket, "envelopeId": envelope_id, "expiresAt": int(expires)}

    def mint_download(self, session, envelope_id, ticket):
        if not _locator(ticket):
            raise ValueError("CSA-TRUST-DOWNLOAD")
        grant = secrets.token_urlsafe(32)
        with self._transaction(session) as connection:
            row = connection.execute("""SELECT tickets.* FROM tickets JOIN grants USING(envelopeId)
                WHERE tokenDigest=? AND envelopeId=? AND grants.operationState='READY'
                AND grants.networkEnabled=1 AND grants.authUsed=1 AND grants.used=0 AND grants.expiresAt>?""",
                (_digest(ticket), envelope_id, time.time())).fetchone()
            if row is None or row["expiresAt"] <= time.time() or row["remaining"] <= 0:
                raise ValueError("CSA-TRUST-DOWNLOAD")
            connection.execute("UPDATE tickets SET remaining=remaining-1 WHERE tokenDigest=?", (_digest(ticket),))
            expires = min(time.time() + 45, row["expiresAt"])
            connection.execute("DELETE FROM downloads WHERE expiresAt<=?", (time.time(),))
            connection.execute("INSERT INTO downloads VALUES (?,?,?,0)", (_digest(grant), envelope_id, expires))
        return {"downloadGrant": grant, "envelopeId": envelope_id, "expiresAt": int(expires)}

    def consume_download(self, session, envelope_id, grant):
        if not _locator(grant):
            raise ValueError("CSA-TRUST-DOWNLOAD")
        with self._transaction(session) as connection:
            now = time.time()
            updated = connection.execute("""UPDATE downloads SET used=1
                WHERE tokenDigest=? AND envelopeId=? AND used=0 AND expiresAt>?
                AND EXISTS (SELECT 1 FROM grants WHERE grants.envelopeId=downloads.envelopeId
                    AND operationState='READY' AND networkEnabled=1 AND authUsed=1 AND grants.used=0 AND grants.expiresAt>?)""",
                                         (_digest(grant), envelope_id, now, now))
            if updated.rowcount != 1:
                raise ValueError("CSA-TRUST-DOWNLOAD")

    def submission_provenance(self, session, submission_id, transport):
        if not self._path(session).exists():
            return None
        with self._transaction(session) as connection:
            rows = connection.execute("SELECT * FROM grants WHERE operationState='READY' AND used=1 AND submissionId=? AND transport=?", (submission_id, transport)).fetchall()
            if len(rows) != 1 or not rows[0]["provenance"]:
                return None
            row = rows[0]
            return {"envelopeId": row["envelopeId"], "buildDigest": row["buildDigest"],
                    "verification": json.loads(row["provenance"]), "authorization": "ONE_USE_ASSESSOR_HANDOFF",
                    "requestedExecutionMode": row["requestedMode"]}

    def require_evidence_binding(self, session, submission_id, transport, package):
        if not self.required(session):
            return
        with self._transaction(session) as connection:
            rows = connection.execute("SELECT * FROM grants WHERE operationState='READY' AND used=1 AND submissionId=? AND transport=?",
                                      (submission_id, transport)).fetchall()
            if len(rows) != 1:
                raise ValueError("CSA-TRUST-SESSION")
            row = rows[0]
            details = json.loads(row["details"])
            if row["buildDigest"] and package.manifest.get("collectorBuildDigest") != row["buildDigest"]:
                raise ValueError("CSA-TRUST-ENGINE")
            if details.get("profileDigest") and package.manifest.get("collectionProfileDigest") != details["profileDigest"]:
                raise ValueError("CSA-TRUST-PROFILE")

    def _audit(self, session):
        return ConsoleAuditLog(self.storage.path(session.assessment_id, "audit", "audit.jsonl"))
