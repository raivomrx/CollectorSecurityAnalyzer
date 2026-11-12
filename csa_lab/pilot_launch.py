"""Assessor-authorized delivery of an independently verified private pilot.

No trust root is introduced: the existing approval/native hashes, TLS pin and
signed bundle remain authoritative. Download credentials are separate from the
one-use collection authority and never appear in a URL or command.
"""
import base64
import hashlib
import hmac
import io
import json
from pathlib import Path
import re
import secrets
import time
import zipfile
import tempfile

from csa_console.audit import ConsoleAuditLog
from csa_console.canonical import sha256_bytes, sha256_file
from csa_console.distribution import DistributionDenied
from csa_console.trusted_grants import TrustedGrantStore
from csa_console.sessions import AssessmentSessionService, _parse_utc
from csa_console.network import source_is_allowed
from csa_console.file_security import restrict_directory
from csa_lab.assessor_pilot import AssessorAuthority, bootstrap_directory, clear_private_session_files

BOOTSTRAP = Path(__file__).parent / "powershell/Receive-CSAPilot.ps1"
FILES = ("pilot-approval.json", "publisher-manifest.json", "publisher-manifest.p7s",
         "session-envelope.json", "session-envelope.p7s", "collector.zip",
         "CSA-TrustedCollector.exe", "Start-CSATrustedCollector.ps1")


def digest(value):
    return sha256_bytes(value.encode("ascii"))


class PilotLaunchService:
    def __init__(self, storage, assessment_id, session_id):
        self.storage, self.assessment_id, self.session_id = storage, assessment_id, session_id
        self.grants = TrustedGrantStore(storage)
        self.session = AssessmentSessionService(storage).load_session(assessment_id, session_id)

    def _db(self):
        return self.grants._transaction(self.session)

    @staticmethod
    def _read(path,maximum):
        if path.is_symlink():
            raise ValueError("PILOT_PACKAGE_PATH")
        with path.open("rb") as stream:
            data=stream.read(maximum+1)
        if len(data)>maximum:
            raise ValueError("PILOT_PACKAGE_TOO_LARGE")
        return data

    def _schema(self, db):
        db.execute("""CREATE TABLE IF NOT EXISTS pilot_launches (
            envelopeId TEXT PRIMARY KEY, verifiedAt INTEGER NOT NULL, verificationReferenceDigest TEXT NOT NULL,
            archiveDigest TEXT NOT NULL, authorizedAt INTEGER, authorizationReferenceDigest TEXT,
            codeDigest TEXT, codeUsed INTEGER NOT NULL DEFAULT 0, cookieDigest TEXT, cookieExpires REAL,
            ticketDigest TEXT, ticketExpires REAL, remaining INTEGER NOT NULL DEFAULT 0,
            acceptanceAt INTEGER, acceptanceReferenceDigest TEXT, retiredAt INTEGER)""")
        columns={row[1] for row in db.execute("PRAGMA table_info(pilot_launches)")}
        for name in ("bootstrapDigest","exeDigest"):
            if name not in columns:
                db.execute("ALTER TABLE pilot_launches ADD COLUMN "+name+" TEXT")

    def _audit(self, event, **values):
        ConsoleAuditLog(self.storage.path(self.assessment_id,"audit","audit.jsonl")).append(event, values)

    @staticmethod
    def _reference(value):
        if not isinstance(value,str) or not 1 <= len(value) <= 160 or any(ord(c)<32 for c in value):
            raise ValueError("PILOT_REFERENCE_REQUIRED")
        return sha256_bytes(value.encode("utf-8"))

    def _row(self, identifier, source=None, db=None):
        current=AssessmentSessionService(self.storage).load_session(self.assessment_id,self.session_id)
        if db is None:
            row=self.grants.record(current,identifier)
        else:
            value=db.execute("SELECT * FROM grants WHERE envelopeId=?",(identifier,)).fetchone()
            if value is None or value["operationState"]!="READY" or value["expiresAt"]<=time.time():
                raise DistributionDenied()
            row=dict(value)
        proof=json.loads(row["provenance"] or "{}")
        if (row["used"] or proof.get("assurance") != "ASSESSOR_VERIFIED_PILOT" or current.status.value!="OPEN"
                or _parse_utc(current.expires_at).timestamp()<=time.time()):
            raise DistributionDenied()
        if source is not None and (not source_is_allowed(current,source) or source not in json.loads(row["approvedSources"] or "[]")):
            raise DistributionDenied()
        return row

    def _launch(self, db, identifier):
        self._schema(db)
        row=db.execute("SELECT * FROM pilot_launches WHERE envelopeId=?",(identifier,)).fetchone()
        if row is None or row["retiredAt"] or not row["authorizedAt"]:
            raise DistributionDenied()
        return row

    def verify_handoff(self, identifier, reference, approval_sha, exe_sha):
        row=self._row(identifier)
        proof=json.loads(row["provenance"])
        bundle=Path(row["bundlePath"])
        expected=proof["facts"]["approvalDigest"]
        if approval_sha!=expected or exe_sha!=sha256_file(bundle/"CSA-TrustedCollector.exe"):
            raise ValueError("PILOT_INDEPENDENT_COMPARISON_FAILED")
        snapshots={name:self._read(bundle/name,64*1024*1024 if name=="collector.zip" else 16*1024*1024) for name in FILES}
        if sha256_bytes(snapshots["CSA-TrustedCollector.exe"])!=exe_sha:
            raise ValueError("PILOT_BUNDLE_CHANGED")
        # Validate the exact captured bytes that will be delivered, not a
        # different reopening of the mutable source directory.
        with tempfile.TemporaryDirectory(dir=bundle.parent) as directory:
            snapshot=Path(directory);restrict_directory(snapshot)
            for name,data in snapshots.items():
                (snapshot/name).write_bytes(data)
            actual=AssessorAuthority(bootstrap_directory()/"CSA-TrustedCollector.exe",expected).verify(snapshot)
            if actual.record()!=proof:
                raise ValueError("PILOT_BUNDLE_CHANGED")
        # Stable archive, created once. Public starter contains only public pins.
        starter=('@echo off\r\n"%~dp0CSA-TrustedCollector.exe" --assessor-pilot --bundle "%~dp0." '
                 '--approval-sha256 '+expected+'\r\nif errorlevel 1 pause\r\n').encode("ascii")
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,"w",zipfile.ZIP_DEFLATED) as archive:
            for name in FILES:
                archive.writestr(name,snapshots[name])
            archive.writestr("Start-CSACollector.cmd",starter)
        data=stream.getvalue()
        if len(data)>64*1024*1024:
            raise ValueError("PILOT_PACKAGE_TOO_LARGE")
        path=bundle/"customer-package.zip"
        with self._db() as db:
            self._schema(db)
            if db.execute("SELECT 1 FROM pilot_launches WHERE envelopeId=?",(identifier,)).fetchone():
                raise ValueError("PILOT_ALREADY_VERIFIED")
            path.write_bytes(data)
            db.execute("INSERT INTO pilot_launches(envelopeId,verifiedAt,verificationReferenceDigest,archiveDigest,bootstrapDigest,exeDigest) VALUES (?,?,?,?,?,?)",
                       (identifier,int(time.time()),self._reference(reference),sha256_bytes(data),sha256_file(BOOTSTRAP),exe_sha))
        self._audit("pilot_independent_handoff_verified",envelopeId=identifier,archiveDigest=sha256_bytes(data),
                    referenceDigest=self._reference(reference))
        return self.status(identifier)

    def authorize(self, identifier, reference):
        self._row(identifier)
        code=secrets.token_urlsafe(24)
        with self._db() as db:
            self._schema(db)
            updated=db.execute("""UPDATE pilot_launches SET authorizedAt=?,authorizationReferenceDigest=?,codeDigest=?
                WHERE envelopeId=? AND authorizedAt IS NULL AND retiredAt IS NULL""",
                (int(time.time()),self._reference(reference),digest(code),identifier))
            if updated.rowcount!=1:
                raise ValueError("PILOT_VERIFY_HANDOFF_FIRST")
        self._audit("pilot_execution_authorized",envelopeId=identifier,referenceDigest=self._reference(reference))
        return {**self.status(identifier),"deliveryCode":code}

    def _by_code(self, db, code, source):
        if not isinstance(code,str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}",code):
            raise DistributionDenied()
        self._schema(db)
        row=db.execute("SELECT * FROM pilot_launches WHERE codeDigest=? AND codeUsed=0 AND retiredAt IS NULL",(digest(code),)).fetchone()
        if row is None:
            raise DistributionDenied()
        self._row(row["envelopeId"],source,db)
        if not row["authorizedAt"]:
            raise DistributionDenied()
        return row

    def login(self, code, source):
        cookie=secrets.token_urlsafe(32)
        with self._db() as db:
            row=self._by_code(db,code,source)
            db.execute("UPDATE pilot_launches SET cookieDigest=?,cookieExpires=? WHERE envelopeId=?",
                       (digest(cookie),time.time()+600,row["envelopeId"]))
        self._audit("pilot_customer_launch_opened",envelopeId=row["envelopeId"])
        return cookie

    def has_authorized(self, source):
        if not self.grants._path(self.session).is_file():
            return False
        with self._db() as db:
            self._schema(db)
            identifiers=[row[0] for row in db.execute("SELECT envelopeId FROM pilot_launches WHERE authorizedAt IS NOT NULL AND codeUsed=0 AND retiredAt IS NULL")]
        for identifier in identifiers:
            try:
                self._row(identifier,source)
                return True
            except ValueError:
                continue
        return False

    def customer_view(self, cookie, source):
        if not cookie or not self.grants._path(self.session).is_file():
            return None
        try:
            with self._db() as db:
                self._schema(db)
                row=db.execute("SELECT * FROM pilot_launches WHERE cookieDigest=? AND cookieExpires>? AND retiredAt IS NULL",
                               (digest(cookie),time.time())).fetchone()
                if row is None:
                    return None
                grant=self._row(row["envelopeId"],source,db)
                if row["codeUsed"] and ((row["ticketExpires"] or 0)<=time.time() or row["remaining"]<=0):
                    return None
            return {**self._view(row,grant),"allowQuick":not bool(row["codeUsed"])}
        except (OSError,ValueError):
            return None

    def _view(self, launch, grant):
        bundle=Path(grant["bundlePath"])
        proof=json.loads(grant["provenance"])
        config=json.loads(grant["details"])
        return {"handoffId":grant["envelopeId"],"archiveSha256":launch["archiveDigest"],
            "approvalSha256":proof["facts"]["approvalDigest"],"exeSha256":launch["exeDigest"],
            "origin":config["origin"],"tlsFingerprint":config["tlsFingerprint"],
            "bootstrapSha256":launch["bootstrapDigest"],"expiresAt":grant["expiresAt"]}

    def bootstrap(self, identifier, source):
        self._row(identifier,source)
        with self._db() as db:
            row=self._launch(db,identifier)
        data=BOOTSTRAP.read_bytes()
        if sha256_bytes(data)!=row["bootstrapDigest"]:
            raise ValueError("PILOT_BOOTSTRAP_CHANGED")
        return data  # Fixed verifier, no private data or session credentials.

    def ticket(self, identifier, source, *, code=None, cookie=None):
        grant=self._row(identifier,source)
        ticket=secrets.token_urlsafe(32)
        with self._db() as db:
            row=self._launch(db,identifier)
            if code is not None:
                bycode=self._by_code(db,code,source)
                if bycode["envelopeId"]!=identifier:
                    raise DistributionDenied()
            elif not cookie or not hmac.compare_digest(row["cookieDigest"] or "",digest(cookie)) or (row["cookieExpires"] or 0)<=time.time():
                raise DistributionDenied()
            if row["codeUsed"]:
                # Browser retry may reuse its authenticated bounded ticket.
                raise DistributionDenied()
            expires=min(time.time()+120,grant["expiresAt"])
            db.execute("UPDATE pilot_launches SET codeUsed=1,ticketDigest=?,ticketExpires=?,remaining=3 WHERE envelopeId=?",
                       (digest(ticket),expires,identifier))
        self._audit("pilot_download_authorized",envelopeId=identifier,purpose="PRIVATE_PACKAGE",expiresAt=int(expires))
        return {"ticket":ticket,"expiresAt":int(expires)}

    def package(self, identifier, source, ticket):
        grant=self._row(identifier,source)
        with self._db() as db:
            row=self._launch(db,identifier)
            if (not ticket or not hmac.compare_digest(row["ticketDigest"] or "",digest(ticket))
                    or (row["ticketExpires"] or 0)<=time.time() or row["remaining"]<=0):
                raise DistributionDenied()
            path=Path(grant["bundlePath"])/"customer-package.zip"
            data=self._read(path,64*1024*1024)
            if sha256_bytes(data)!=row["archiveDigest"]:
                raise ValueError("PILOT_PACKAGE_CHANGED")
            db.execute("UPDATE pilot_launches SET remaining=remaining-1 WHERE envelopeId=?",(identifier,))
        self._audit("pilot_private_package_delivered",envelopeId=identifier)
        return data

    def status(self, identifier):
        # Historical status survives consumption/retirement and never claims live acceptance from CI.
        with self._db() as db:
            self._schema(db)
            grant=db.execute("SELECT * FROM grants WHERE envelopeId=?",(identifier,)).fetchone()
            launch=db.execute("SELECT * FROM pilot_launches WHERE envelopeId=?",(identifier,)).fetchone()
        if grant is None:
            raise ValueError("PILOT_HANDOFF_UNKNOWN")
        received=bool(grant["submissionId"] and self.storage.path(self.assessment_id,"submissions","accepted",grant["submissionId"]+".receipt.json").is_file())
        expired=grant["expiresAt"]<=time.time()
        current=AssessmentSessionService(self.storage).load_session(self.assessment_id,self.session_id)
        session_active=current.status.value=="OPEN" and _parse_utc(current.expires_at).timestamp()>time.time()
        state=("REVOKED" if grant["reasonCode"]=="PILOT_REVOKED" else "ISSUANCE_FAILED" if grant["operationState"]=="FAILED"
               else "ACCEPTANCE_COMPLETED" if launch and launch["acceptanceAt"] else "EVIDENCE_RECEIVED" if received
               else "EXPIRED" if expired else "SESSION_INACTIVE" if not session_active else "EXECUTION_STARTED" if grant["used"] else "AUTHORIZED_FOR_EXECUTION" if launch and launch["authorizedAt"]
               else "INDEPENDENT_HANDOFF_VERIFIED" if launch else "PACKAGE_PREPARED")
        return {"handoffId":identifier,"state":state,"packagePrepared":True,
            "executionTransport":grant["requestedMode"],
            "executionTransportEvidence":"CLIENT_REQUEST_NOT_POLICY_ATTESTATION",
            "independentHandoffVerified":bool(launch and launch["verifiedAt"]),"authorizedForExecution":bool(launch and launch["authorizedAt"] and session_active and not expired and not grant["used"] and not launch["retiredAt"]),
            "evidenceReceived":received,"acceptanceCompleted":bool(launch and launch["acceptanceAt"]),
            "expiresAt":grant["expiresAt"],"publicRelease":"HOLD"}

    def accept(self, identifier, reference, report_path=None):
        if not self.status(identifier)["evidenceReceived"]:
            raise ValueError("PILOT_RECEIPT_REQUIRED")
        if not report_path or not Path(report_path).is_file():
            raise ValueError("PILOT_HTML_REPORT_REQUIRED")
        with self._db() as db:
            db.execute("UPDATE pilot_launches SET acceptanceAt=?,acceptanceReferenceDigest=? WHERE envelopeId=?",
                       (int(time.time()),self._reference(reference),identifier))
        self._audit("pilot_live_acceptance_recorded",envelopeId=identifier,referenceDigest=self._reference(reference))
        return self.status(identifier)

    def retire(self, identifier, *, revoke=False):
        state=self.status(identifier)
        if not revoke and not state["evidenceReceived"] and state["state"]!="EXPIRED":
            raise ValueError("PILOT_RETIRE_NOT_DUE")
        with self._db() as db:
            grant=db.execute("SELECT * FROM grants WHERE envelopeId=?",(identifier,)).fetchone()
            self._schema(db)
            db.execute("INSERT OR IGNORE INTO pilot_launches(envelopeId,verifiedAt,verificationReferenceDigest,archiveDigest) VALUES (?,0,'','')",(identifier,))
            db.execute("UPDATE pilot_launches SET codeDigest=NULL,cookieDigest=NULL,ticketDigest=NULL WHERE envelopeId=?",
                       (identifier,))
            if revoke and not state["evidenceReceived"]:
                db.execute("UPDATE grants SET operationState='FAILED',reasonCode=COALESCE(reasonCode,'PILOT_REVOKED') WHERE envelopeId=?",(identifier,))
        bundle=Path(grant["bundlePath"]) if grant["bundlePath"] else self.storage.path(self.assessment_id,"pilot-handoffs",identifier)
        try:
            clear_private_session_files(bundle,self.storage.path(self.assessment_id,"pilot-handoffs"))
        except OSError:
            self._audit("pilot_private_cleanup_pending",envelopeId=identifier,code="PILOT_CLEANUP_PENDING")
            raise ValueError("PILOT_CLEANUP_PENDING") from None
        with self._db() as db:
            db.execute("UPDATE pilot_launches SET retiredAt=? WHERE envelopeId=?",(int(time.time()),identifier))
        self._audit("pilot_private_material_retired",envelopeId=identifier,reason="REVOKED" if revoke else state["state"])
        return self.status(identifier)

    def list_status(self):
        if not self.grants._path(self.session).is_file():
            return []
        with self._db() as db:
            self._schema(db)
            rows=[dict(row) for row in db.execute("SELECT grants.*,pilot_launches.retiredAt FROM grants LEFT JOIN pilot_launches USING(envelopeId)")]
        result=[]
        for row in rows:
            proof=json.loads(row["provenance"] or "{}")
            if proof.get("assurance")!="ASSESSOR_VERIFIED_PILOT" and not (row["envelopeId"].startswith("PILOT-") and row["operationState"]=="FAILED"):
                continue
            status=self.status(row["envelopeId"])
            if not row["retiredAt"] and (status["evidenceReceived"] or status["state"] in {"EXPIRED","REVOKED","ISSUANCE_FAILED"}):
                try:
                    status=self.retire(row["envelopeId"],revoke=status["state"] in {"REVOKED","ISSUANCE_FAILED"})
                except ValueError:
                    status["cleanupPending"]=True
            result.append(status)
        return result
