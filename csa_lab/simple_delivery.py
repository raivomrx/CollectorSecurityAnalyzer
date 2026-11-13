"""Start Collector -> source-scoped ADR 5682 delivery, using the existing signer/verifier.

The trusted local Lab installation is the assessor's independent handoff channel.
No customer browser, JSON flag or downloaded hash can create this authorization.
Production Publisher enrollment and real HOME/LAB acceptance remain separate.
"""
import hashlib
import base64
import io
import ipaddress
import json
import os
import re
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import zipfile

from csa_console.canonical import sha256_bytes, sha256_file
from csa_console.collector_package import COLLECTOR_VERSION
from csa_console.distribution import DistributionDenied
from csa_console.file_security import restrict_directory
from csa_console.network import source_is_allowed
from csa_console.sessions import _parse_utc
from csa_console.trusted_grants import TrustedGrantStore
from csa_lab.assessor_pilot import bootstrap_directory, issue_assessor_pilot
from csa_lab.pilot_launch import AssessorAuthority, FILES, PilotLaunchService

BUILD_FILES = ("CSA-TrustedCollector.exe", "Start-CSATrustedCollector.ps1", "Program.cs", "BoundPilot.cs", "Start-CSASimple.ps1")


class DeliveryDenied(DistributionDenied):
    def __init__(self,reason,status=403,retry_after=0):
        super().__init__();self.args=(reason,);self.reason_code=reason;self.http_status=status;self.retry_after=retry_after


def checked_build():
    root = bootstrap_directory()
    try:
        seal = json.loads((root / "delivery-build.json").read_text(encoding="utf-8-sig"))
        if set(seal) != set(BUILD_FILES) or any(sha256_file(root/name) != seal[name] for name in BUILD_FILES):
            raise ValueError()
        if not (Path(os.environ["SystemRoot"])/"Microsoft.NET/Framework64/v4.0.30319/csc.exe").is_file():
            raise ValueError()
    except (OSError, ValueError, KeyError):
        raise ValueError("CSA-START-BUILD: Collector delivery files are missing or changed. Reinstall the verified CSA Lab build.") from None
    return root, seal


def prepare_start(service, state, session):
    """Only invoked by the local assessor's Start Collector action."""
    _, seal = checked_build()
    authorization = {"authorizationId": secrets.token_hex(24), "approvedAt": int(time.time()),
                     "sessionId": session.session_id, "sourceSubnet": state.source_subnet,
                     "expiresAt": session.expires_at,"profileDigest":session.collection_profile_digest,
                     "invitationBudget":session.allowed_submission_count,"build": seal}
    # Persist the actual action, not fabricated customer contract references.
    service._audit(state.assessment_id).append("collector_start_authorized", {
        "sessionId": session.session_id, "authorizationId": authorization["authorizationId"],
        "binding": "DIRECT_LAN_SOURCE_ONE_USE", "assurance": "ASSESSOR_VERIFIED_PILOT", "publicRelease": "HOLD"})
    return authorization


class SimpleDelivery:
    def __init__(self, service, assessment_id, authorization):
        self.service, self.assessment_id, self.authorization = service, assessment_id, authorization
        self.last_error = None
        self.diagnostics=[]

    def record_diagnostic(self,stage,code,correlation,*,client=False):
        item={"stage":stage,"code":code,"correlationId":correlation,"eventClass":"CLIENT_REPORTED" if client else "SERVER_VERIFIED","recordedAt":int(time.time())}
        with self.service._lock:
            self.diagnostics=(self.diagnostics+[item])[-20:]
            self.service.storage.write_json(self.assessment_id,("delivery",self.authorization["sessionId"]+".diagnostics.json"),{"entries":self.diagnostics})
        self.service._audit(self.assessment_id).append("collector_client_diagnostic" if client else "collector_delivery_diagnostic",item)

    def client_diagnostic(self,identifier,source,value):
        if (not isinstance(value,dict) or set(value)!={"stage","code","correlationId"}
                or value.get("stage") not in {"CONNECTION_TLS","AUTHORIZATION","PACKAGE_INTEGRITY","APPLICATION_CONTROL","COLLECTOR_EXECUTION","EVIDENCE_SUBMISSION"}
                or not isinstance(value.get("code"),str) or not re.fullmatch(r"CSA-[A-Z0-9_-]{1,100}",value["code"])
                or not isinstance(value.get("correlationId"),str) or not re.fullmatch(r"[a-f0-9]{0,32}",value["correlationId"])):
            raise ValueError("CSA-CLIENT-DIAGNOSTIC-SCHEMA")
        _,session,_=self._current(source)
        grant=TrustedGrantStore(self.service.storage).record(session,identifier)
        if source not in json.loads(grant["approvedSources"] or "[]"):raise DeliveryDenied("SOURCE_NOT_AUTHORIZED")
        self.record_diagnostic(value['stage'],value['code'],value['correlationId'],client=True)

    def _current(self, source):
        state = self.service.load_state(self.assessment_id)
        session = self.service.sessions.load_session(self.assessment_id, state.session_id)
        if (session.session_id != self.authorization["sessionId"] or session.status.value != "OPEN"
                or _parse_utc(session.expires_at).timestamp() <= time.time() or not source_is_allowed(session, source)
                or _parse_utc(self.authorization["expiresAt"]).timestamp() <= time.time()
                or ipaddress.ip_address(source) not in ipaddress.ip_network(self.authorization["sourceSubnet"],strict=False)
                or session.collection_profile_digest != self.authorization["profileDigest"]
                or session.allowed_submission_count != self.authorization["invitationBudget"]
                or state.source_subnet != self.authorization["sourceSubnet"]):
            raise DeliveryDenied("SESSION_OR_SOURCE_NOT_AUTHORIZED")
        root, seal = checked_build()
        if seal != self.authorization["build"]:
            raise ValueError("CSA-START-BUILD-CHANGED")
        return state, session, root

    @staticmethod
    def _schema(db):
        db.execute("""CREATE TABLE IF NOT EXISTS simple_launches (
            envelopeId TEXT PRIMARY KEY, sourceDigest TEXT NOT NULL, executableDigest TEXT NOT NULL,
            authorizationId TEXT, downloads INTEGER NOT NULL DEFAULT 0)""")
        if "authorizationId" not in {row[1] for row in db.execute("PRAGMA table_info(simple_launches)")}:
            db.execute("ALTER TABLE simple_launches ADD COLUMN authorizationId TEXT")
        columns={row[1] for row in db.execute("PRAGMA table_info(simple_launches)")}
        for name,kind in (("windowStarted","REAL NOT NULL DEFAULT 0"),("windowDownloads","INTEGER NOT NULL DEFAULT 0")):
            if name not in columns: db.execute("ALTER TABLE simple_launches ADD COLUMN "+name+" "+kind)

    def view(self, source):
        try:
            result = self._view(source)
            self.last_error = None
            return result
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            code = str(error).split(":",1)[0]
            self.last_error = code if code.startswith("CSA-") and len(code)<80 else "CSA-START-PACKAGE"
            self.service._audit(self.assessment_id).append("collector_preparation_failed", {"code":self.last_error})
            raise ValueError(self.last_error) from None

    def readiness(self):
        try:
            if checked_build()[1]!=self.authorization["build"]:
                self.last_error="CSA-START-BUILD-CHANGED"
        except ValueError:
            self.last_error="CSA-START-BUILD"
        return {"state":"PREPARATION_FAILED" if self.last_error else "READY","diagnostics":self.diagnostics[-5:],
                "diagnosticCode":self.last_error, "methods":["EXE","QUICK_RUN_PROCESS_BYPASS"],
                "assurance":"ASSESSOR_VERIFIED_PILOT", "binding":"DIRECT_LAN_SOURCE_ONE_USE",
                "instruction":"Share this assessment's Join URL on the approved direct LAN. Both methods need no client preparation."
                    if not self.last_error else "Check Collector files and the approved direct LAN/source scope. Reinstall the verified build if files changed."}

    def _view(self, source):
        with self.service._lock:
            state, session, root = self._current(source)
            store = TrustedGrantStore(self.service.storage)
            source_digest = sha256_bytes(source.encode("ascii"))
            with store._transaction(session, create=True) as db:
                self._schema(db)
                revoked=db.execute("""SELECT 1 FROM grants g JOIN simple_launches s USING(envelopeId)
                    WHERE s.sourceDigest=? AND s.authorizationId=? AND g.reasonCode='PILOT_REVOKED'""",
                    (source_digest,self.authorization["authorizationId"])).fetchone()
                if revoked:
                    raise ValueError("CSA-START-REVOKED: The assessor revoked this source. Pause and explicitly start a new authorization before another run.")
                row = db.execute("""SELECT g.*,s.executableDigest,s.downloads FROM grants g
                    JOIN simple_launches s USING(envelopeId) WHERE s.sourceDigest=? AND g.used=0
                    AND g.operationState='READY' AND g.expiresAt>? ORDER BY g.rowid DESC LIMIT 1""",
                    (source_digest, time.time())).fetchone()
                count = db.execute("SELECT COUNT(*) FROM simple_launches").fetchone()[0]
            if row is None:
                if count >= session.allowed_submission_count:
                    raise ValueError("CSA-START-LIMIT: The assessment invitation budget is exhausted. Create a new assessment.")
                auth = "START-" + self.authorization["authorizationId"]
                result = issue_assessor_pilot(self.service, self.assessment_id, {
                    "recipientId": "ENDPOINT-" + secrets.token_hex(16), "endpointBinding": "source-ip:"+source,
                    "sourceAddress": source, "approvedBy": "Local assessor / Start Collector",
                    "customerApprovalReference": "Assessment scope confirmed by local assessor",
                    "assessorApprovalReference": auth, "independentChannelReference": "Verified local CSA Lab installation / "+auth,
                    "riskAccepted": True}, _source_bound=True)
                identifier = result["handoffId"]
                bundle = self.service.storage.path(self.assessment_id, "pilot-handoffs", identifier)
                try:
                    executable = self._seal(bundle, result, root)
                    expected = sha256_file(executable)
                    # Native verification covers the exact captured bundle; compile
                    # pins are supplied from the local approval, never the customer.
                    with store._transaction(session) as db:
                        PilotLaunchService(self.service.storage,self.assessment_id,session.session_id)._schema(db)
                        db.execute("INSERT INTO simple_launches(envelopeId,sourceDigest,executableDigest,authorizationId) VALUES (?,?,?,?)",
                                   (identifier, source_digest, expected,self.authorization["authorizationId"]))
                        db.execute("""INSERT INTO pilot_launches(envelopeId,verifiedAt,verificationReferenceDigest,
                            archiveDigest,authorizedAt,authorizationReferenceDigest,exeDigest) VALUES (?,?,?,?,?,?,?)""",
                            (identifier,int(time.time()),sha256_bytes(auth.encode()),expected,
                             self.authorization["approvedAt"],sha256_bytes(auth.encode()),result["exeSha256"]))
                        row = db.execute("SELECT g.*,s.executableDigest,s.downloads FROM grants g JOIN simple_launches s USING(envelopeId) WHERE envelopeId=?", (identifier,)).fetchone()
                    self.service._audit(self.assessment_id).append("collector_single_file_ready", {
                        "envelopeId": identifier, "executableDigest": expected, "authorizationId": self.authorization["authorizationId"]})
                except Exception:
                    with store._transaction(session) as db:
                        db.execute("UPDATE grants SET operationState='FAILED',reasonCode='CSA-START-PACKAGE' WHERE envelopeId=?", (identifier,))
                    raise
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            certificate=x509.load_pem_x509_certificate(Path(session.tls_certificate_path).read_bytes())
            public_key=certificate.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
            return {"singleFile": True, "handoffId": row["envelopeId"], "exeSha256": row["executableDigest"],
                    "starterSha256":self.authorization["build"]["Start-CSASimple.ps1"],
                    "tlsPublicKeyPin":"sha256//"+base64.b64encode(hashlib.sha256(public_key).digest()).decode("ascii"),
                    "origin": "https://"+state.listener_address+":"+str(state.listener_port),
                    "tlsFingerprint": session.tls_fingerprint, "expiresAt": row["expiresAt"]}

    def starter(self,identifier,source):
        _,session,root=self._current(source)
        with TrustedGrantStore(self.service.storage)._transaction(session) as db:
            grant=db.execute('SELECT * FROM grants WHERE envelopeId=?',(identifier,)).fetchone()
        if grant is None: raise DeliveryDenied("INVITATION_UNKNOWN")
        if grant["used"]: raise DeliveryDenied("INVITATION_ALREADY_USED")
        if grant["operationState"]!="READY": raise DeliveryDenied("INVITATION_REVOKED_OR_FAILED")
        if grant["expiresAt"]<=time.time(): raise DeliveryDenied("INVITATION_EXPIRED")
        if source not in json.loads(grant["approvedSources"] or "[]"):
            raise DeliveryDenied("SOURCE_NOT_AUTHORIZED")
        data=(root/"Start-CSASimple.ps1").read_bytes()
        if sha256_bytes(data)!=self.authorization["build"]["Start-CSASimple.ps1"]:
            raise ValueError("CSA-START-BOOTSTRAP-CHANGED")
        return data

    def _seal(self, bundle, result, root):
        snapshots = {name: (bundle/name).read_bytes() for name in FILES}
        with tempfile.TemporaryDirectory(dir=bundle.parent) as directory:
            work = Path(directory); restrict_directory(work)
            for name, content in snapshots.items():
                (work/name).write_bytes(content)
            AssessorAuthority(root/"CSA-TrustedCollector.exe", result["approvalSha256"]).verify(work)
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
                for name, content in snapshots.items():
                    archive.writestr(name, content)
            payload = stream.getvalue()
            if len(payload) > 64*1024*1024:
                raise ValueError("CSA-START-SIZE")
            (work/"payload.bin").write_bytes(payload)
            for name in ("Program.cs","BoundPilot.cs"):
                content=(root/name).read_bytes()
                if sha256_bytes(content)!=self.authorization["build"][name]:
                    raise ValueError("CSA-START-BUILD-CHANGED")
                (work/name).write_bytes(content)
            pins = {"Payload": hashlib.sha256(payload).hexdigest(), "Executable": result["exeSha256"][7:],
                    "Approval": result["approvalSha256"][7:]}
            (work/"Pins.cs").write_text('[assembly:System.Reflection.AssemblyTitle("CSA Collector")]'+
                '[assembly:System.Reflection.AssemblyFileVersion("'+COLLECTOR_VERSION+'")]' +
                '[assembly:System.Reflection.AssemblyVersion("'+COLLECTOR_VERSION+'")]' +
                "namespace CSA.Collector { internal static class BoundPins {"+
                "".join('internal const string '+key+'="'+value+'";' for key,value in pins.items())+"}}", "ascii")
            compiler = Path(os.environ["SystemRoot"])/"Microsoft.NET/Framework64/v4.0.30319/csc.exe"
            run = subprocess.run([str(compiler), "/nologo", "/optimize+", "/target:exe", "/main:CSA.Collector.BoundEntry",
                "/out:"+str(work/"CSA-Collector.exe"), "/resource:"+str(work/"payload.bin")+",CSA.Pilot",
                "/reference:System.IO.Compression.dll", "/reference:System.IO.Compression.FileSystem.dll",
                "/reference:System.Web.Extensions.dll", str(work/"Program.cs"), str(work/"BoundPilot.cs"), str(work/"Pins.cs")],
                capture_output=True, timeout=60, creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
            if run.returncode:
                raise ValueError("CSA-START-COMPILE: Windows could not prepare the Collector. Review application control; do not disable it.")
            (work/"CSA-Collector.exe").replace(bundle/"CSA-Collector.exe")
        return bundle/"CSA-Collector.exe"

    def download(self, identifier, source):
        with self.service._lock:
            _, session, _ = self._current(source)
            store = TrustedGrantStore(self.service.storage)
            with store._transaction(session) as db:
                self._schema(db)
                row = db.execute("SELECT g.*,s.executableDigest,s.sourceDigest,s.downloads,s.windowStarted,s.windowDownloads FROM grants g JOIN simple_launches s USING(envelopeId) WHERE envelopeId=?", (identifier,)).fetchone()
                if row is None: raise DeliveryDenied("INVITATION_UNKNOWN")
                if row["used"]: raise DeliveryDenied("INVITATION_ALREADY_USED")
                if row["operationState"]!="READY": raise DeliveryDenied("INVITATION_REVOKED_OR_FAILED")
                if row["expiresAt"]<=time.time(): raise DeliveryDenied("INVITATION_EXPIRED")
                if row["sourceDigest"]!=sha256_bytes(source.encode("ascii")): raise DeliveryDenied("SOURCE_NOT_AUTHORIZED")
                now=time.time(); window=row["windowStarted"]; count=row["windowDownloads"]
                if now-window>=60: window=now;count=0
                if count>=5: raise DeliveryDenied("DOWNLOAD_RATE_LIMIT",429,max(1,int(61-(now-window))))
                path = Path(row["bundlePath"])/"CSA-Collector.exe"
                if path.is_symlink():
                    raise DistributionDenied()
                with path.open("rb") as stream:
                    data = stream.read(64*1024*1024+1)
                if len(data)>64*1024*1024 or sha256_bytes(data) != row["executableDigest"]:
                    raise DeliveryDenied("PACKAGE_INTEGRITY_FAILED")
                db.execute("UPDATE simple_launches SET downloads=downloads+1,windowStarted=?,windowDownloads=? WHERE envelopeId=?",(window,count+1,identifier))
            self.service._audit(self.assessment_id).append("collector_single_file_delivered", {"envelopeId": identifier})
            return data
