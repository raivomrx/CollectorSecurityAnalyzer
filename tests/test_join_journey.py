"""Customer Join -> authorized private delivery -> native collection -> receipt/report."""
import base64
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import zipfile
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from unittest import mock

import requests

from csa_console.canonical import sha256_bytes
from csa_console.customer_launch import commands
from csa_console.integrity import verify_recorded_evidence
from csa_lab.pilot_launch import PilotLaunchService
from csa_lab.pilot_readiness import inspect_pilot
from tests.test_assessor_pilot import AssessorPilotCase


class JoinJourneyTests(AssessorPilotCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.production_native=cls.native
        if __import__("ctypes").windll.shell32.IsUserAnAdmin():
            # Hosted CI is elevated. Compile a synthetic token fixture only;
            # product gate remains unchanged and is tested separately below.
            root=cls.crypto_type.root
            source=(Path(__file__).resolve().parents[1]/"collector/trusted/AssessorPilot.cs").read_text()
            marker="try { RejectElevatedProcess(); }"
            assert source.count(marker)==1
            alternate=root/"SyntheticAssessorPilot.cs"
            alternate.write_text(source.replace(marker,"try { /* Synthetic medium-token fixture only. */ }"))
            native=root/"synthetic-native";native.mkdir()
            repo=Path(__file__).resolve().parents[1]
            compiler=Path(os.environ["SystemRoot"])/"Microsoft.NET/Framework64/v4.0.30319/csc.exe"
            result=subprocess.run([str(compiler),"/nologo","/target:exe","/main:CSA.Collector.TrustedEntry",
                "/out:"+str(native/"CSA-TrustedCollector.exe"),"/reference:System.IO.Compression.dll",
                "/reference:System.IO.Compression.FileSystem.dll","/reference:System.Web.Extensions.dll","/reference:System.Security.dll",
                str(repo/"collector/bootstrapper/Program.cs"),str(repo/"collector/trusted/TrustProtocol.cs"),
                str(repo/"collector/trusted/TrustedEntry.cs"),str(repo/"collector/trusted/TrustedNetwork.cs"),
                str(repo/"collector/trusted/TrustInspection.cs"),str(alternate)],capture_output=True,text=True,timeout=30)
            if result.returncode:
                raise AssertionError(result.stdout+result.stderr)
            shutil.copy2(cls.native/"Start-CSATrustedCollector.ps1",native)
            cls.native=native

    def setUp(self):
        super().setUp()
        patch=mock.patch("csa_lab.pilot_launch.bootstrap_directory",return_value=self.native)
        patch.start();self.addCleanup(patch.stop)
        helper=Path(__file__).resolve().parents[1]/"csa_lab/powershell/Receive-CSAPilot.ps1"
        # Only emulate a human's secure terminal input. The actual generated
        # command still downloads/hash-checks this fixture, which keeps every
        # package, endpoint, TLS and native-engine check unchanged.
        input_host=("function Read-Host {param($Prompt,[switch]$AsSecureString);"
            "$s=New-Object Security.SecureString;foreach($c in $env:CSA_SYNTHETIC_DELIVERY_CODE.ToCharArray()){$s.AppendChar($c)};return $s}\n")
        self.helper=self.root/"Receive-Fixture.ps1"
        self.helper.write_text(helper.read_text().replace("$ErrorActionPreference='Stop'",input_host+"$ErrorActionPreference='Stop'",1))
        patch=mock.patch("csa_lab.pilot_launch.BOOTSTRAP",self.helper)
        patch.start();self.addCleanup(patch.stop)
        self.launches=PilotLaunchService(self.service.storage,self.state.assessment_id,self.session.session_id)

    def authorize(self):
        result,bundle=self.issue()
        self.assertEqual(self.launches.status(result["handoffId"])["state"],"PACKAGE_PREPARED")
        preflight=inspect_pilot(self.service,self.state.assessment_id,"ENDPOINT-PILOT-FIXTURE-001")
        self.assertFalse(preflight["customerPilotPermitted"])
        stage=self.launches.verify_handoff(result["handoffId"],"INDEPENDENT-FIXTURE",result["approvalSha256"],result["exeSha256"])
        self.assertEqual(stage["state"],"INDEPENDENT_HANDOFF_VERIFIED")
        stage=self.launches.authorize(result["handoffId"],"EXECUTION-FIXTURE")
        self.assertEqual(stage["state"],"AUTHORIZED_FOR_EXECUTION")
        return result,bundle,stage["deliveryCode"]

    def login(self,code):
        client=requests.Session();self.addCleanup(client.close)
        response=client.post(self.url+"pilot-activate",data={"code":code},verify=self.session.tls_certificate_path,
                             allow_redirects=False,timeout=15)
        self.assertEqual(response.status_code,303,response.text)
        self.assertIn("HttpOnly",response.headers["Set-Cookie"])
        return client

    def test_join_exe_and_quick_submit_equivalent_evidence_generate_report_and_retire(self):
        for quick in (False,True):
            result,bundle,code=self.authorize()
            client=self.login(code)
            page=client.get(self.url,verify=self.session.tls_certificate_path,timeout=15)
            self.assertEqual(page.status_code,200)
            self.assertIn("Laadi alla EXE",page.text)
            self.assertIn("Kopeeri Quick Run",page.text)
            for text in ("TRUST_ENROLLMENT_PENDING","Release HOLD","TRUST_NOT_ESTABLISHED","SETUP_REQUIRED","Publisher enrollment",code):
                self.assertNotIn(text,page.text)
            env={**os.environ};env.pop("PSModulePath",None)
            if not quick:
                response=client.get(self.url+"pilot-download",verify=self.session.tls_certificate_path,timeout=15)
                self.assertEqual(response.status_code,200,response.text[:100])
                target=self.root/"customer-exe";target.mkdir()
                with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
                    archive.extractall(target)
                run=subprocess.run(["cmd.exe","/d","/c",str(target/"Start-CSACollector.cmd")],
                    capture_output=True,text=True,timeout=90,env=env)
            else:
                view=self.launches.customer_view(client.cookies.get("__Host-CSA-Pilot"),"127.0.0.1")
                command=commands(view)["quick"]
                self.assertLess(len(command),8191)  # CMD command-line budget.
                decoded=base64.b64decode(command.split(" -EncodedCommand ")[1]).decode("utf-16-le")
                self.assertNotIn(code,decoded)
                env["CSA_SYNTHETIC_DELIVERY_CODE"]=code
                run=subprocess.run(["powershell.exe","-NoProfile","-Command",command],
                    capture_output=True,text=True,timeout=120,env=env)
            self.assertEqual(run.returncode,0,run.stdout+run.stderr)
            self.assertIn("Submission accepted",run.stdout)
            self.assertNotIn(code,run.stdout+run.stderr)
            self.assertTrue(self.launches.status(result["handoffId"])["evidenceReceived"])
        rows=self.service.submissions.list_submissions(self.state.assessment_id)
        self.assertEqual(len(rows),2)
        documents=[self.service.storage.read_json(self.state.assessment_id,"submissions","accepted",row["submissionId"]+".evidence.json") for row in rows]
        for key in ("software","security","services","collectorVersion"):
            self.assertEqual(documents[0][key],documents[1][key])
        receipts=[self.service.storage.read_json(self.state.assessment_id,"submissions","accepted",row["submissionId"]+".trust.json") for row in rows]
        self.assertEqual({row["requestedExecutionMode"] for row in receipts},{"EXE","QUICK_RUN_PROCESS_BYPASS"})
        self.service.stop_collection(self.state.assessment_id)
        # No live vulnerability feeds in this controlled input fixture. Use the
        # existing explicit acknowledgement and preserve incomplete CVE labels.
        report=self.service.generate_unified_report(self.state.assessment_id,allow_without_cve=True)
        self.assertTrue(report.is_file())
        states=self.launches.list_status()
        self.assertTrue(all(row["evidenceReceived"] and not row["acceptanceCompleted"] for row in states))
        for row in states:
            bundle=self.service.storage.path(self.state.assessment_id,"pilot-handoffs",row["handoffId"])
            self.assertFalse((bundle/"collector.zip").exists())
            self.assertFalse((bundle/"customer-package.zip").exists())
        proof=verify_recorded_evidence(self.service.storage,self.state.assessment_id,
            [{"submissionId":row["submissionId"],"sessionId":self.session.session_id} for row in rows],rows)
        self.assertEqual(proof["signedReceiptIntegrity"],"VERIFIED")
        self.assertEqual(proof["publisherAuthenticity"],"ASSESSOR_VERIFIED_PILOT")

    def test_unauthorized_wrong_source_expired_modified_and_revoked_delivery(self):
        result,bundle=self.issue()
        with self.assertRaises(ValueError):
            self.launches.authorize(result["handoffId"],"fixture")
        with self.assertRaises(ValueError):
            self.launches.verify_handoff(result["handoffId"],"fixture","sha256:"+"0"*64,result["exeSha256"])
        page=requests.get(self.url,verify=self.session.tls_certificate_path,timeout=15)
        self.assertNotIn("data-copy-command",page.text)
        self.assertNotIn('href="pilot-download"',page.text)
        result,bundle,code=self.authorize()
        with self.assertRaises(ValueError):
            self.launches.login(code,"127.0.0.2")
        ticket=self.launches.ticket(result["handoffId"],"127.0.0.1",code=code)["ticket"]
        with self.assertRaises(ValueError):
            self.launches.ticket(result["handoffId"],"127.0.0.1",code=code)
        path=bundle/"customer-package.zip";path.write_bytes(path.read_bytes()+b"changed")
        with self.assertRaisesRegex(ValueError,"PILOT_PACKAGE_CHANGED"):
            self.launches.package(result["handoffId"],"127.0.0.1",ticket)
        self.launches.retire(result["handoffId"],revoke=True)
        self.assertFalse(path.exists())
        with self.assertRaises(ValueError):
            self.launches.package(result["handoffId"],"127.0.0.1",ticket)
        with self.assertRaises(ValueError):
            self.launches.accept(result["handoffId"],"not-real")

    def test_customer_browser_has_short_authorized_methods_and_no_internal_states(self):
        result,bundle,code=self.authorize()
        if os.environ.get("CSA_BROWSER_SMOKE")!="1":
            return  # Dedicated Windows Collector lane runs the actual browser.
        candidates=[Path(os.environ[folder])/relative for folder in ("ProgramFiles","ProgramFiles(x86)") if folder in os.environ
                    for relative in ("Microsoft/Edge/Application/msedge.exe","Google/Chrome/Application/chrome.exe")]
        browser=next(path for path in candidates if path.is_file())
        certificate=x509.load_pem_x509_certificate(Path(self.session.tls_certificate_path).read_bytes())
        pin=base64.b64encode(hashlib.sha256(certificate.public_key().public_bytes(
            serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).digest()).decode()
        screenshot=Path(os.environ.get("CSA_PILOT_EVIDENCE_DIR",self.root))/"customer-launch.png"
        screenshot.parent.mkdir(parents=True,exist_ok=True)
        data=dict(url=self.url,browserPath=str(browser),profile=str(self.root/"customer-browser"),
                  mode="customer",pin=pin,deliveryCode=code,screenshot=str(screenshot))
        run=subprocess.run(["node",str(Path(__file__).resolve().parents[1]/"tests/fixtures/join_browser_smoke.mjs")],
                           input=json.dumps(data),capture_output=True,text=True,timeout=50)
        self.assertEqual(run.returncode,0,run.stderr)
        self.assertIn("Customer authorized EXE",run.stdout)

    def test_expired_private_material_is_retired_with_retry_without_resetting_grants(self):
        result,bundle,code=self.authorize()
        with self.launches._db() as db:
            db.execute("UPDATE grants SET expiresAt=? WHERE envelopeId=?",(time.time()-1,result["handoffId"]))
        original=Path.unlink
        def locked(path,*args,**kwargs):
            if path==bundle/"collector.zip":
                raise PermissionError("SYNTHETIC-PRIVATE-DETAIL")
            return original(path,*args,**kwargs)
        with mock.patch.object(Path,"unlink",locked):
            state=self.launches.list_status()[0]
            self.assertTrue(state["cleanupPending"])
        self.assertEqual(self.launches.list_status()[0]["state"],"EXPIRED")
        self.assertFalse((bundle/"collector.zip").exists())
        self.assertFalse((bundle/"customer-package.zip").exists())
        with self.assertRaises(ValueError):
            self.launches.login(code,"127.0.0.1")
        audit=self.service.storage.path(self.state.assessment_id,"audit","audit.jsonl").read_text("utf-8")
        self.assertNotIn("SYNTHETIC-PRIVATE-DETAIL",audit)

    def test_bootstrap_wrong_tls_or_modified_verifier_stops_before_private_download(self):
        result,bundle,code=self.authorize()
        client=self.login(code)
        view=self.launches.customer_view(client.cookies.get("__Host-CSA-Pilot"),"127.0.0.1")
        original=self.helper.read_bytes()
        for changed in ("tls","helper"):
            current=dict(view)
            if changed=="tls":
                current["tlsFingerprint"]="sha256:"+"0"*64
            else:
                self.helper.write_bytes(original+b"\n# MODIFIED")
            command=commands(current)["quick"]
            env={**os.environ,"CSA_SYNTHETIC_DELIVERY_CODE":code};env.pop("PSModulePath",None)
            run=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-Command",command],
                               capture_output=True,text=True,timeout=40,env=env)
            self.assertNotEqual(run.returncode,0)
            with self.launches._db() as db:
                used=db.execute("SELECT codeUsed FROM pilot_launches WHERE envelopeId=?",(result["handoffId"],)).fetchone()[0]
            self.assertEqual(used,0)
            self.assertEqual(self.service.submissions.list_submissions(self.state.assessment_id),[])
        self.helper.write_bytes(original)

    def test_interrupted_private_transfer_retries_and_full_digest_mismatch_does_not(self):
        server=self.service._servers[self.state.assessment_id]
        handler=server._server.RequestHandlerClass
        original=handler._bytes
        for behavior in ("truncated","modified"):
            result,bundle,code=self.authorize()
            client=self.login(code)
            view=self.launches.customer_view(client.cookies.get("__Host-CSA-Pilot"),"127.0.0.1")
            calls=[]
            def transfer(instance,status,body,content_type,*args,**kwargs):
                if instance.diagnostic_stage=="PILOT_PRIVATE_DELIVERY" and content_type=="application/zip" and status==200:
                    calls.append(status)
                    if behavior=="truncated" and len(calls)==1:
                        instance.send_response(status);instance.send_header("Content-Length",str(len(body)))
                        instance.send_header("Connection","close");instance.end_headers()
                        instance.wfile.write(body[:len(body)//2]);instance.close_connection=True
                        return
                    if behavior=="modified":
                        body=bytes([body[0]^1])+body[1:]
                return original(instance,status,body,content_type,*args,**kwargs)
            env={**os.environ,"CSA_SYNTHETIC_DELIVERY_CODE":code};env.pop("PSModulePath",None)
            with mock.patch.object(handler,"_bytes",transfer):
                run=subprocess.run(["powershell.exe","-NoProfile","-Command",commands(view)["quick"]],
                                   capture_output=True,text=True,timeout=120,env=env)
            if behavior=="truncated":
                self.assertEqual(run.returncode,0,run.stdout+run.stderr)
                self.assertEqual(len(calls),2)
            else:
                self.assertNotEqual(run.returncode,0)
                self.assertEqual(len(calls),1)
