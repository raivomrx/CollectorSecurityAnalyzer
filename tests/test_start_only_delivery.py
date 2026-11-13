"""Regress the actual omission: new assessment -> Start -> Join, no handoff API.

Acquisition is synthetic; signing, packaged engine, native execution, submission,
privacy, receipt and report are real. Hosted elevated CI must honor the real gate.
"""
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
from unittest import mock

import requests

from csa_console.customer_launch import commands
from csa_console.integrity import verify_recorded_evidence
from csa_console.enums import SessionStatus
from tests.test_assessor_pilot import AssessorPilotCase
from tests.test_collector_launcher import LauncherCase, PRIVACY_MARKERS


class StartOnlyDeliveryTests(AssessorPilotCase):
    def setUp(self):
        # Deliberately bypass the old manual-handoff fixture's setup, not any
        # product security check. No issue/verify/authorize/login API is called.
        LauncherCase.setUp(self)
        for module in ("csa_lab.assessor_pilot", "csa_lab.simple_delivery"):
            patch=mock.patch(module+".bootstrap_directory", return_value=self.native)
            patch.start(); self.addCleanup(patch.stop)
        self.create(synthetic=True,development=False,expected_endpoints=3,automatic=True)
        self.delivery=self.service._servers[self.state.assessment_id].simple_delivery

    def join(self):
        response=requests.get(self.url,verify=self.session.tls_certificate_path,timeout=60)
        self.assertEqual(response.status_code,200,response.text[:120])
        self.assertIn("Copy Quick Run",response.text)
        self.assertIn("Download Collector (.exe)",response.text)
        self.assertNotIn("pöördu hindaja",response.text)
        self.assertNotIn(".zip",response.text)
        self.assertNotIn("input",response.text)
        url=re.search(r'href="(https://[^\"]+/collector.exe)"',response.text).group(1)
        return response,url

    def run_file(self, url, name):
        response=requests.get(url,verify=self.session.tls_certificate_path,timeout=30)
        self.assertEqual(response.status_code,200,response.text[:100] if not response.content.startswith(b"MZ") else "")
        self.assertIn('filename="CSA-Collector.exe"',response.headers["Content-Disposition"])
        self.assertTrue(response.content.startswith(b"MZ"))
        path=self.root/name;path.write_bytes(response.content)
        return path

    def test_start_alone_exposes_real_single_exe_and_one_paste_both_shells(self):
        outputs=[]
        for shell in ("exe","powershell","cmd"):
            page,url=self.join()
            view=self.delivery.view("127.0.0.1")
            env=dict(os.environ);env.pop("PSModulePath",None)
            if shell=="exe":
                executable=self.run_file(url,"Collector.exe")
                # No bundle, flags, CMD starter, installation or manual extraction.
                args=[str(executable)]
            else:
                command=commands(view)["quick"]
                self.assertLess(len(command),8191)
                script=base64.b64decode(command.split(" -EncodedCommand ")[1]).decode("utf-16-le")
                for secret in ("enrollmentToken","Read-Host","IEX","DownloadString","Set-ExecutionPolicy"):
                    self.assertNotIn(secret,script)
                args=(["cmd.exe","/d","/s","/c",command] if shell=="cmd" else
                      ["powershell.exe","-NoProfile","-Command",command])
            run=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=150,env=env)
            if ctypes.windll.shell32.IsUserAnAdmin():
                self.assertNotEqual(run.returncode,0)
                self.assertIn("STANDARD-USER-REQUIRED",run.stderr)
                self.assertEqual(self.service.submissions.list_submissions(self.state.assessment_id),[])
                return  # Explicit hosted-token limitation, no synthetic acceptance.
            self.assertEqual(run.returncode,0,run.stdout+run.stderr)
            self.assertIn("Submission accepted",run.stdout)
            outputs.append(run.stdout)
            # Replay of the exact single-use download/authority is rejected.
            self.assertEqual(requests.get(url,verify=self.session.tls_certificate_path,timeout=10).status_code,403)
        rows=self.service.submissions.list_submissions(self.state.assessment_id)
        self.assertEqual(len(rows),3)
        evidence=[self.service.storage.read_json(self.state.assessment_id,"submissions","accepted",r["submissionId"]+".evidence.json") for r in rows]
        for key in ("software","security","services","collectorVersion"):
            self.assertTrue(all(document[key]==evidence[0][key] for document in evidence))
        for document in evidence:
            self.assertEqual(document["metadata"]["privacyMode"],"PROFILE_ENFORCED")
            for marker in PRIVACY_MARKERS:
                self.assertNotIn(marker,json.dumps(document))
        proof=verify_recorded_evidence(self.service.storage,self.state.assessment_id,
            [{"submissionId":r["submissionId"],"sessionId":self.state.session_id} for r in rows],rows)
        self.assertEqual(proof["signedReceiptIntegrity"],"VERIFIED")
        self.assertEqual(proof["publisherAuthenticity"],"ASSESSOR_VERIFIED_PILOT")
        self.service.stop_collection(self.state.assessment_id)
        report=self.service.generate_unified_report(self.state.assessment_id,allow_without_cve=True)
        self.assertTrue(report.is_file())

    def test_unauthorized_source_expiry_changed_file_and_budget_fail_closed(self):
        _,url=self.join()
        view=self.delivery.view("127.0.0.1")
        identifier=view["handoffId"]
        with self.assertRaises(ValueError):self.delivery.download(identifier,"127.0.0.2")
        with self.assertRaises(ValueError):self.delivery.view("192.0.2.4")
        bundle=self.service.storage.path(self.state.assessment_id,"pilot-handoffs",identifier)
        path=bundle/"CSA-Collector.exe";original=path.read_bytes();path.write_bytes(original+b"TAMPER")
        with self.assertRaisesRegex(ValueError,"PACKAGE-CHANGED"):self.delivery.download(identifier,"127.0.0.1")
        path.write_bytes(original)
        store=self.delivery.service._servers[self.state.assessment_id].trusted_network.grants
        with store._transaction(self.session) as db:
            db.execute("UPDATE grants SET expiresAt=? WHERE envelopeId=?",(int(time.time())-1,identifier))
        with self.assertRaises(ValueError):self.delivery.download(identifier,"127.0.0.1")
        self.service.pause_collection(self.state.assessment_id)
        with self.assertRaises(ValueError):self.delivery.view("127.0.0.1")
        self.assertEqual(self.service.submissions.list_submissions(self.state.assessment_id),[])

    def test_missing_or_replaced_installed_collector_stops_start_with_diagnostic(self):
        self.service.pause_collection(self.state.assessment_id)
        with mock.patch("csa_lab.simple_delivery.bootstrap_directory",return_value=self.root/"missing"):
            with self.assertRaisesRegex(ValueError,"CSA-START-BUILD"):
                self.service.start_collection(self.state.assessment_id)
        self.assertNotIn(self.state.assessment_id,self.service._servers)

    def test_session_json_cannot_expand_the_assessors_start_scope(self):
        current=self.service.sessions.load_session(self.state.assessment_id,self.state.session_id)
        current.allowed_source_networks=["0.0.0.0/0"]
        self.service.sessions._write_session(current)
        with self.assertRaises(ValueError):
            self.delivery.view("192.0.2.4")
        self.assertEqual(self.service.submissions.list_submissions(self.state.assessment_id),[])

    def test_old_manual_cookie_cannot_replace_start_only_exe_with_zip(self):
        # Adversarial compatibility case only; the main journey above still
        # invokes no manual issue/verify/authorize/activation operation.
        from csa_lab.pilot_launch import PilotLaunchService
        result,_=self.issue()
        launches=PilotLaunchService(self.service.storage,self.state.assessment_id,self.state.session_id)
        launches.verify_handoff(result["handoffId"],"SYNTHETIC-LEGACY",result["approvalSha256"],result["exeSha256"])
        code=launches.authorize(result["handoffId"],"SYNTHETIC-LEGACY")["deliveryCode"]
        cookie=launches.login(code,"127.0.0.1")
        response=requests.get(self.url,cookies={"__Host-CSA-Pilot":cookie},
            verify=self.session.tls_certificate_path,timeout=60)
        self.assertEqual(response.status_code,200)
        self.assertIn("Download Collector (.exe)",response.text)
        self.assertIn("Copy Quick Run",response.text)
        self.assertNotIn(".zip",response.text)

    def test_quick_wrong_tls_and_digest_never_collect(self):
        self.join()
        view=self.delivery.view("127.0.0.1")
        env=dict(os.environ);env.pop("PSModulePath",None)
        for key in ("tlsFingerprint","exeSha256"):
            changed={**view,key:"sha256:"+"0"*64}
            run=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-Command",commands(changed)["quick"]],
                stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=45,env=env)
            self.assertNotEqual(run.returncode,0)
            self.assertNotIn("Submission accepted",run.stdout)
        self.assertEqual(self.service.submissions.list_submissions(self.state.assessment_id),[])

    def test_revoke_cannot_be_undone_by_reloading_join(self):
        self.join()
        view=self.delivery.view("127.0.0.1")
        from csa_lab.pilot_launch import PilotLaunchService
        PilotLaunchService(self.service.storage,self.state.assessment_id,self.state.session_id).retire(view["handoffId"],revoke=True)
        with self.assertRaisesRegex(ValueError,"REVOKED"):
            self.delivery.view("127.0.0.1")
        with self.assertRaises(ValueError):
            self.delivery.download(view["handoffId"],"127.0.0.1")

    def test_native_source_route_and_changed_container_fail_before_collection(self):
        self.join()
        wrong=self.delivery.view("127.0.0.2")
        data=self.delivery.download(wrong["handoffId"],"127.0.0.2")
        path=self.root/"wrong-route.exe";path.write_bytes(data)
        env=dict(os.environ);env.pop("PSModulePath",None)
        run=subprocess.run([str(path)],stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=45,env=env)
        self.assertNotEqual(run.returncode,0)
        self.assertIn("STANDARD-USER-REQUIRED" if ctypes.windll.shell32.IsUserAnAdmin() else "CSA-PILOT-SOURCE-ROUTE",run.stderr)
        # Modify bytes in the embedded ZIP resource while retaining a valid PE.
        at=data.find(b"PK\x03\x04");self.assertGreater(at,0)
        changed=bytearray(data);changed[at+40]^=1;path=self.root/"modified-container.exe";path.write_bytes(changed)
        run=subprocess.run([str(path)],stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=45,env=env)
        self.assertNotEqual(run.returncode,0)
        self.assertIn("STANDARD-USER-REQUIRED" if ctypes.windll.shell32.IsUserAnAdmin() else "CSA-PILOT-START-FAILED",run.stderr)
        self.assertEqual(self.service.submissions.list_submissions(self.state.assessment_id),[])

    def test_no_browser_flag_or_session_json_can_create_start_authority(self):
        self.service.pause_collection(self.state.assessment_id)
        self.assertEqual(self.service._servers, {})
        from csa_console.server import ConsoleHttpsServer
        from csa_console.portal import PortalBinding,normalize_join_code
        import threading
        self.service.sessions.set_session_status(self.state.assessment_id,self.state.session_id,SessionStatus.OPEN)
        portal=PortalBinding(assessment_id=self.state.assessment_id,session_id=self.state.session_id,
            join_code_hash=hashlib.sha256(normalize_join_code(self.service.join_code(self.state.assessment_id)).encode()).hexdigest(),
            collector_path=Path(self.state.collector_path),expires_at=self.state.expires_at,maximum_downloads=10,storage=self.service.storage)
        server=ConsoleHttpsServer(self.state.assessment_id,self.state.session_id,self.service.storage,portal=portal)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            page=requests.get(self.url+"?authorized=true",verify=self.session.tls_certificate_path,timeout=10)
            self.assertNotIn("Copy Quick Run",page.text)
        finally:server.shutdown();thread.join(timeout=5)
