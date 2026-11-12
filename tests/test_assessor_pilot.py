"""ADR 5682 private pilot exercises real CMS and native verifier with synthetic acquisition."""
import ctypes
import json
import os
from pathlib import Path
import subprocess
import time
import threading
import unittest
from unittest import mock

import requests

from csa_console.canonical import sha256_file
from csa_console.integrity import verify_recorded_evidence
from csa_lab.assessor_pilot import issue_assessor_pilot, pilot_commands
from tests import test_collector_launcher as launcher
from tests import test_trusted_distribution as crypto


@unittest.skipUnless(os.name=="nt","Native Windows Collector integration")
class AssessorPilotCase(launcher.LauncherCase):
    @classmethod
    def setUpClass(cls):
        cls.crypto_type = type("PilotCrypto", (crypto.TrustedProtocolTests,), {})
        cls.crypto_type.setUpClass()
        cls.addClassCleanup(cls.crypto_type.tearDownClass)
        cls.native = cls.crypto_type.root / "native"
        result = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
            str(launcher.ROOT/"scripts/Build-CSATrustedCollector.ps1"), "-OutputDirectory", str(cls.native)],
            capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise AssertionError(result.stdout+result.stderr)
        # Read-only MachineGuid hashing; no trust-store/policy enrollment.
        ps = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
            "$v=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography').MachineGuid.Trim().ToLowerInvariant();"
            "$h=[Security.Cryptography.SHA256]::Create();try{'sha256:'+([BitConverter]::ToString("
            "$h.ComputeHash([Text.Encoding]::UTF8.GetBytes($v)))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}"],
            capture_output=True, text=True, timeout=20)
        cls.binding = ps.stdout.strip()
        if ps.returncode or not cls.binding.startswith("sha256:"):
            raise AssertionError("Endpoint fixture binding unavailable")

    def setUp(self):
        super().setUp()
        self.create(synthetic=True, development=False, expected_endpoints=3)
        patch = mock.patch("csa_lab.assessor_pilot.bootstrap_directory", return_value=self.native)
        patch.start(); self.addCleanup(patch.stop)

    def issue(self):
        request = dict(recipientId="ENDPOINT-PILOT-FIXTURE-001", endpointBinding=self.binding, sourceAddress="127.0.0.1",
            approvedBy="Synthetic assessor", customerApprovalReference="CONTRACT-FIXTURE",
            assessorApprovalReference="APPROVAL-FIXTURE", independentChannelReference="OFFLINE-FIXTURE", riskAccepted=True)
        result = issue_assessor_pilot(self.service, self.state.assessment_id, request)
        self.assertTrue(result["handoffId"].startswith("PILOT-"))
        bundle = self.service.storage.path(self.state.assessment_id, "pilot-handoffs", result["handoffId"])
        return result, bundle

    def harness(self, bundle, result, **changes):
        case = dict(kind="pilot", now=int(time.time()), root=str(bundle), approvalDigest=result["approvalSha256"],
            executable=str(bundle/"CSA-TrustedCollector.exe"), entryPoint=str(bundle/"Start-CSATrustedCollector.ps1"),
            endpoint=self.binding, execute=False, quick=True)
        case.update(changes)
        source = self.root/"pilot-case.json"; source.write_text(json.dumps([case]), "utf-8")
        env = {**os.environ, "PSExecutionPolicyPreference":"RemoteSigned"}; env.pop("PSModulePath",None)
        run = subprocess.run([str(self.crypto_type.harness), str(source)], capture_output=True,
                             text=True, timeout=90, env=env)
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout.splitlines()[-1])[0]

class AssessorPilotTests(AssessorPilotCase):
    def test_exe_and_quick_collect_same_engine_with_pilot_receipts_without_installation(self):
        for quick in (False, True):
            result, bundle = self.issue()
            if ctypes.windll.shell32.IsUserAnAdmin():
                self.assertEqual(self.harness(bundle, result, execute=True, quick=quick), "PASS")
            else:
                env = {**os.environ, "PSExecutionPolicyPreference":"RemoteSigned"}; env.pop("PSModulePath",None)
                # The same independently fingerprinted binaries, launched directly or by the copy command.
                if quick:
                    command = pilot_commands(str(bundle), result["approvalSha256"], result["exeSha256"])["quick"]
                    run = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                        capture_output=True, text=True, timeout=90, env=env)
                else:
                    run = subprocess.run([str(bundle/"CSA-TrustedCollector.exe"), "--assessor-pilot", "--bundle", str(bundle),
                        "--approval-sha256", result["approvalSha256"]], capture_output=True, text=True, timeout=90, env=env)
                self.assertEqual(run.returncode, 0, run.stdout+run.stderr)
        rows = self.service.submissions.list_submissions(self.state.assessment_id)
        self.assertEqual(len(rows), 2)
        analyses = [{"submissionId":row["submissionId"],"sessionId":self.state.session_id} for row in rows]
        proof = verify_recorded_evidence(self.service.storage, self.state.assessment_id, analyses, rows)
        self.assertEqual(proof["publisherAuthenticity"], "ASSESSOR_VERIFIED_PILOT")
        self.assertEqual(proof["signedReceiptIntegrity"], "VERIFIED")
        evidence = [self.service.storage.read_json(self.state.assessment_id,"submissions","accepted",row["submissionId"]+".evidence.json") for row in rows]
        for key in ("software","security","services","collectorVersion"):
            self.assertEqual(evidence[0][key], evidence[1][key])
        for document in evidence:
            self.assertEqual(document["metadata"]["privacyMode"], "PROFILE_ENFORCED")
            for marker in launcher.PRIVACY_MARKERS:
                self.assertNotIn(marker, json.dumps(document))

    def test_wrong_endpoint_hash_expiry_and_replaced_payload_fail_before_execution(self):
        result, bundle = self.issue()
        self.assertEqual(self.harness(bundle,result), "PASS")
        self.assertEqual(self.harness(bundle,result,endpoint="sha256:"+"0"*64), "CSA-PILOT-ENDPOINT")
        self.assertEqual(self.harness(bundle,result,approvalDigest="sha256:"+"0"*64), "CSA-TRUST-BOOTSTRAP")
        self.assertEqual(self.harness(bundle,result,now=int(time.time())+86400), "CSA-TRUST-EXPIRED")
        for name in ("collector.zip","publisher-manifest.p7s","session-envelope.p7s","Start-CSATrustedCollector.ps1","CSA-TrustedCollector.exe"):
            path=bundle/name; before=path.read_bytes()
            path.write_bytes(before+b"TAMPER")
            self.assertNotEqual(self.harness(bundle,result),"PASS",name)
            path.write_bytes(before)
        self.assertEqual(self.service.submissions.list_submissions(self.state.assessment_id),[])
        self.assertEqual(requests.get(self.url+"download",verify=self.session.tls_certificate_path,timeout=5).status_code,403)

    def test_pilot_nonce_requires_exact_source_and_is_one_use(self):
        result,bundle=self.issue()
        envelope=json.loads((bundle/"session-envelope.json").read_bytes())
        store=self.service._servers[self.state.assessment_id].trusted_network.grants
        with self.assertRaisesRegex(ValueError,"CSA-TRUST-SOURCE"):
            store.consume(self.session,envelope["envelopeId"],envelope["nonce"],"SUB-PILOT","HTTPS","127.0.0.2")
        store.consume(self.session,envelope["envelopeId"],envelope["nonce"],"SUB-PILOT","HTTPS","127.0.0.1")
        with self.assertRaisesRegex(ValueError,"CSA-TRUST-REPLAY"):
            store.consume(self.session,envelope["envelopeId"],envelope["nonce"],"SUB-PILOT2","HTTPS","127.0.0.1")

    def test_encrypted_offline_pilot_import_preserves_separate_assurance(self):
        from csa_console.offline import OfflineImportService
        result,bundle=self.issue()
        output=self.root/"private-offline.csa"
        self.assertEqual(self.harness(bundle,result,execute=True,offlineOutput=str(output)),"PASS")
        self.assertTrue(output.is_file())
        OfflineImportService(self.service.storage).import_file(self.state.assessment_id,output,analyze=False)
        rows=self.service.submissions.list_submissions(self.state.assessment_id)
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]["transport"],"OFFLINE_ENCRYPTED")
        proof=verify_recorded_evidence(self.service.storage,self.state.assessment_id,
            [{"submissionId":rows[0]["submissionId"],"sessionId":self.state.session_id}],rows)
        self.assertEqual(proof["publisherAuthenticity"],"ASSESSOR_VERIFIED_PILOT")
        self.assertEqual(proof["signedReceiptIntegrity"],"VERIFIED")

    def test_cmd_paste_runs_native_pilot_or_honors_the_real_elevation_gate(self):
        result,bundle=self.issue()
        command=pilot_commands(str(bundle),result["approvalSha256"],result["exeSha256"])["quick"]
        env={**os.environ};env.pop("PSModulePath",None)
        run=subprocess.run(["cmd.exe","/d","/s","/c",command],capture_output=True,text=True,timeout=90,env=env)
        if ctypes.windll.shell32.IsUserAnAdmin():
            self.assertNotEqual(run.returncode,0)
            self.assertIn("CSA-PILOT-STANDARD-USER-REQUIRED",run.stderr)
            self.assertEqual(self.service.submissions.list_submissions(self.state.assessment_id),[])
        else:
            self.assertEqual(run.returncode,0,run.stdout+run.stderr)
            self.assertIn("Submission accepted",run.stdout)
            self.assertEqual(len(self.service.submissions.list_submissions(self.state.assessment_id)),1)

    def test_command_generation_refuses_shell_injection_and_omits_secrets(self):
        result,bundle=self.issue()
        for path in ('C:\\pilot&whoami', 'C:\\%TEMP%', 'C:\\pilot"bad', 'C:\\pilot\\..\\other'):
            with self.assertRaises(ValueError):
                pilot_commands(path,result["approvalSha256"],result["exeSha256"])
        commands=pilot_commands("C:\\CSA Pilot",result["approvalSha256"],result["exeSha256"])
        config=json.loads((Path(self.state.collector_path).parent/"package/session-config.json").read_bytes())
        self.assertNotIn(config["enrollmentToken"],json.dumps(commands))
        self.assertIn("-ExecutionPolicy Bypass",commands["quick"])
        import base64
        decoded=base64.b64decode(commands["quick"].split(" -EncodedCommand ")[1]).decode("utf-16-le")
        self.assertEqual(decoded,commands["verificationScript"])
        self.assertNotIn("Set-ExecutionPolicy",json.dumps(commands))

    def test_local_assessor_ui_and_private_scope_status(self):
        from csa_lab.web import LabAdminServer
        from csa_lab.pilot_readiness import inspect_pilot
        result,bundle=self.issue()
        status=inspect_pilot(self.service,self.state.assessment_id,"ENDPOINT-PILOT-FIXTURE-001")
        self.assertEqual(status["trustState"],"ASSESSOR_VERIFIED_PILOT")
        self.assertNotEqual(status["trustState"],"REAL")
        if os.environ.get("CSA_BROWSER_SMOKE") != "1":
            return  # Browser evidence is exercised in the dedicated Windows Collector CI lane.
        admin=LabAdminServer(self.service,port=0)
        thread=threading.Thread(target=admin.server.serve_forever,daemon=True);thread.start()
        def close():
            admin.server.shutdown();thread.join(5);admin.server.server_close()
        self.addCleanup(close)
        candidates=[Path(os.environ[folder])/relative for folder in ("ProgramFiles","ProgramFiles(x86)") if folder in os.environ
                    for relative in ("Microsoft/Edge/Application/msedge.exe","Google/Chrome/Application/chrome.exe")]
        browser=next(path for path in candidates if path.is_file())
        screenshot=Path(os.environ.get("CSA_PILOT_EVIDENCE_DIR",self.root))/"pilot-enabled.png"
        screenshot.parent.mkdir(parents=True,exist_ok=True)
        data=dict(url=admin.url,browserPath=str(browser),profile=str(self.root/"pilot-browser"),mode="pilot",pin="",
            screenshot=str(screenshot),pilot={"pilot-recipient":"ENDPOINT-PILOT-FIXTURE-001","pilot-approver":"Synthetic assessor",
                "pilot-customer-reference":"CONTRACT-FIXTURE","pilot-assessor-reference":"APPROVAL-FIXTURE",
                "pilot-channel-reference":"OFFLINE-FIXTURE","pilot-source":"127.0.0.1","pilot-endpoint-binding":self.binding})
        run=subprocess.run(["node",str(launcher.ROOT/"tests/fixtures/join_browser_smoke.mjs")],
            input=json.dumps(data),capture_output=True,text=True,timeout=50)
        self.assertEqual(run.returncode,0,run.stderr)
        self.assertIn("Private pilot UI",run.stdout)
