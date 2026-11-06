"""Loopback HTTPS acceptance with isolated CMS identities and the shared engine."""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import unittest
from unittest import mock

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from csa_console.collector_package import COLLECTOR_VERSION
from csa_console.integrity import verify_recorded_evidence
from csa_console.trust_evidence import VerifiedTrustEvidence
from csa_lab.trusted_distribution import create_trusted_bundle, publisher_manifest, trust_bytes
from tests import test_collector_launcher as launcher
from tests import test_trusted_distribution as crypto


@unittest.skipUnless(os.name == "nt", "Requires the Windows Collector and Windows PowerShell")
class TrustedNetworkAcceptance(launcher.LauncherCase):
    @classmethod
    def setUpClass(cls):
        cls.crypto_type = type("NetworkCryptoFixture", (crypto.TrustedProtocolTests,), {})
        cls.crypto_type.setUpClass()
        cls.addClassCleanup(cls.crypto_type.tearDownClass)

    def setUp(self):
        super().setUp()
        self.crypto = self.crypto_type()
        self.create(synthetic=True, development=False, expected_endpoints=3)
        self.server = self.service._servers[self.state.assessment_id]
        self.network = self.server.trusted_network
        self.origin = self.url.split("/join/", 1)[0]
        self.package_root = Path(self.state.collector_path).parent / "package"
        config = json.loads((self.package_root / "session-config.json").read_bytes())
        self.policy = self.crypto.policy()
        self.policy["labs"][0].update(origin=self.origin, tlsFingerprint=config["serverCertificateFingerprint"])
        self.exe, self.entry = self.root / "publisher.exe", self.root / "entry.ps1"
        self.exe.write_bytes(b"immutable fixture EXE")
        self.entry.write_bytes(b"immutable fixture PS1")
        now = self.crypto.now
        self.publisher = publisher_manifest(self.package_root, self.exe, self.entry, key_id="publisher-1",
            version=COLLECTOR_VERSION, commit="0"*40, release_sequence=2, issued_at=now-30, expires_at=now+1800)
        self.network.authority_factory = lambda _: self
        self.verify_tls = self.session.tls_certificate_path

    def _run(self, kind, *, secret="", policy=None, **fields):
        def b64(data):
            return base64.b64encode(data).decode("ascii")
        case = dict(kind=kind, now=self.crypto.now, policy=b64(trust_bytes(policy or self.policy)),
            executable=b64(self.exe.read_bytes()), entryPoint=b64(self.entry.read_bytes()), **fields)
        case_path = self.root / ("case-" + secrets.token_hex(8) + ".json")
        case_path.write_text(json.dumps([case]), encoding="utf-8")
        env = {**os.environ, "PSExecutionPolicyPreference": "RemoteSigned"}
        env.pop("PSModulePath", None)
        result = subprocess.run([str(self.crypto.harness), str(case_path)], input=secret+"\n",
                                capture_output=True, encoding="utf-8", errors="replace", timeout=90, env=env)
        self.assertEqual(result.returncode, 0)
        if secret:
            self.assertNotIn(secret, result.stdout + result.stderr)
        outcome = json.loads(result.stdout.splitlines()[-1])[0]
        return outcome

    def verify(self, bundle):
        outcome = self._run("inspect", root=str(bundle))
        if not isinstance(outcome, dict):
            raise ValueError("CSA-TRUST-TEST-FIXTURE")
        return VerifiedTrustEvidence(outcome["assurance"], outcome["facts"])

    def _sign(self, content, role):
        return base64.b64decode(self.crypto.signature_case(json.loads(content), role=role)["signature"])

    def _issue(self, *, locator=None, signer=None):
        locator = locator or "ENV-" + secrets.token_urlsafe(24)
        bundle = create_trusted_bundle(self.root / locator, self.package_root, self.publisher,
            self._sign(self.publisher, "publishers"), sign_session=signer or (lambda data: self._sign(data, "labs")),
            grant_store=self.network.grants, session=self.session, network=True, authority=self,
            key_id="lab-1", lab_id="LAB-FIXTURE", recipient_id=self.policy["endpointId"],
            envelope_id=locator, nonce=secrets.token_urlsafe(32), issued_at=self.crypto.now)
        return locator, (bundle / "assessor-authorization.txt").read_text("ascii")

    def _acquire(self, locator, secret, *, quick=False, execute=False, policy=None):
        return self._run("network", secret=secret, labId="LAB-FIXTURE", envelopeId=locator, execute=execute,
                         requestedMode="QUICK_RUN_PROCESS_BYPASS" if quick else "STANDARD_POLICY", policy=policy)

    def _get(self, path):
        return requests.get(path, verify=self.verify_tls, timeout=15)

    def _post(self, path, credential, **kwargs):
        return requests.post(path, headers={"Authorization": credential}, verify=self.verify_tls, timeout=15, **kwargs)

    def _endpoint(self, locator):
        return self.origin + "/api/v2/trusted/" + locator + "/"

    def _check_browser(self):
        candidates = [Path(os.environ[folder]) / relative for folder in ("ProgramFiles", "ProgramFiles(x86)")
                      if folder in os.environ for relative in ("Google/Chrome/Application/chrome.exe", "Microsoft/Edge/Application/msedge.exe")]
        browser = next((path for path in candidates if path.is_file()), None)
        self.assertIsNotNone(browser, "Edge or Chrome is required by CSA_BROWSER_SMOKE")
        certificate = x509.load_pem_x509_certificate(Path(self.verify_tls).read_bytes())
        pin = base64.b64encode(hashlib.sha256(certificate.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).digest()).decode()
        result = subprocess.run(["node", str(Path(__file__).parent / "fixtures/join_browser_smoke.mjs")],
            input=json.dumps({"url": self.url, "browserPath": str(browser), "profile": str(self.root / "browser"), "pin": pin}),
            capture_output=True, encoding="utf-8", timeout=40)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("fallback: PASS", result.stdout)

    @staticmethod
    def _persisted_execution_policy():
        import winreg
        values = []
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            for key in (r"Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell",
                        r"Software\Policies\Microsoft\Windows\PowerShell"):
                for name in ("ExecutionPolicy", "EnableScripts"):
                    try:
                        with winreg.OpenKey(hive, key) as handle:
                            values.append(winreg.QueryValueEx(handle, name))
                    except FileNotFoundError:
                        values.append(None)
        return values

    def test_standard_and_process_bypass_submit_with_same_profile_and_privacy(self):
        first, standard_secret = self._issue()
        second, quick_secret = self._issue()
        pending = self._get(self.url)
        self.assertIn("TRUST_ENROLLMENT_PENDING", pending.text)
        self.assertNotIn(first, pending.text)
        self.assertEqual(self._get(self._endpoint(first) + "metadata").status_code, 403)
        self.network.isolated_testing = True
        ready = self._get(self.url)
        self.assertIn("Quick Run", ready.text)
        self.assertIn("-ExecutionPolicy Bypass", ready.text)
        self.assertIn(first, ready.text)
        for secret in (standard_secret, quick_secret, self.service.join_code(self.state.assessment_id)):
            self.assertNotIn(secret, ready.text)
        if os.environ.get("CSA_BROWSER_SMOKE") == "1":
            self._check_browser()
        before = self._persisted_execution_policy()
        standard = self._acquire(first, standard_secret, execute=True)
        quick = self._acquire(second, quick_secret, execute=True, quick=True)
        self.assertEqual(standard.get("status") if isinstance(standard, dict) else standard, "PASS")
        self.assertEqual(quick.get("status") if isinstance(quick, dict) else quick, "PASS")
        self.assertEqual(self._persisted_execution_policy(), before)
        rows = self.service.submissions.list_submissions(self.state.assessment_id)
        self.assertEqual(len(rows), 2)
        self.assertEqual({self.network.grants.record(self.session, item)["requestedMode"] for item in (first, second)},
                         {"STANDARD_POLICY", "QUICK_RUN_PROCESS_BYPASS"})
        storage, assessment = self.service.storage, self.state.assessment_id
        evidence = [storage.read_json(assessment, "submissions", "accepted", row["submissionId"]+".evidence.json")
                    for row in rows]
        for item in evidence:
            self.assertEqual(item["metadata"]["privacyMode"], "PROFILE_ENFORCED")
            for marker in launcher.PRIVACY_MARKERS:
                self.assertNotIn(marker, json.dumps(item, ensure_ascii=False))
        for key in ("collectorVersion", "software", "security", "services"):
            self.assertEqual(evidence[0][key], evidence[1][key])
        report_rows = [{"submissionId": item["submissionId"], "sessionId": self.state.session_id} for item in rows]
        proof = verify_recorded_evidence(storage, assessment, report_rows, rows)
        self.assertEqual(proof["publisherAuthenticity"], "TEST_ONLY")
        self.assertEqual(proof["signedReceiptIntegrity"], "VERIFIED")
        receipt = storage.path(assessment, "submissions", "accepted", rows[0]["submissionId"]+".trust.json")
        original = receipt.read_bytes()
        receipt.write_bytes(original.replace(b"TEST_ONLY", b"FAKE_TRUST"))
        altered = verify_recorded_evidence(storage, assessment, report_rows, rows)
        self.assertNotEqual(altered["publisherAuthenticity"], "VERIFIED")
        self.assertEqual(altered["signedReceiptIntegrity"], "VERIFIED")

    def test_authorization_and_download_are_purpose_limited_and_one_use(self):
        self.network.isolated_testing = True
        locator, secret = self._issue()
        endpoint = self._endpoint(locator)
        descriptor = self._get(endpoint+"metadata").json()
        envelope = json.loads(base64.b64decode(descriptor["sessionEnvelope"]))
        challenge = self._get(endpoint+"challenge").json()
        body = {key: challenge[key] for key in ("challengeId", "nonce", "recipientId", "envelopeDigest")}
        body["requestedMode"] = "QUICK_RUN_PROCESS_BYPASS"
        for wrong in (locator, envelope["nonce"], challenge["nonce"]):
            self.assertEqual(self._post(endpoint+"authorize", "CSA-Assessor "+wrong, json=body).status_code, 403)
        self.assertEqual(self._post(endpoint+"authorize", "CSA-Assessor "+secret,
                                    json={**body, "requestedMode": []}).status_code, 403)
        ticket = self._post(endpoint+"authorize", "CSA-Assessor "+secret, json=body)
        self.assertEqual(ticket.status_code, 200)
        token = ticket.json()["authorizationTicket"]
        self.assertEqual(self._post(endpoint+"authorize", "CSA-Assessor "+secret, json=body).status_code, 403)
        self.assertEqual(self._post(endpoint+"package", "CSA-Download "+token).status_code, 403)
        grant = self._post(endpoint+"download-grant", "CSA-Authorization "+token, json={}).json()["downloadGrant"]
        self.assertEqual(self._post(endpoint+"package", "CSA-Download "+grant).status_code, 200)
        self.assertEqual(self._post(endpoint+"package", "CSA-Download "+grant).status_code, 403)
        audit = self.service.storage.path(self.state.assessment_id, "audit", "audit.jsonl").read_text("utf-8")
        for private in (secret, token, grant):
            self.assertNotIn(private, audit)

    def test_wrong_pin_and_wrong_recipient_refuse_before_authorization(self):
        self.network.isolated_testing = True
        locator, secret = self._issue()
        for field, value, expected in (("pin", "sha256:"+"0"*64, "CSA-TRUST-TLS"),
                                      ("recipient", "ENDPOINT-FIXTURE-0002", "CSA-TRUST-RECIPIENT")):
            policy = json.loads(json.dumps(self.policy))
            if field == "pin":
                policy["labs"][0]["tlsFingerprint"] = value
            else:
                policy["endpointId"] = value
            self.assertEqual(self._acquire(locator, "", policy=policy), expected)
            self.assertEqual(self.network.grants.record(self.session, locator)["authUsed"], 0)
        self.assertEqual(self._acquire(locator, secret)["status"], "PASS")

    def test_interrupted_package_retries_complete_wrong_package_does_not(self):
        self.network.isolated_testing = True
        handler = self.server._server.RequestHandlerClass
        send = handler._bytes
        for behavior in ("truncated", "wrong"):
            locator, secret = self._issue()
            package_responses = []

            def alter(instance, status, data, content_type, *args, **kwargs):
                if instance.diagnostic_stage == "TRUSTED_PACKAGE_DOWNLOAD" and status == 200:
                    package_responses.append(status)
                    if len(package_responses) == 1 and behavior == "truncated":
                        instance.send_response(status)
                        instance.send_header("Content-Length", str(len(data)))
                        instance.send_header("Connection", "close")
                        instance.end_headers()
                        instance.wfile.write(data[:len(data)//2])
                        instance.close_connection = True
                        return
                    if behavior == "wrong":
                        data = bytes([data[0] ^ 1]) + data[1:]
                return send(instance, status, data, content_type, *args, **kwargs)

            with mock.patch.object(handler, "_bytes", alter):
                result = self._acquire(locator, secret)
            if behavior == "truncated":
                self.assertIsInstance(result, dict, result)
                self.assertEqual(result["status"], "PASS")
                self.assertIn("TRUST_DOWNLOAD_RETRY", result["phases"])
                self.assertEqual(len(package_responses), 2)
            else:
                self.assertEqual(result, "CSA-TRUST-DIGEST")
                self.assertEqual(len(package_responses), 1)

    def test_authoring_interruptions_never_publish_a_ready_invitation(self):
        self.network.isolated_testing = True
        signing, publication = ("ENV-" + secrets.token_urlsafe(24) for _ in range(2))
        failed_signer = mock.Mock(side_effect=OSError("SYNTHETIC-SIGNER-INTERRUPTION"))
        with self.assertRaises(OSError):
            self._issue(locator=signing, signer=failed_signer)
        rename = Path.replace

        def interrupt(path, target):
            if path.name == "bundle" and Path(target).name == publication:
                raise OSError("SYNTHETIC-PUBLISH-INTERRUPTION")
            return rename(path, target)

        with mock.patch.object(Path, "replace", interrupt), self.assertRaises(OSError):
            self._issue(locator=publication)
        for locator in (signing, publication):
            self.assertFalse((self.root / locator).exists())
            self.assertEqual(self._get(self._endpoint(locator)+"metadata").status_code, 403)
        rows = {item["envelopeId"]: item for item in self.network.grants.reconcile(self.session)["items"]}
        self.assertEqual(rows[signing]["reasonCode"], "CSA-TRUST-ISSUANCE-SIGNING")
        self.assertEqual(rows[publication]["operationState"], "FAILED")
        fresh, secret = self._issue()
        self.assertEqual(self._acquire(fresh, secret)["status"], "PASS")
