"""Independent trust, immutable artifacts and fail-closed release regressions."""
import base64
import copy
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from unittest import mock
import threading
import requests

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from csa_console.canonical import sha256_bytes
from csa_lab.collector_executable import _signed_pe, build_bound_collector
from csa_lab.trusted_distribution import trust_bytes
from csa_console.submission import SubmissionService, SubmissionRejected
from csa_console.trusted_grants import TrustedGrantStore
from csa_console.server import ConsoleHttpsServer
from csa_console.portal import PortalBinding
from tests.test_console_sprint5 import Sprint5TestCase

ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"


class TrustedAuthoringTests(unittest.TestCase):
    def test_jcs_uses_utf16_order_and_rejects_noninteger_numbers(self):
        self.assertEqual(trust_bytes({"\ue000": "õäöü", "\U00010000": True}),
                         '{"𐀀":true,"":"õäöü"}'.encode())
        for value in (0.1, float("nan"), 9007199254740992, {"bad": "\ud800"}):
            with self.assertRaises((ValueError, UnicodeError)):
                trust_bytes(value)

    def test_a_signed_pe_cannot_receive_a_session_overlay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = bytearray(512)
            value[:2] = b"MZ"
            struct.pack_into("<I", value, 60, 64)
            value[64:68] = b"PE\x00\x00"
            struct.pack_into("<H", value, 88, 0x20B)
            struct.pack_into("<II", value, 88 + 144, 384, 128)
            self.assertTrue(_signed_pe(value))
            bootstrap = root / "signed.exe"
            bootstrap.write_bytes(value)
            with self.assertRaisesRegex(ValueError, "CSA-TRUST-IMMUTABLE"):
                build_bound_collector(bootstrap, root, root / "changed.exe")


@unittest.skipUnless(os.name == "nt", "Windows CMS and Authenticode runtime")
class TrustedProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.harness = cls.root / "trust-tests.exe"
        compiler = Path(os.environ["SystemRoot"]) / "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
        result = subprocess.run([str(compiler), "/nologo", "/target:exe", "/main:TrustHarness", f"/out:{cls.harness}",
            "/reference:System.IO.Compression.dll", "/reference:System.IO.Compression.FileSystem.dll",
            "/reference:System.Web.Extensions.dll", "/reference:System.Security.dll",
            str(ROOT / "collector/bootstrapper/Program.cs"), str(ROOT / "collector/trusted/TrustedEntry.cs"),
            str(ROOT / "collector/trusted/TrustedNetwork.cs"), str(ROOT / "collector/trusted/TrustInspection.cs"),
            str(ROOT / "collector/trusted/AssessorPilot.cs"),
            str(ROOT / "collector/trusted/TrustProtocol.cs"), str(ROOT / "tests/fixtures/trust_protocol_harness.cs")],
            capture_output=True, text=True, timeout=30)
        if result.returncode:
            cls.temporary.cleanup()
            raise AssertionError(result.stdout + result.stderr)
        cls.now = int(datetime.now(timezone.utc).timestamp())
        cls.publisher_key, cls.publisher_cert = cls.certificate("Publisher fixture")
        cls.lab_key, cls.lab_cert = cls.certificate("Lab fixture")

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @classmethod
    def certificate(cls, name, expired=False):
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        current = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(current - timedelta(days=2))
                .not_valid_after(current - timedelta(days=1) if expired else current + timedelta(days=2))
                .sign(key, hashes.SHA256()))
        return key, cert

    def policy(self):
        def key_row(name, key):
            return {"keyId": name, "spkiSha256": sha256_bytes(key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)),
                "issuedAt": self.now - 60, "expiresAt": self.now + 3600, "revoked": False}
        publisher = key_row("publisher-1", self.publisher_key)
        publisher["certificateSha256"] = sha256_bytes(self.publisher_cert.public_bytes(serialization.Encoding.DER))
        lab = {**key_row("lab-1", self.lab_key), "labId": "LAB-FIXTURE", "origin": "https://collector.example.invalid:8443",
               "tlsFingerprint": "sha256:" + "a" * 64}
        return {"objectType": "CSA_TRUST_POLICY", "schemaVersion": 1, "issuedAt": self.now - 60,
                "expiresAt": self.now + 3600, "revocationFreshUntil": self.now + 1800,
                "minimumReleaseSequence": 2, "endpointId": "ENDPOINT-FIXTURE-0001", "publishers": [publisher], "labs": [lab]}

    def release(self):
        return {"objectType": "CSA_PUBLISHER_RELEASE", "schemaVersion": 1, "keyId": "publisher-1",
                "issuedAt": self.now - 30, "expiresAt": self.now + 600, "releaseSequence": 2,
                "version": "fixture", "commit": "0" * 40, "bootstrapSha256": sha256_bytes(b"immutable fixture"),
                "bootstrapSize": len(b"immutable fixture"), "entryPointSize": len(b"entry fixture"),
                "entryPointSha256": sha256_bytes(b"entry fixture"), "files": [], "profiles": []}

    def session(self):
        return {"objectType": "CSA_LAB_SESSION", "schemaVersion": 1, "keyId": "lab-1",
                "issuedAt": self.now - 30, "expiresAt": self.now + 600, "envelopeId": "ENV-FIXTURE-00000001",
                "labId": "LAB-FIXTURE", "recipientId": "ENDPOINT-FIXTURE-0001",
                "assessmentId": "CSA-FIXTURE", "sessionId": "SES-FIXTURE",
                "origin": "https://collector.example.invalid:8443", "tlsFingerprint": "sha256:" + "a" * 64,
                "mode": "STANDARD_USER_COLLECTION", "profileId": "windows-standard-v1", "profileDigest": "sha256:" + "b" * 64,
                "privacyPolicyDigest": "sha256:" + "c" * 64, "publisherManifestDigest": sha256_bytes(trust_bytes(self.release())),
                "packageDigest": "", "sessionManifestDigest": "", "nonce": "NONCE-FIXTURE-000001",
                "submissionPolicy": {"transport": "HTTPS_OR_ENCRYPTED_OFFLINE", "maximumBytes": 1048576, "receiptRequired": True}}

    def signature_case(self, value, policy=None, key=None, cert=None, role="publishers"):
        content = trust_bytes(value)
        key = key or (self.publisher_key if role == "publishers" else self.lab_key)
        cert = cert or (self.publisher_cert if role == "publishers" else self.lab_cert)
        signature = (pkcs7.PKCS7SignatureBuilder().set_data(content).add_signer(cert, key, hashes.SHA256())
                     .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary]))
        return {"kind": "signature", "content": base64.b64encode(content).decode(), "signature": base64.b64encode(signature).decode(),
                "policy": base64.b64encode(trust_bytes(policy or self.policy())).decode(), "role": role, "now": self.now}

    def run_cases(self, cases):
        source = self.root / "cases.json"
        source.write_text(json.dumps(cases), encoding="utf-8")
        result = subprocess.run([str(self.harness), str(source)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_enforced_organization_policy_refuses_quick_run_with_machine_precedence(self):
        cases = [dict(kind="organizationPolicy", now=self.now, machineEnabled=me, machinePolicy=mp,
                      userEnabled=ue, userPolicy=up)
                 for me, mp, ue, up in ((0, None, 1, "RemoteSigned"), (None, None, 0, None),
                                       (1, "Restricted", 1, "AllSigned"), (1, "AllSigned", 0, None),
                                       (None, None, None, None))]
        self.assertEqual(self.run_cases(cases), ["CSA-COL-ORGANIZATION-POLICY"] * 3 + ["PASS", "PASS"])

    def test_publisher_signatures_substitution_expiry_revocation_and_rollback(self):
        release = self.release()
        cases, expected = [self.signature_case(release)], ["PASS"]
        other_key, other_cert = self.certificate("Wrong signer fixture")
        cases.append(self.signature_case(release, key=other_key, cert=other_cert))
        expected.append("CSA-TRUST-SIGNER")
        key, cert = self.certificate("Expired fixture", expired=True)
        cases.append(self.signature_case(release, key=key, cert=cert))
        expected.append("CSA-TRUST-CERTIFICATE")
        for change, outcome in (
            (lambda p: p["publishers"][0].update(revoked=True), "CSA-TRUST-REVOKED"),
            (lambda p: p["publishers"][0].update(expiresAt=self.now - 1), "CSA-TRUST-EXPIRED"),
            (lambda p: p.update(revocationFreshUntil=self.now - 1), "CSA-TRUST-STALE"),
            (lambda p: p.update(minimumReleaseSequence=3), "CSA-TRUST-ROLLBACK"),
            (lambda p: p["publishers"][0].update(certificateSha256="sha256:" + "0" * 64), "CSA-TRUST-SIGNER"),
        ):
            policy = self.policy()
            change(policy)
            cases.append(self.signature_case(release, policy))
            expected.append(outcome)
        changed = self.signature_case(release)
        changed["content"] = base64.b64encode(trust_bytes({**release, "version": "changed"})).decode()
        cases.append(changed)
        expected.append("CSA-TRUST-SIGNATURE")
        self.assertEqual(self.run_cases(cases), expected)

    def test_windows_cms_authoring_matches_the_production_verifier(self):
        content = trust_bytes(self.release())
        signed = subprocess.run([str(self.harness), "--self-sign"], input=content,
                                capture_output=True, timeout=30)
        self.assertEqual(signed.returncode, 0, "Windows ephemeral CMS authoring failed")
        public = json.loads(signed.stdout)
        self.assertEqual(public["keySize"], 3072)
        policy = self.policy()
        policy["publishers"][0].update({key: public[key] for key in ("spkiSha256", "certificateSha256")})
        case = {"kind": "signature", "content": base64.b64encode(content).decode(), "signature": public["signature"],
                "policy": base64.b64encode(trust_bytes(policy)).decode(), "role": "publishers", "now": self.now}
        self.assertEqual(self.run_cases([case]), ["PASS"])

    def test_configuration_binds_destination_session_privacy_nonce_and_tls(self):
        root = self.root / "configuration"
        root.mkdir(exist_ok=True)
        privacy = root / "collector/profiles/privacy.json"
        privacy.parent.mkdir(parents=True, exist_ok=True)
        privacy.write_bytes(b'{"fixture":true}')
        session = self.session()
        session.update(privacyPolicyDigest=sha256_bytes(privacy.read_bytes()),
                       tlsFingerprint=sha256_bytes(self.lab_cert.public_bytes(serialization.Encoding.DER)))
        (root / "server-cert.pem").write_bytes(self.lab_cert.public_bytes(serialization.Encoding.PEM))
        manifest = {key: session[key] for key in ("assessmentId", "sessionId")}
        manifest.update(collectionProfileDigest=session["profileDigest"], serverCertificateFingerprint=session["tlsFingerprint"])
        (root / "trusted-manifest.json").write_bytes(trust_bytes(manifest))
        config = {**manifest, "serverUrl": session["origin"], "collectorMode": session["mode"],
                  "collectionProfile": session["profileId"], "privacyPolicy": "collector/profiles/privacy.json",
                  "trustedEnvelopeId": session["envelopeId"], "trustedEnvelopeNonce": session["nonce"],
                  "expiresAt": datetime.fromtimestamp(session["expiresAt"], timezone.utc).isoformat()}
        case = {"kind": "configuration", "root": str(root), "session": base64.b64encode(trust_bytes(session)).decode(), "now": self.now}
        for field, changed, result in ((None, None, "PASS"), ("sessionId", "other", "CSA-TRUST-SESSION"),
            ("serverUrl", "https://other.example.invalid", "CSA-TRUST-SCOPE"),
            ("collectionProfileDigest", "changed", "CSA-TRUST-SCOPE"),
            ("trustedEnvelopeNonce", "changed", "CSA-TRUST-NONCE"),
            ("expiresAt", "2020-01-01T00:00:00Z", "CSA-TRUST-EXPIRED"),
            ("privacyPolicy", "../unsafe.json", "CSA-TRUST-PATH")):
            value = {**config, **({field: changed} if field else {})}
            (root / "session-config.json").write_bytes(trust_bytes(value))
            self.assertEqual(self.run_cases([case]), [result])
        (root / "session-config.json").write_bytes(trust_bytes(config))
        (root / "server-cert.pem").write_bytes(self.publisher_cert.public_bytes(serialization.Encoding.PEM))
        self.assertEqual(self.run_cases([case]), ["CSA-TRUST-TLS"])

    def test_lab_identity_scope_and_certificate_substitution(self):
        value = self.session()
        cases, expected = [self.signature_case(value, role="labs")], ["PASS"]
        for field in ("labId", "origin", "tlsFingerprint", "recipientId"):
            changed = {**value, field: "different"}
            cases.append(self.signature_case(changed, role="labs"))
            expected.append("CSA-TRUST-RECIPIENT" if field == "recipientId" else "CSA-TRUST-LAB")
        other_key, other_cert = self.certificate("Substituted Lab fixture")
        cases.append(self.signature_case(value, key=other_key, cert=other_cert, role="labs"))
        expected.append("CSA-TRUST-SIGNER")
        for field, result in (("revoked", "CSA-TRUST-REVOKED"), ("expiresAt", "CSA-TRUST-EXPIRED")):
            policy = self.policy()
            policy["labs"][0][field] = True if field == "revoked" else self.now - 1
            cases.append(self.signature_case(value, policy=policy, role="labs"))
            expected.append(result)
        cases.append(self.signature_case({**value, "expiresAt": self.now - 1}, role="labs"))
        expected.append("CSA-TRUST-EXPIRED")
        self.assertEqual(self.run_cases(cases), expected)

    def test_canonical_json_and_modified_launchers_fail_closed(self):
        cases, expected = [], []
        for content in (b'{"a":1,"a":2}', b'{"a":1.0}', b' {"a":1}', b'{"a":1, "b":2}', b'{"x":"\xff"}'):
            cases.append({"kind": "canonical", "content": base64.b64encode(content).decode(), "now": self.now})
            expected.append("CSA-TRUST-JSON" if b"\xff" in content else
                            "CSA-TRUST-NUMBER" if b"1.0" in content else "CSA-TRUST-CANONICAL")
        for content in (b"immutable fixture", b"immutable fixture-modified", b"immutable fixture-overlay"):
            cases.append({"kind": "artifact", "content": base64.b64encode(content).decode(),
                          "expected": sha256_bytes(b"immutable fixture"), "now": self.now})
            expected.append("PASS" if content == b"immutable fixture" else "CSA-TRUST-BOOTSTRAP")
        self.assertEqual(self.run_cases(cases), expected)

    def test_engine_manifest_rejects_rehashed_substitution_and_unsafe_inventory(self):
        content = {"Invoke-CSACollector.ps1": b"# fixture engine",
                   "session-config.json": b"{}", "server-cert.pem": b"certificate fixture",
                   "offline-public.xml": b"public fixture", "OPERATOR-INSTRUCTIONS.txt": b"fixture"}
        content["trusted-manifest.json"] = b"manifest fixture"
        release = self.release()
        session = self.session()
        release["profiles"] = [{key: session[key] for key in ("profileId", "profileDigest", "privacyPolicyDigest")}]
        release["files"] = [{"path": "Invoke-CSACollector.ps1", "size": len(content["Invoke-CSACollector.ps1"]),
                             "sha256": sha256_bytes(content["Invoke-CSACollector.ps1"])}]

        def archive_case(files, entries=None, profile=False):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                for name in entries or files:
                    archive.writestr(name, files.get(name, b"unexpected"))
            package = buffer.getvalue()
            envelope = {**session, "packageDigest": sha256_bytes(package),
                        "sessionManifestDigest": sha256_bytes(files["trusted-manifest.json"])}
            if profile:
                envelope["privacyPolicyDigest"] = "sha256:" + "0" * 64
            return {"kind": "archive", "content": base64.b64encode(package).decode(),
                    "release": base64.b64encode(trust_bytes(release)).decode(),
                    "session": base64.b64encode(trust_bytes(envelope)).decode(), "now": self.now}

        changed = {**content, "Invoke-CSACollector.ps1": b"# substituted", "trusted-manifest.json": b"rehashed manifest"}
        cases = [archive_case(content), archive_case(changed), archive_case(content, profile=True),
                 archive_case({**content, "../escape.psm1": b"unsafe"}),
                 archive_case({**content, "collector/unexpected.psm1": b"unexpected"}),
                 archive_case(content, entries=list(content) + ["INVOKE-CSACOLLECTOR.PS1"])]
        self.assertEqual(self.run_cases(cases), ["PASS", "CSA-TRUST-ENGINE", "CSA-TRUST-PROFILE",
                                               "CSA-TRUST-PATH", "CSA-TRUST-UNEXPECTED-FILE", "CSA-TRUST-PATH"])

    def test_staging_change_between_extraction_and_read_lease_is_rejected(self):
        root = self.root / "leases"
        root.mkdir(exist_ok=True)
        source = b"# publisher-authorized fixture"
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("module.psm1", source)
        case = {"kind": "leases", "root": str(root), "now": self.now,
                "content": base64.b64encode(buffer.getvalue()).decode()}
        for content, expected in ((source, "PASS"), (source.replace(b"fixture", b"changed"), "CSA-TRUST-STAGED-DIGEST"),
                                  (source + b"modified", "CSA-TRUST-STAGED-DIGEST")):
            (root / "module.psm1").write_bytes(content)
            self.assertEqual(self.run_cases([case]), [expected])

    def test_both_entry_points_and_release_lane_require_enrollment(self):
        build = subprocess.run([POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                                str(ROOT / "scripts/Build-CSATrustedCollector.ps1"), "-OutputDirectory", str(self.root / "build")],
                               capture_output=True, text=True, timeout=30)
        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
        commands = [[str(self.root / "build/CSA-TrustedCollector.exe"), "--bundle", str(self.root)],
                    [POWERSHELL, "-NoProfile", "-File", str(self.root / "build/Start-CSATrustedCollector.ps1"), "-Bundle", str(self.root)]]
        for command in commands:
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("TRUST_NOT_ESTABLISHED", result.stdout + result.stderr)
        environment = {**os.environ, "CSA_RELEASE_APPROVED": "", "CSA_TRUST_ENROLLMENT_ACCEPTED": ""}
        result = subprocess.run([POWERSHELL, "-NoProfile", "-File", str(ROOT / "scripts/Build-CSALab.ps1"), "-Release"],
                                env=environment, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CSA-RELEASE-HOLD", result.stdout + result.stderr)
        environment.update(CSA_RELEASE_APPROVED="true", CSA_TRUST_ENROLLMENT_ACCEPTED="true",
                           CSA_SIGNING_CERTIFICATE_BASE64="", CSA_SIGNING_CERTIFICATE_PASSWORD="")
        result = subprocess.run([POWERSHELL, "-NoProfile", "-File", str(ROOT / "scripts/Build-CSALab.ps1"), "-Release"],
                                env=environment, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CSA-RELEASE-SIGNING-REQUIRED", result.stdout + result.stderr)
        blocked = subprocess.run([POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Restricted", "-File",
                                  str(self.root / "build/Start-CSATrustedCollector.ps1"), "-Bundle", str(self.root)],
                                 capture_output=True, text=True, timeout=30)
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("UnauthorizedAccess", blocked.stdout + blocked.stderr)


class TrustedSubmissionTests(Sprint5TestCase):
    def grant(self, label="0001"):
        value = {"envelopeId": "ENV-FIXTURE-" + label + "0000", "nonce": "NONCE-FIXTURE-" + label + "0000",
                 "assessmentId": self.assessment.assessment_id, "sessionId": self.session.session_id,
                 "recipientId": "ENDPOINT-FIXTURE-0001", "expiresAt": int(datetime.now(timezone.utc).timestamp()) + 600}
        TrustedGrantStore(self.storage).issue(self.session, value)
        return value

    def test_grant_is_required_and_consumed_once_across_concurrent_requests(self):
        grant = self.grant()
        service = SubmissionService(self.storage)
        with self.assertRaises(SubmissionRejected):
            service.request_nonce(self.assessment.assessment_id, self.session.session_id, "SUB-NO-GRANT", self.token, "127.0.0.1")

        def request(index):
            try:
                SubmissionService(self.storage).request_nonce(self.assessment.assessment_id, self.session.session_id,
                    f"SUB-TRUST-{index}", self.token, "127.0.0.1", (grant["envelopeId"], grant["nonce"]))
                return True
            except SubmissionRejected:
                return False

        with ThreadPoolExecutor(max_workers=5) as pool:
            self.assertEqual(sum(pool.map(request, range(10))), 1)

    def test_grant_consumption_is_atomic_across_processes(self):
        grant = self.grant()
        program = """import json,sys
from csa_console.storage import AssessmentStorage
from csa_console.trusted_grants import TrustedGrantStore
value=json.load(sys.stdin)
store=TrustedGrantStore(AssessmentStorage(value['storage']))
session=store.sessions.load_session(value['assessment'],value['session'])
try:
    store.consume(session,value['envelope'],value['nonce'],value['submission'],'HTTPS')
    print('PASS')
except ValueError:
    print('REJECTED')
"""
        def consume(index):
            value = {"storage": str(self.storage.root), "assessment": self.assessment.assessment_id,
                     "session": self.session.session_id, "envelope": grant["envelopeId"],
                     "nonce": grant["nonce"], "submission": f"SUB-PROCESS-{index}"}
            result = subprocess.run([sys.executable, "-c", program], cwd=ROOT, input=json.dumps(value),
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, "Isolated grant process failed")
            return result.stdout.strip() == "PASS"
        with ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(sum(pool.map(consume, range(8))), 1)

    def test_preissued_legacy_nonce_cannot_bypass_a_trusted_session(self):
        service = SubmissionService(self.storage)
        submission = "SUB-LEGACY-NONCE"
        nonce = service.request_nonce(self.assessment.assessment_id, self.session.session_id,
                                      submission, self.token, "127.0.0.1")
        self.grant()
        # A stale metadata writer must not reopen the legacy nonce route.
        self.sessions._write_session(self.session)
        with self.assertRaisesRegex(SubmissionRejected, "CSA-TRUST-SESSION"):
            service.accept(assessment_id=self.assessment.assessment_id, session_id=self.session.session_id,
                submission_id=submission, enrollment_token=self.token, nonce=nonce, source_address="127.0.0.1",
                archive_bytes=self.package(submission, nonce).read_bytes())

    def test_trusted_online_submission_retains_valid_receipt(self):
        from csa_console.receipts import verify_receipt
        from csa_console.serde import model_to_dict
        grant = self.grant()
        service = SubmissionService(self.storage)
        submission = "SUB-TRUST-ONLINE"
        nonce = service.request_nonce(self.assessment.assessment_id, self.session.session_id,
            submission, self.token, "127.0.0.1", (grant["envelopeId"], grant["nonce"]))
        receipt, package, _path = service.accept(assessment_id=self.assessment.assessment_id,
            session_id=self.session.session_id, submission_id=submission, enrollment_token=self.token,
            nonce=nonce, source_address="127.0.0.1", archive_bytes=self.package(submission, nonce).read_bytes())
        self.assertEqual(receipt.package_digest, package.package_digest)
        self.assertTrue(verify_receipt(model_to_dict(receipt), self.session.tls_certificate_path))

    def test_signed_bundle_is_separate_and_preserves_original_engine(self):
        from csa_console.collector_package import create_collector_package
        from csa_lab.trusted_distribution import create_trusted_bundle, publisher_manifest
        package = create_collector_package(self.session, self.token, Path(self.temporary.name) / "engine")
        config = (package / "session-config.json").read_bytes()
        bootstrap, entry = Path(self.temporary.name) / "immutable.exe", Path(self.temporary.name) / "entry.ps1"
        bootstrap.write_bytes(b"immutable test publisher artifact")
        entry.write_bytes(b"# immutable test publisher entry")
        now = int(datetime.now(timezone.utc).timestamp())
        publisher = publisher_manifest(package, bootstrap, entry, key_id="publisher-fixture", version="fixture",
            commit="0" * 40, release_sequence=2, issued_at=now, expires_at=now + 600)
        output = Path(self.temporary.name) / "handoff"
        create_trusted_bundle(output, package, publisher, b"test-only signature", sign_session=lambda _: b"test-only signature",
            grant_store=TrustedGrantStore(self.storage), session=self.session, key_id="lab-fixture", lab_id="LAB-FIXTURE",
            recipient_id="ENDPOINT-FIXTURE-0001", envelope_id="ENV-FIXTURE-00000001", nonce="NONCE-FIXTURE-000001", issued_at=now)
        self.assertEqual((package / "session-config.json").read_bytes(), config)
        self.assertEqual(bootstrap.read_bytes(), b"immutable test publisher artifact")
        self.assertEqual(set(path.name for path in output.iterdir()),
            {"publisher-manifest.json", "publisher-manifest.p7s", "session-envelope.json", "session-envelope.p7s", "collector.zip"})
        envelope = json.loads((output / "session-envelope.json").read_bytes())
        self.assertEqual(envelope["packageDigest"], sha256_bytes((output / "collector.zip").read_bytes()))

    def test_trusted_offline_import_consumes_grant_and_rejects_reuse(self):
        from csa_console.offline import encrypt_offline_submission, OfflineImportService, OfflineImportError
        from csa_console.package import EvidencePackageValidator
        grant = self.grant()
        nonce = "trusted:" + grant["nonce"]
        submission = "SUB-TRUST-OFFLINE"
        archive = self.package(submission, nonce).read_bytes()
        package = EvidencePackageValidator().validate(archive, enrollment_token=self.token,
            expected_assessment_id=self.assessment.assessment_id, expected_session_id=self.session.session_id,
            expected_submission_id=submission, expected_nonce=nonce, expected_profile_digest=self.session.collection_profile_digest)
        encrypted = encrypt_offline_submission(Path(self.temporary.name) / "trusted.csa", archive_bytes=archive,
            enrollment_token=self.token, nonce=nonce, public_key_xml_path=self.session.offline_public_key_path,
            associated_data={"assessmentId": self.assessment.assessment_id, "sessionId": self.session.session_id,
                             "submissionId": submission, "packageDigest": package.package_digest})
        service = OfflineImportService(self.storage)
        self.assertEqual(service.import_file(self.assessment.assessment_id, encrypted, analyze=False).package_digest, package.package_digest)
        from csa_console.integrity import verify_recorded_evidence
        proof = verify_recorded_evidence(self.storage, self.assessment.assessment_id,
            [{"submissionId": submission, "sessionId": self.session.session_id}],
            SubmissionService(self.storage).list_submissions(self.assessment.assessment_id))
        self.assertEqual(proof["signedReceiptIntegrity"], "VERIFIED")
        with self.assertRaises(OfflineImportError):
            service.import_file(self.assessment.assessment_id, encrypted, analyze=False)

    def test_portal_error_has_safe_correlation_and_stable_stage(self):
        from csa_console.distribution import DistributionPolicy, DistributionState
        from csa_console.portal import normalize_join_code
        import hashlib
        join = normalize_join_code("ABCD-EFGH")
        collector = Path(self.temporary.name) / "collector.exe"
        collector.write_bytes(b"fixture")
        portal = PortalBinding(self.assessment.assessment_id, self.session.session_id,
            hashlib.sha256(join.encode()).hexdigest(), collector, self.session.expires_at, 10, self.storage,
            distribution_policy=DistributionPolicy(DistributionState.DEVELOPMENT_UNSIGNED, frozenset({"127.0.0.1"})))
        server = ConsoleHttpsServer(self.assessment.assessment_id, self.session.session_id, self.storage,
                                    analyze_automatically=False, portal=portal)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        url = "https://%s:%s/join/%s/download" % (*server.address, join)
        read_bytes = Path.read_bytes

        def locked(path):
            if path == collector:
                raise OSError("secret-join-token raw-user synthetic-private-address")
            return read_bytes(path)

        with mock.patch.object(Path, "read_bytes", locked), self.assertLogs("csa_console.server") as logs:
            response = requests.get(url, verify=self.session.tls_certificate_path, timeout=5)
        self.assertEqual(response.status_code, 500)
        self.assertRegex(response.headers["X-CSA-Correlation-ID"], r"^[a-f0-9]{32}$")
        self.assertEqual(response.headers["X-CSA-Stage"], "PORTAL_DOWNLOAD")
        self.assertEqual(response.headers["X-CSA-Code"],"CSA-PORTAL-ERROR")
        self.assertIn("hindaja poole",response.text)
        self.assertNotIn("secret-join-token", response.text + " ".join(logs.output))
        self.assertNotIn("127.0.0.1", " ".join(logs.output))
        server.shutdown()
        thread.join(timeout=5)

    def test_three_accepted_submissions_are_two_endpoints_and_one_duplicate(self):
        from csa_console.audit import ConsoleAuditLog
        from csa_console.fleet import FleetAnalyzer
        from csa_console.pipeline import ConsoleAnalysisPipeline
        from csa_console.package import build_evidence_package
        service = SubmissionService(self.storage)
        for index, device in enumerate(("a", "b", "a")):
            submission = f"SUB-STAGING-{index}"
            nonce = service.request_nonce(self.assessment.assessment_id, self.session.session_id,
                                          submission, self.token, "127.0.0.1")

            def bound_package(*args, **kwargs):
                kwargs["manifest_fields"]["deviceId"] = "sha256:" + device * 64
                return build_evidence_package(*args, **kwargs)

            with mock.patch("tests.test_console_sprint5.build_evidence_package", side_effect=bound_package):
                archive = self.package(submission, nonce).read_bytes()
            _receipt, validated, _path = service.accept(assessment_id=self.assessment.assessment_id, session_id=self.session.session_id,
                submission_id=submission, enrollment_token=self.token, nonce=nonce, source_address="127.0.0.1",
                archive_bytes=archive)
            ConsoleAnalysisPipeline(self.storage).analyze(validated)
        fleet = FleetAnalyzer(self.storage).analyze(self.assessment.assessment_id)
        self.assertEqual((fleet.submission_count, fleet.endpoint_count, fleet.duplicate_endpoint_submission_count), (3, 2, 1))
        audit = ConsoleAuditLog(self.storage.path(self.assessment.assessment_id, "audit", "audit.jsonl"))
        audit.verify()
        events = [json.loads(line) for line in audit.path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(sum(row["eventType"] == "submission_accepted" for row in events), 3)
        self.assertEqual(sum(row["details"].get("repeatEndpoint", False) for row in events
                             if row["eventType"] == "submission_accepted"), 1)
        staged = [row for row in events if row["eventType"] == "submission_quarantined"]
        self.assertEqual(len(staged), 3)
        self.assertTrue(all(row["details"]["stage"] == "IMMUTABLE_STAGING" for row in staged))
        from csa_lab.unified_report import _safe_audit_events
        original_hash = audit.final_hash()
        displayed = _safe_audit_events(audit.path)
        self.assertEqual(sum("CSA immutable staging before validation" in row["displayEvent"] for row in displayed), 3)
        self.assertEqual(audit.final_hash(), original_hash)
