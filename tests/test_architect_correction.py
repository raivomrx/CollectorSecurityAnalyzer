"""5.6.8.1: distribution authorization and report evidence corrections."""
import hashlib
import errno
import secrets
import socket
import ssl
import threading
import time
from pathlib import Path
from unittest import mock
import requests

from csa_console.distribution import DistributionPolicy, DistributionState
from csa_console.portal import PortalBinding
from csa_console.server import ConsoleHttpsServer
from csa_console.trusted_grants import TrustedGrantStore
from csa_lab.unified_report import _verification_for_finding
from tests import test_console_sprint5


class DistributionBoundaryTests(test_console_sprint5.Sprint5TestCase):
    def start_portal(self, policy=DistributionPolicy(), *, analyze=False):
        root = Path(self.temporary.name)
        collector, script = root / "collector.exe", root / "collector.zip"
        collector.write_bytes(b"development fixture")
        script.write_bytes(b"development fixture zip")
        code, credential = "ABCD-EFGH", "synthetic-download-only-fixture"
        portal = PortalBinding(self.assessment.assessment_id, self.session.session_id,
            hashlib.sha256(code.encode()).hexdigest(), collector, self.session.expires_at, 20, self.storage,
            script_collector_path=script, launcher_bytes=b"# development fixture",
            launcher_token_hash=hashlib.sha256(credential.encode()).hexdigest(), distribution_policy=policy)
        server = ConsoleHttpsServer(self.assessment.assessment_id, self.session.session_id, self.storage,
                                   analyze_automatically=analyze, portal=portal)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def stop():
            server.shutdown()
            thread.join(timeout=5)
        self.addCleanup(stop)
        return f"https://{server.address[0]}:{server.address[1]}", code, credential

    def test_hold_blocks_every_legacy_handler_and_browser_flags(self):
        origin, code, credential = self.start_portal()
        for route in ("download", "download-powershell", "download-launcher"):
            response = requests.get(f"{origin}/join/{code}/{route}?development=true&state=RELEASE_APPROVED",
                                    verify=self.session.tls_certificate_path, timeout=5)
            self.assertEqual(response.status_code, 403)
            self.assertEqual(response.json()["error"], "TRUST_NOT_ESTABLISHED")
        response = requests.post(origin + "/api/v1/collector-package", headers={"Authorization": "CSA-Launcher " + credential},
                                 verify=self.session.tls_certificate_path, timeout=5)
        self.assertEqual(response.status_code, 403)
        page = requests.get(f"{origin}/join/{code}/", verify=self.session.tls_certificate_path, timeout=5).text
        self.assertNotIn('href="download"', page)
        self.assertNotIn("Default/Home", page)
        self.assertIn("Quick Run – ExecutionPolicy Bypass", page)
        self.assertIn("TRUST_NOT_ESTABLISHED", page)

    def test_explicit_restricted_development_is_functional_and_labelled(self):
        origin, code, _ = self.start_portal(DistributionPolicy(DistributionState.DEVELOPMENT_UNSIGNED, ("127.0.0.1",)))
        response = requests.get(f"{origin}/join/{code}/download", verify=self.session.tls_certificate_path, timeout=5)
        self.assertEqual(response.status_code, 200)
        page = requests.get(f"{origin}/join/{code}/", verify=self.session.tls_certificate_path, timeout=5).text
        self.assertIn("Restricted assessor development only", page)
        self.assertIn("UNSIGNED LAB ONLY", page)
        self.assertNotIn("Recommended", page)

    def test_session_claim_cannot_approve_customer_distribution(self):
        for state in ("PILOT_APPROVED", "RELEASE_APPROVED", "TEST_ONLY"):
            self.session.report_configuration["distribution"] = {"mode": state, "assessorOnly": True,
                                                                 "allowedSources": ["127.0.0.1"]}
            policy = DistributionPolicy.from_session(self.session)
            self.assertEqual(policy.state, DistributionState.TRUST_ENROLLMENT_PENDING)
        for state in DistributionState:
            if state != DistributionState.DEVELOPMENT_UNSIGNED:
                with self.assertRaisesRegex(ValueError, "TRUST_NOT_ESTABLISHED"):
                    DistributionPolicy(state, ("127.0.0.1",)).require_legacy("127.0.0.1")

    def test_correlations_do_not_reflect_request_data_or_tokens(self):
        origin, _, _ = self.start_portal()
        marker = "SECRET-SYNTHETIC-LOG-INJECTION"
        context = ssl.create_default_context(cafile=self.session.tls_certificate_path)
        host, port = origin.removeprefix("https://").rsplit(":", 1)
        with self.assertLogs("csa_console.server") as logs:
            with socket.create_connection((host, int(port)), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname=host) as stream:
                    stream.sendall(f"GET /{marker} BAD-HTTP-VERSION\r\nHost: ignored\r\n\r\n".encode("ascii"))
                    response = stream.makefile("rb")
                    with response:
                        bad = response.read().decode("utf-8")
            missing = requests.post(origin+"/api/v1/nonce", json={"submissionId": "SUB-FIXTURE"},
                                    verify=self.session.tls_certificate_path, timeout=5)
            invalid = requests.post(origin+"/api/v1/nonce", json={"submissionId": "SUB-FIXTURE"},
                                    headers={"Authorization": "CSA-Enrollment "+marker},
                                    verify=self.session.tls_certificate_path, timeout=5)
        self.assertEqual((missing.status_code, invalid.status_code), (400, 403))
        self.assertIn("HTTP_REQUEST_REJECTED", bad)
        audit = self.storage.path(self.assessment.assessment_id, "audit", "audit.jsonl").read_text("utf-8")
        combined = "\n".join(logs.output)
        for response in (missing, invalid):
            correlation = response.headers["X-CSA-Correlation-ID"]
            self.assertEqual(response.json()["correlationId"], correlation)
            self.assertIn(correlation, audit)
            self.assertIn(correlation, combined)
            self.assertEqual(response.headers["X-CSA-Event-Class"], "REJECTED")
        self.assertNotIn(marker, bad + combined + audit + missing.text + invalid.text)

    def test_accepted_evidence_with_analysis_failure_remains_accepted(self):
        origin, _, _ = self.start_portal(analyze=True)
        submission = "SUB-POST-ACCEPTANCE-FIXTURE"
        verify = self.session.tls_certificate_path
        auth = {"Authorization": "CSA-Enrollment " + self.token}
        nonce = requests.post(origin+"/api/v1/nonce", json={"submissionId": submission},
                              headers=auth, verify=verify, timeout=5).json()["nonce"]
        archive = self.package(submission, nonce).read_bytes()
        headers = {**auth, "X-CSA-Nonce": nonce, "Content-Type": "application/zip"}
        with mock.patch("csa_console.pipeline.ConsoleAnalysisPipeline.analyze", side_effect=RuntimeError("UNSAFE SYNTHETIC DETAIL")):
            response = requests.post(origin+"/api/v1/submissions/"+submission,
                                     data=archive, headers=headers, verify=verify, timeout=10)
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.json()["validationStatus"], "ACCEPTED")
        self.assertEqual(response.json()["analysisState"], "FAILED")
        self.assertEqual(response.headers["X-CSA-Event-Class"], "ACCEPTED_ANALYSIS_FAILED")
        audit = self.storage.path(self.assessment.assessment_id, "audit", "audit.jsonl").read_text("utf-8")
        for value in (response.headers["X-CSA-Correlation-ID"], "submission_quarantined", "post_acceptance_analysis_failed"):
            self.assertIn(value, audit)
        self.assertNotIn("UNSAFE SYNTHETIC DETAIL", audit + response.text)
        self.assertTrue(self.storage.path(self.assessment.assessment_id, "submissions", "accepted", submission+".csa.zip").is_file())
        from csa_console.integrity import verify_recorded_evidence
        from csa_console.receipts import sign_receipt
        from csa_console.submission import SubmissionService
        assessment = self.assessment.assessment_id
        analyses = [{"submissionId": submission, "sessionId": self.session.session_id}]
        index = SubmissionService(self.storage).list_submissions(assessment)
        self.assertEqual(verify_recorded_evidence(self.storage, assessment, analyses, index)["publisherAuthenticity"], "NOT_EVALUATED")
        fabricated = {"objectType": "CSA_SUBMISSION_TRUST_RECEIPT", "schemaVersion": 1, "assurance": "REAL",
                      "submissionId": submission, "publisherProvenance": "VERIFIED_AUTHORIZED_PROVENANCE"}
        fabricated["serverSignature"] = sign_receipt(fabricated, self.session.tls_private_key_path)
        self.storage.write_json(assessment, ("submissions", "accepted", submission+".trust.json"), fabricated)
        proof = verify_recorded_evidence(self.storage, assessment, analyses, index)
        self.assertEqual(proof["publisherAuthenticity"], "NOT_VERIFIED")
        self.assertEqual(proof["signedReceiptIntegrity"], "VERIFIED")


class IssuanceRecoveryTests(test_console_sprint5.Sprint5TestCase):
    def setUp(self):
        super().setUp()
        self.grants = TrustedGrantStore(self.storage)

    def envelope(self):
        return {"assessmentId": self.session.assessment_id, "sessionId": self.session.session_id,
                "envelopeId": secrets.token_urlsafe(24), "nonce": secrets.token_urlsafe(24),
                "recipientId": "ENDPOINT-FIXTURE-0001", "expiresAt": int(time.time()) + 300}

    def test_ledger_only_interruption_duplicate_and_consumed_row_recovery(self):
        ready, interrupted, missing = (self.envelope() for _ in range(3))
        self.grants.issue(self.session, ready)
        self.grants.consume(self.session, ready["envelopeId"], ready["nonce"], "SUB-FIXTURE", "HTTPS")
        self.grants.begin_issue(self.session, interrupted)
        self.grants.issue(self.session, missing, bundle_path=Path(self.temporary.name) / "missing-bundle")
        with self.assertRaisesRegex(ValueError, "CSA-TRUST-REPLAY"):
            self.grants.issue(self.session, ready)
        for denied in (interrupted,):
            with self.assertRaisesRegex(ValueError, "CSA-TRUST-SESSION"):
                self.grants.consume(self.session, denied["envelopeId"], denied["nonce"], "SUB-FIXTURE", "HTTPS")
        outcome = self.grants.reconcile(self.session)
        self.assertEqual(outcome["action"], "ISSUE_NEW_ENVELOPE")
        self.assertFalse(outcome["legacyFallbackAllowed"])
        rows = {row["envelopeId"]: row for row in outcome["items"]}
        self.assertEqual(rows[ready["envelopeId"]]["used"], 1)
        self.assertEqual(rows[interrupted["envelopeId"]]["reasonCode"], "CSA-TRUST-ISSUANCE-INTERRUPTED")
        self.assertEqual(rows[missing["envelopeId"]]["reasonCode"], "CSA-TRUST-PUBLICATION-MISSING")
        with self.assertRaisesRegex(ValueError, "CSA-TRUST-REPLAY"):
            self.grants.consume(self.session, ready["envelopeId"], ready["nonce"], "SUB-FIXTURE", "HTTPS")
        fresh = self.envelope()
        self.grants.issue(self.session, fresh)
        self.grants.consume(self.session, fresh["envelopeId"], fresh["nonce"], "SUB-NEW", "HTTPS")

    def test_disk_full_session_write_and_audit_failure_never_activate(self):
        for target, error in (("csa_console.sessions.AssessmentSessionService._write_session", OSError(errno.ENOSPC, "fixture")),
                              ("csa_console.audit.ConsoleAuditLog.append", OSError("fixture"))):
            envelope = self.envelope()
            with mock.patch(target, side_effect=error), self.assertRaises(OSError):
                self.grants.issue(self.session, envelope)
            with self.assertRaisesRegex(ValueError, "CSA-TRUST-SESSION"):
                self.grants.record(self.session, envelope["envelopeId"])
        self.assertTrue(self.grants.required(self.session))
        self.assertTrue(all(row["operationState"] == "FAILED" for row in self.grants.reconcile(self.session)["items"]))

    def test_session_only_configuration_cannot_authorize_a_missing_grant(self):
        self.session.report_configuration["trustedEnvelopeRequired"] = True
        self.grants.sessions._write_session(self.session)
        self.assertTrue(self.grants.required(self.session))
        self.assertFalse(self.grants._path(self.session).exists())
        with self.assertRaisesRegex(ValueError, "CSA-TRUST-SESSION"):
            self.grants.record(self.session, self.envelope()["envelopeId"])
        result = self.grants.reconcile(self.session)
        self.assertEqual(result["items"], [])
        self.assertFalse(result["legacyFallbackAllowed"])


class GuidanceBoundaryTests(test_console_sprint5.Sprint5TestCase):
    def test_incomplete_evidence_does_not_promise_pass_or_configuration_failure(self):
        for status in ("NOT_EVALUATED", "PARTIAL", "ERROR", "UNKNOWN"):
            result = _verification_for_finding({"ruleId": "DEF-004", "status": status})
            self.assertIn("evidence source", result)
            self.assertIn("permissions", result)
            self.assertNotIn("PASS", result)
            self.assertNotIn("configuration change", result)
        for status in ("FAIL", "WARN", "WARNING"):
            result = _verification_for_finding({"ruleId": "DEF-004", "status": status})
            self.assertIn("configuration change", result)
            self.assertIn("independently", result)

    def test_report_mixed_legacy_real_test_only_and_tamper_do_not_all_become_verified(self):
        from csa_console.integrity import _trust_summary
        states = lambda *values: [{"publisher": value} for value in values]
        self.assertEqual(_trust_summary(states("NOT_EVALUATED"), "publisher"), "NOT_EVALUATED")
        self.assertEqual(_trust_summary(states("TEST_ONLY", "NOT_EVALUATED"), "publisher"), "TEST_ONLY")
        self.assertEqual(_trust_summary(states("VERIFIED_AUTHORIZED_PROVENANCE", "NOT_EVALUATED"), "publisher"), "PARTIAL")
        self.assertEqual(_trust_summary(states("VERIFIED_AUTHORIZED_PROVENANCE", "NOT_VERIFIED"), "publisher"), "NOT_VERIFIED")
