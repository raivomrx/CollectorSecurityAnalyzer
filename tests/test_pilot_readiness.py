"""Pilot preflight is an observation, never a self-approval or unsigned downgrade."""
import json
import threading
import time
from unittest import mock

import requests

from csa_lab.pilot_readiness import inspect_pilot, validate_pilot_authorization, handoff_markdown
from csa_lab.web import LabAdminServer
from csa_console.quick_start import exe_start_command, quick_start_command
from tests import test_collector_launcher as fixture


class PilotPreparationTests(fixture.LauncherCase):
    def setUp(self):
        super().setUp()
        self.create(development=False)

    def test_missing_recipient_or_enrollment_remains_blocked_without_side_effects(self):
        before = self.service.sessions.load_session(self.state.assessment_id, self.state.session_id)
        for recipient, code in (("", "PILOT_RECIPIENT_REQUIRED"), ("ENDPOINT-FIXTURE-0001", "PILOT_PROVISIONING_MISSING")):
            authority = mock.Mock(policy_path=self.root/"missing-policy", approval_path=self.root/"missing-approval")
            with mock.patch("csa_lab.pilot_readiness.NativeTrustAuthority.for_recipient", return_value=authority):
                result = inspect_pilot(self.service, self.state.assessment_id, recipient)
            self.assertEqual(result["diagnosticCode"], code)
            self.assertFalse(result["customerPilotPermitted"])
            self.assertEqual((result["exe"], result["quickRun"]), ("BLOCKED", "BLOCKED"))
            self.assertEqual(len(result["checks"]), 7)
            self.assertIn("PILOT_GO_NO_GO", handoff_markdown(result))
        after = self.service.sessions.load_session(self.state.assessment_id, self.state.session_id)
        self.assertEqual(before.report_configuration, after.report_configuration)
        with self.assertRaises(ValueError):
            inspect_pilot(self.service, self.state.assessment_id, "../outside")

    def test_independent_authorization_has_time_recipient_customer_and_source_scope(self):
        approval = dict(approvedBy="Fixture approver", approvedAt=int(time.time())-1,
            assessorApprovalReference="ASSESSOR-FIXTURE", customerApprovalReference="CUSTOMER-FIXTURE",
            approvedSourceAddresses=["127.0.0.1"], expiresAt=int(time.time())+300,
            assessmentId=self.state.assessment_id, sessionId=self.state.session_id,
            recipientId="ENDPOINT-FIXTURE-0001", tlsFingerprint=self.session.tls_fingerprint)
        validate_pilot_authorization(approval, self.session, approval["recipientId"])
        for key, value in (("approvedBy", "PENDING"), ("customerApprovalReference", ""),
                           ("approvedAt", int(time.time())+100), ("expiresAt", 1),
                           ("recipientId", "OTHER-ENDPOINT"), ("approvedSourceAddresses", ["127.0.0.0/8"]),
                           ("tlsFingerprint", "sha256:"+"0"*64)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_pilot_authorization({**approval, key:value}, self.session, approval["recipientId"])

    def test_local_ui_inspection_and_export_require_csrf_and_cannot_accept_browser_approval(self):
        admin = LabAdminServer(self.service, port=0)
        thread = threading.Thread(target=admin.server.serve_forever, daemon=True); thread.start()
        def close():
            admin.server.shutdown(); thread.join(5); admin.server.server_close()
        self.addCleanup(close)
        endpoint = admin.url+"api/v1/assessments/"+self.state.assessment_id+"/"
        self.assertEqual(requests.post(endpoint+"pilot-readiness", json={}, timeout=5).status_code, 403)
        headers = {"X-CSA-Lab-CSRF": admin.csrf_token}
        result = requests.post(endpoint+"pilot-readiness", json={}, headers=headers, timeout=5)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()["state"], "SETUP_REQUIRED")
        forged = requests.post(endpoint+"pilot-readiness", json={"state":"PILOT_READY"}, headers=headers, timeout=5)
        self.assertEqual(forged.status_code, 400)
        exported = requests.post(endpoint+"pilot-handoff", json={}, headers=headers, timeout=5)
        self.assertEqual(exported.status_code, 200)
        self.assertIn("Customer pilot permitted: False", exported.text)
        self.assertNotIn("enrollmentToken", exported.text)
        audit = self.service.storage.path(self.state.assessment_id, "audit", "audit.jsonl").read_text("utf-8")
        self.assertIn("pilot_readiness_checked", audit)

    def test_commands_support_explicit_exe_and_process_bypass_without_credentials(self):
        native = exe_start_command("LAB-FIXTURE", "ENV-FIXTURE-00000001")
        self.assertTrue(native.startswith('"%ProgramFiles%'))
        for quick in (False, True):
            command = quick_start_command("LAB-FIXTURE", "ENV-FIXTURE-00000001", quick_run=quick)
            self.assertEqual("-ExecutionPolicy Bypass" in command, quick)
            self.assertNotIn("Set-ExecutionPolicy", command)
            self.assertNotIn("enrollment", command.lower())
