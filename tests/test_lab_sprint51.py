"""Sprint 5.1 CSA Lab, portal, Collector and unified-report tests."""

from __future__ import annotations

import hashlib
import json
import socket
import tempfile
import threading
import unittest
from unittest import mock
import zipfile
from datetime import timedelta
from pathlib import Path
from urllib.parse import urljoin

import requests

from csa_console.archive import verify_assessment_archive
from csa_console.canonical import write_canonical_json
from csa_console.enums import SessionStatus
from csa_console.fleet import FleetAnalyzer
from csa_console.identifiers import utc_now, utc_text
from csa_console.pipeline import ConsoleAnalysisPipeline
from csa_console.portal import PortalBinding
from csa_console.serde import model_to_dict
from csa_console.sessions import AssessmentSessionService
from csa_console.storage import AssessmentStorage
from csa_console.submission import SubmissionService
from csa_lab.collector_executable import (
    build_bound_collector,
    read_bound_collector_payload,
)
from csa_lab.firewall import NullFirewallManager, validate_firewall_spec
from csa_lab.models import (
    AssessmentWizardRequest,
    EndpointDashboardItem,
    EndpointUiStatus,
    FirewallRuleSpec,
    LabAssessmentState,
    LabAssessmentStatus,
    NetworkInterface,
)
from csa_lab.network import select_default_interface
from csa_lab.service import LabApplicationService
from csa_lab.unified_report import UnifiedReportGenerator, _transport_label
from csa_lab.web import LabAdminServer
from tests.test_console_sprint5 import Sprint5TestCase

ROOT = Path(__file__).resolve().parents[1]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as value:
        value.bind(("127.0.0.1", 0))
        return int(value.getsockname()[1])


class LabUiContractTests(unittest.TestCase):
    """Verify durable browser-side assessment workflow contracts."""

    def test_create_assessment_retains_form_across_async_request(self) -> None:
        script = (ROOT / "csa_lab" / "templates" / "lab.js").read_text(
            encoding="utf-8"
        )

        self.assertIn("const formElement = event.currentTarget;", script)
        self.assertIn("formElement.reset();", script)
        self.assertNotIn("event.currentTarget.reset()", script)

    def test_report_requires_stopped_collection_and_completed_analysis(
        self,
    ) -> None:
        script = (ROOT / "csa_lab" / "templates" / "lab.js").read_text(
            encoding="utf-8"
        )

        self.assertIn('item.status === "COMPLETE"', script)
        self.assertIn('"READY_FOR_REPORT", "COMPLETED"', script)
        self.assertIn("cveAnalysisStatus", script)
        self.assertIn("Run CVE Analysis", (
            ROOT / "csa_lab" / "templates" / "lab.html"
        ).read_text(encoding="utf-8"))
        self.assertIn("Generate without CVE data", (
            ROOT / "csa_lab" / "templates" / "lab.html"
        ).read_text(encoding="utf-8"))
        self.assertEqual(
            _transport_label("OFFLINE_ENCRYPTED"),
            "Encrypted offline import",
        )

    def test_terminal_assessments_are_explicitly_deletable(self) -> None:
        script = (ROOT / "csa_lab" / "templates" / "lab.js").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            '["DRAFT", "CLOSED", "COMPLETED"].includes(status)',
            script,
        )
        self.assertIn(
            "its evidence, reports, and local audit history",
            script,
        )

    def test_packaged_lab_includes_default_policy_profile(self) -> None:
        specification = (ROOT / "packaging" / "csa-lab.spec").read_text(
            encoding="utf-8"
        )
        workflow = (
            ROOT / ".github" / "workflows" / "csa-lab-build.yml"
        ).read_text(encoding="utf-8")

        self.assertIn('(str(ROOT / "policies"), "policies")', specification)
        self.assertIn(
            "policies/windows_endpoint_default.json",
            workflow,
        )


class LabServiceTests(unittest.TestCase):
    """Verify wizard, lifecycle, portal and recovery behavior."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bootstrap = self.root / "CSA-Collector-bootstrap.exe"
        self.bootstrap.write_bytes(b"MZ" + bytes(range(128)))
        self.firewall = NullFirewallManager()
        self.service = LabApplicationService(
            self.root / "assessments",
            firewall=self.firewall,
            collector_bootstrap=self.bootstrap,
            executable_path=Path(__file__).resolve(),
        )
        self.addCleanup(self.service.shutdown)

    def request(self, **changes: object) -> AssessmentWizardRequest:
        values = {
            "name": "Windows 11 Lab",
            "expected_endpoints": 1,
            "organization": "Example",
            "source_subnet": "127.0.0.0/8",
            "network_profile": "Private",
            "listener_address": "127.0.0.1",
            "listener_port": _free_port(),
        }
        values.update(changes)
        return AssessmentWizardRequest(**values)

    def test_wizard_defaults_and_validation(self) -> None:
        request = self.request(expected_endpoints=13)
        request.validate()
        self.assertEqual(request.collection_profile, "windows-standard-v1")
        self.assertEqual(request.session_expiry_hours, 2)
        self.assertEqual(request.allowed_submissions, 20)
        self.assertTrue(request.offline_collection)
        self.assertFalse(request.active_validation)
        with self.assertRaises(ValueError):
            self.request(name="").validate()
        with self.assertRaises(ValueError):
            self.request(active_validation=True).validate()

    def test_interface_selection_prefers_physical_private_network(self) -> None:
        interfaces = [
            NetworkInterface(
                "2", "vEthernet", "192.168.20.1", "192.168.20.0/24",
                "Private", "Hyper-V", True, True, False, False
            ),
            NetworkInterface(
                "1", "Ethernet", "192.168.10.20", "192.168.10.0/24",
                "Private", "Intel Ethernet", True, False, False, True
            ),
            NetworkInterface(
                "3", "VPN", "10.9.0.2", "10.9.0.0/24",
                "Public", "WireGuard", True, False, True, False
            ),
        ]
        self.assertEqual(select_default_interface(interfaces).name, "Ethernet")

    def test_create_assessment_hides_secret_and_builds_bound_collector(self) -> None:
        state = self.service.create_assessment(self.request())
        collector = Path(state.collector_path)
        self.assertTrue(collector.is_file())
        payload = read_bound_collector_payload(collector)
        self.assertTrue(payload.startswith(b"PK"))
        session_text = self.service.storage.path(
            state.assessment_id,
            "sessions",
            f"{state.session_id}.json",
        ).read_text(encoding="utf-8")
        package_config = self.service.storage.path(
            state.assessment_id,
            "downloads",
            state.session_id,
            "package",
            "session-config.json",
        ).read_text(encoding="utf-8")
        token = json.loads(package_config)["enrollmentToken"]
        self.assertNotIn(token, session_text)
        self.assertNotIn(token, json.dumps(model_to_dict(state)))
        self.assertEqual(len(self.service.join_code(state.assessment_id)), 24)

    def test_empty_draft_can_be_deleted_without_leaving_session_state(
        self,
    ) -> None:
        state = self.service.create_assessment(self.request())
        assessment_path = self.service.storage.assessment_path(
            state.assessment_id
        )

        self.service.delete_draft_assessment(state.assessment_id)

        self.assertFalse(assessment_path.exists())
        self.assertEqual(self.service.list_assessments(), [])
        application_audit = (
            self.service.storage.root.parent
            / "audit"
            / "application.jsonl"
        ).read_text(encoding="utf-8")
        self.assertIn("assessment_deleted", application_audit)

    def test_non_draft_assessment_cannot_be_deleted(self) -> None:
        state = self.service.create_assessment(self.request())
        self.service.start_collection(state.assessment_id)

        with self.assertRaisesRegex(ValueError, "Only an empty draft"):
            self.service.delete_draft_assessment(state.assessment_id)

    def test_completed_assessment_and_local_evidence_can_be_deleted(
        self,
    ) -> None:
        state = self.service.create_assessment(self.request())
        state.status = LabAssessmentStatus.COMPLETED
        state.report_path = str(
            self.service.storage.path(
                state.assessment_id, "reports", "assessment.html"
            )
        )
        self.service.storage.path(
            state.assessment_id, "reports"
        ).mkdir(parents=True, exist_ok=True)
        Path(state.report_path).write_text("report", encoding="utf-8")
        self.service._write_state(state)

        self.service.delete_assessment(state.assessment_id)

        self.assertFalse(
            self.service.storage.assessment_path(
                state.assessment_id
            ).exists()
        )
        application_audit = (
            self.service.storage.root.parent
            / "audit"
            / "application.jsonl"
        ).read_text(encoding="utf-8")
        self.assertIn('"status":"COMPLETED"', application_audit)

    def test_closed_assessment_can_be_deleted(self) -> None:
        state = self.service.create_assessment(self.request())
        state.status = LabAssessmentStatus.CLOSED
        self.service._write_state(state)

        self.service.delete_assessment(state.assessment_id)

        self.assertFalse(
            self.service.storage.assessment_path(
                state.assessment_id
            ).exists()
        )

    def test_active_assessment_cannot_be_deleted(self) -> None:
        state = self.service.create_assessment(self.request())
        self.service.start_collection(state.assessment_id)

        with self.assertRaisesRegex(
            ValueError, "draft, closed, or completed"
        ):
            self.service.delete_assessment(state.assessment_id)

    def test_terminal_assessment_with_firewall_access_cannot_be_deleted(
        self,
    ) -> None:
        state = self.service.create_assessment(self.request())
        state.status = LabAssessmentStatus.CLOSED
        self.service._write_state(state)
        self.firewall.create(
            FirewallRuleSpec(
                rule_name=state.firewall_rule_name,
                program_path=str(Path(__file__).resolve()),
                local_address=state.listener_address,
                local_port=state.listener_port,
                remote_subnet=state.source_subnet,
                profile=state.network_profile,
            )
        )

        with self.assertRaisesRegex(
            ValueError, "network access must be cleaned up"
        ):
            self.service.delete_assessment(state.assessment_id)

    def test_encrypted_assessment_archive_export_is_verifiable(self) -> None:
        state = self.service.create_assessment(self.request())
        output = self.service.export_archive(
            state.assessment_id,
            "correct horse battery staple",
        )
        self.assertTrue(output.is_file())
        verified = verify_assessment_archive(
            output,
            "correct horse battery staple",
        )
        self.assertEqual(verified["assessmentId"], state.assessment_id)

    def test_report_rejects_active_collection(self) -> None:
        state = self.service.create_assessment(self.request())
        self.service.start_collection(state.assessment_id)

        with self.assertRaisesRegex(
            ValueError, "Stop collection before generating"
        ):
            self.service.generate_unified_report(state.assessment_id)

    def test_report_rejects_failed_endpoint_analysis(self) -> None:
        state = self.service.create_assessment(self.request())
        state.status = LabAssessmentStatus.READY_FOR_REPORT
        self.service._write_state(state)
        failed = EndpointDashboardItem(
            device_id="DEVICE-ERROR",
            submission_id="SUB-ERROR",
            status=EndpointUiStatus.ERROR,
            transport="HTTPS",
            coverage_percent=None,
            finding_count=None,
            received_at=utc_text(),
            collector_version="PENDING",
            execution_mode="PENDING",
            integrity_level="PENDING",
            is_elevated=False,
            local_administrator_member=None,
            receipt_status="VERIFIED",
            evidence_digest="a" * 64,
        )

        with mock.patch.object(
            self.service, "dashboard", return_value=[failed]
        ):
            with self.assertRaisesRegex(
                ValueError, "completed endpoint analysis"
            ):
                self.service.generate_unified_report(state.assessment_id)

    def test_diagnostic_bundle_is_sanitized_and_contains_no_evidence(self) -> None:
        state = self.service.create_assessment(self.request())
        log_root = self.service.storage.root.parent / "logs"
        log_root.mkdir(parents=True)
        (log_root / "csa-lab.log").write_text(
            "token=unsafe 192.168.10.55 C:\\Users\\Alice\\secret.txt",
            encoding="utf-8",
        )
        output = self.service.export_diagnostic_bundle()
        with zipfile.ZipFile(output) as archive:
            names = archive.namelist()
            self.assertEqual(
                names,
                ["diagnostic-summary.json", "logs/csa-lab.log"],
            )
            combined = b"\n".join(archive.read(name) for name in names)
        self.assertNotIn(b"unsafe", combined)
        self.assertNotIn(b"192.168.10.55", combined)
        self.assertNotIn(b"C:\\Users\\Alice", combined)
        self.assertNotIn(state.assessment_id.encode("utf-8"), combined)
        self.assertNotIn(b"evidence", b"\n".join(name.encode() for name in names))

    def test_collection_lifecycle_and_portal_security(self) -> None:
        state = self.service.create_assessment(self.request())
        state = self.service.start_collection(state.assessment_id)
        self.assertEqual(state.status, LabAssessmentStatus.COLLECTING)
        self.assertTrue(self.firewall.exists(state.firewall_rule_name))
        session = self.service.sessions.load_session(
            state.assessment_id, state.session_id
        )
        url = self.service.portal_url(state.assessment_id)
        self.assertTrue(url.endswith("/"))
        noncanonical = requests.get(
            url.rstrip("/"),
            verify=session.tls_certificate_path,
            timeout=5,
            allow_redirects=False,
        )
        self.assertEqual(noncanonical.status_code, 308)
        canonical_path = url[url.index("/", 8) :]
        self.assertEqual(noncanonical.headers["Location"], canonical_path)
        response = requests.get(
            url,
            verify=session.tls_certificate_path,
            timeout=5,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Download CSA Collector", response.text)
        self.assertIn('href="download"', response.text)
        self.assertNotIn("enrollmentToken", response.text)
        unavailable = requests.get(
            (
                f"https://127.0.0.1:{state.listener_port}/join/"
                "INVALID-ASSESSMENT-LINK/"
            ),
            verify=session.tls_certificate_path,
            timeout=5,
        )
        self.assertEqual(unavailable.status_code, 410)
        self.assertIn("Collector page unavailable", unavailable.text)
        self.assertIn("Copy Collector Page", unavailable.text)
        self.assertNotIn("PORTAL_UNAVAILABLE", unavailable.text)
        download = requests.get(
            urljoin(response.url, "download"),
            verify=session.tls_certificate_path,
            timeout=5,
        )
        self.assertEqual(download.status_code, 200)
        expected_collector = Path(state.collector_path).read_bytes()
        self.assertEqual(download.content, expected_collector)
        self.assertIn(
            'filename="CSA-Collector.exe"',
            download.headers["Content-Disposition"],
        )
        self.assertEqual(
            self.service.load_state(state.assessment_id).download_count,
            1,
        )
        admin = requests.get(
            f"https://127.0.0.1:{state.listener_port}/api/v1/assessments",
            verify=session.tls_certificate_path,
            timeout=5,
        )
        self.assertEqual(admin.status_code, 404)
        traversal = requests.get(
            f"{url}/%2e%2e/reports",
            verify=session.tls_certificate_path,
            timeout=5,
        )
        self.assertNotEqual(traversal.status_code, 200)
        state = self.service.pause_collection(state.assessment_id)
        self.assertEqual(state.status, LabAssessmentStatus.PAUSED)
        self.assertFalse(self.firewall.exists(state.firewall_rule_name))
        state = self.service.resume_collection(state.assessment_id)
        self.assertEqual(state.status, LabAssessmentStatus.COLLECTING)
        state = self.service.stop_collection(state.assessment_id)
        self.assertEqual(state.status, LabAssessmentStatus.CLOSED)
        self.assertFalse(self.firewall.exists(state.firewall_rule_name))
        self.assertEqual(
            self.service.sessions.load_session(
                state.assessment_id, state.session_id
            ).status,
            SessionStatus.CLOSED,
        )

    def test_download_limit_expiry_and_session_close_invalidate_portal(self) -> None:
        state = self.service.create_assessment(self.request())
        code = self.service.join_code(state.assessment_id)
        binding = PortalBinding(
            assessment_id=state.assessment_id,
            session_id=state.session_id,
            join_code_hash=hashlib.sha256(code.encode()).hexdigest(),
            collector_path=Path(state.collector_path),
            expires_at=state.expires_at,
            maximum_downloads=1,
            storage=self.service.storage,
        )
        self.assertTrue(binding.authorize(code, "127.0.0.1"))
        self.assertFalse(binding.authorize("wrong", "127.0.0.1"))
        binding.record_download("127.0.0.1")
        self.assertFalse(binding.authorize(code, "127.0.0.1"))
        binding.download_count = 0
        binding.expires_at = utc_text(utc_now() - timedelta(seconds=1))
        self.assertFalse(binding.authorize(code, "127.0.0.1"))
        binding.expires_at = state.expires_at
        self.service.sessions.set_session_status(
            state.assessment_id, state.session_id, SessionStatus.CLOSED
        )
        self.assertFalse(binding.authorize(code, "127.0.0.1"))

    def test_firewall_spec_rejects_broad_access_and_cleanup_is_exact(self) -> None:
        valid = FirewallRuleSpec(
            rule_name="CSA Lab Temporary TEST",
            program_path=str(Path(__file__).resolve()),
            local_address="192.168.10.5",
            local_port=8443,
            remote_subnet="192.168.10.0/24",
            profile="Private",
        )
        validate_firewall_spec(valid)
        self.firewall.create(valid)
        self.assertTrue(self.firewall.exists(valid.rule_name))
        self.firewall.remove(valid.rule_name)
        self.assertFalse(self.firewall.exists(valid.rule_name))
        for change in (
            {"local_address": "0.0.0.0"},
            {"remote_subnet": "0.0.0.0/0"},
            {"profile": "Public"},
        ):
            data = model_to_dict(valid)
            mapping = {
                "local_address": "localAddress",
                "remote_subnet": "remoteSubnet",
                "profile": "profile",
            }
            key, value = next(iter(change.items()))
            data[mapping[key]] = value
            with self.assertRaises(ValueError):
                validate_firewall_spec(
                    FirewallRuleSpec(
                        rule_name=data["ruleName"],
                        program_path=data["programPath"],
                        local_address=data["localAddress"],
                        local_port=data["localPort"],
                        remote_subnet=data["remoteSubnet"],
                        profile=data["profile"],
                    )
                )

    def test_crash_recovery_retains_evidence_and_removes_access(self) -> None:
        state = self.service.create_assessment(self.request())
        self.service.start_collection(state.assessment_id)
        server = self.service._servers.pop(state.assessment_id)
        thread = self.service._threads.pop(state.assessment_id)
        server.shutdown()
        thread.join(timeout=5)
        self.assertTrue(self.firewall.exists(state.firewall_rule_name))
        recovered_service = LabApplicationService(
            self.root / "assessments",
            firewall=self.firewall,
            collector_bootstrap=self.bootstrap,
            executable_path=Path(__file__).resolve(),
        )
        self.addCleanup(recovered_service.shutdown)
        recovered = recovered_service.load_state(state.assessment_id)
        self.assertEqual(
            recovered.status, LabAssessmentStatus.RECOVERY_REQUIRED
        )
        cleaned = recovered_service.cleanup_recovery(state.assessment_id)
        self.assertEqual(cleaned.status, LabAssessmentStatus.CLOSED)
        self.assertFalse(self.firewall.exists(state.firewall_rule_name))
        self.assertEqual(
            recovered_service.audit_status(state.assessment_id)[
                "auditVerificationStatus"
            ],
            "VERIFIED",
        )

    def test_local_admin_server_binds_loopback_and_requires_csrf(self) -> None:
        admin = LabAdminServer(
            self.service, port=0, browser_timeout_seconds=120
        )
        thread = threading.Thread(
            target=admin.server.serve_forever, daemon=True
        )
        thread.start()
        self.addCleanup(admin.server.shutdown)
        self.addCleanup(admin.server.server_close)
        self.assertEqual(admin.server.server_address[0], "127.0.0.1")
        page = requests.get(admin.url, timeout=5)
        self.assertEqual(page.status_code, 200)
        self.assertIn("Content-Security-Policy", page.headers)
        rejected = requests.post(
            admin.url + "api/v1/assessments",
            json={"name": "Blocked"},
            timeout=5,
        )
        self.assertEqual(rejected.status_code, 403)
        admin.server.shutdown()
        thread.join(timeout=5)
        admin.server.server_close()


class CollectorExecutableTests(unittest.TestCase):
    """Verify deterministic package overlay boundaries."""

    def test_bound_collector_detects_payload_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bootstrap = root / "bootstrap.exe"
            bootstrap.write_bytes(b"MZ" + bytes(200))
            package = root / "package"
            package.mkdir()
            (package / "trusted-manifest.json").write_text(
                "{}", encoding="utf-8"
            )
            (package / "file.txt").write_text("evidence", encoding="utf-8")
            output = build_bound_collector(
                bootstrap, package, root / "CSA-Collector.exe"
            )
            self.assertTrue(read_bound_collector_payload(output).startswith(b"PK"))
            raw = bytearray(output.read_bytes())
            raw[-60] ^= 1
            output.write_bytes(raw)
            with self.assertRaises(ValueError):
                read_bound_collector_payload(output)


class UnifiedReportTests(Sprint5TestCase):
    """Verify the one-file report and 13-endpoint synthetic flow."""

    def _accept_and_analyze(self, submission_id: str) -> None:
        service = SubmissionService(self.storage)
        nonce = service.request_nonce(
            self.assessment.assessment_id,
            self.session.session_id,
            submission_id,
            self.token,
            "127.0.0.1",
        )
        _receipt, package, _path = service.accept(
            assessment_id=self.assessment.assessment_id,
            session_id=self.session.session_id,
            submission_id=submission_id,
            enrollment_token=self.token,
            nonce=nonce,
            source_address="127.0.0.1",
            archive_bytes=self.package(
                submission_id, nonce, f"{submission_id}.zip"
            ).read_bytes(),
        )
        ConsoleAnalysisPipeline(self.storage).analyze(package)

    def _write_lab_state(self, expected: int) -> None:
        write_canonical_json(
            self.storage.path(
                self.assessment.assessment_id, "lab-state.json"
            ),
            model_to_dict(
                LabAssessmentState(
                    assessment_id=self.assessment.assessment_id,
                    session_id=self.session.session_id,
                    name="Synthetic Windows Fleet",
                    organization="Example",
                    reference_number="SYNTH-13",
                    assessor_notes="",
                    description="Synthetic report acceptance flow",
                    created_at=self.assessment.created_at,
                    expected_endpoints=expected,
                    listener_address="127.0.0.1",
                    listener_port=8443,
                    source_subnet="127.0.0.0/8",
                    network_profile="Private",
                    interface_id="loopback-test",
                    status=LabAssessmentStatus.READY_FOR_REPORT,
                    expires_at=self.session.expires_at,
                    offline_collection=True,
                    firewall_rule_name="CSA Lab Temporary SYNTH",
                    collector_path="CSA-Collector.exe",
                )
            ),
        )

    def test_unified_report_is_self_contained_and_complete(self) -> None:
        self._accept_and_analyze("SUB-UNIFIED-01")
        self._write_lab_state(1)
        generator = UnifiedReportGenerator(self.storage)
        first_model = generator.build_model(self.assessment.assessment_id)
        second_model = generator.build_model(self.assessment.assessment_id)
        self.assertEqual(first_model, second_model)
        output = generator.generate(self.assessment.assessment_id)
        html = output.read_text(encoding="utf-8")
        self.assertTrue(output.name.endswith("-CSA-Assessment-Report.html"))
        self.assertEqual(
            len(list(output.parent.glob("*-CSA-Assessment-Report.html"))), 1
        )
        self.assertIn("<style>", html)
        self.assertIn("<script>", html)
        self.assertNotIn("<link ", html)
        self.assertNotIn("<script src=", html)
        self.assertNotIn("file://", html.casefold())
        for anchor in (
            "executive", "scope", "risk", "fleet", "cve", "priority", "systemic",
            "remediation", "comparison", "endpoints", "gaps", "frameworks",
            "evidence", "methodology", "integrity",
        ):
            self.assertIn(f'id="{anchor}"', html)
            self.assertIn(f'href="#{anchor}"', html)
        self.assertIn("<details", html)
        self.assertIn("Standard Privileges Assessment", html)
        self.assertIn("CVE analysis: NOT PERFORMED", html)
        self.assertIn("control results", html)
        self.assertEqual(first_model["endpoints"][0]["displayName"], "Endpoint 01")
        self.assertEqual(
            first_model["coverage"]["corePassiveCoverage"], 100.0
        )
        self.assertNotIn("enrollmentToken", html)
        self.assertNotIn("tokenHash", html)

    def test_report_requires_cve_completion_or_explicit_acknowledgement(
        self,
    ) -> None:
        """Final report generation should gate incomplete CVE analysis."""

        self._accept_and_analyze("SUB-CVE-GATE-01")
        self._write_lab_state(1)
        service = LabApplicationService(
            self.storage.root,
            firewall=NullFirewallManager(),
            executable_path=Path(__file__).resolve(),
        )
        self.addCleanup(service.shutdown)

        with self.assertRaisesRegex(
            ValueError, "CVE analysis is not complete"
        ):
            service.generate_unified_report(
                self.assessment.assessment_id
            )

        output = service.generate_unified_report(
            self.assessment.assessment_id,
            allow_without_cve=True,
        )
        self.assertTrue(output.is_file())
        audit = self.storage.path(
            self.assessment.assessment_id, "audit", "audit.jsonl"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "report_without_complete_cve_acknowledged", audit
        )

    def test_cve_retry_persists_lifecycle_and_distinct_metrics(
        self,
    ) -> None:
        """CVE retry should persist a terminal status and typed counts."""

        submission_id = "SUB-CVE-LIFECYCLE-01"
        self._accept_and_analyze(submission_id)
        existing_report = self.storage.path(
            self.assessment.assessment_id,
            "reports",
            "endpoints",
            f"{submission_id}.html",
        )
        existing_report.parent.mkdir(parents=True, exist_ok=True)
        existing_report.write_text("report", encoding="utf-8")

        def analyze_stub(*_args: object, **kwargs: object):
            metadata = kwargs["analysis_metadata"]
            metadata.update(
                {
                    "status": "COMPLETE",
                    "timestamp": "2026-07-30T10:00:00Z",
                    "installedSoftwareRecords": 4,
                    "normalizedProducts": 3,
                    "cveEligibleProducts": 2,
                    "successfullyEvaluatedProducts": 2,
                    "notEvaluatedProducts": 0,
                    "uniqueCves": 1,
                    "uniqueCveIds": ["CVE-2026-0001"],
                    "confirmedUniqueCves": 1,
                    "confirmedCveIds": ["CVE-2026-0001"],
                    "confirmedProductCveRelationships": 2,
                    "possibleUniqueCves": 0,
                    "possibleCveIds": [],
                    "possibleProductCveRelationships": 0,
                    "criticalUniqueCves": 0,
                    "criticalCveIds": [],
                    "highUniqueCves": 1,
                    "highCveIds": ["CVE-2026-0001"],
                    "cisaKevUniqueCves": 0,
                    "cisaKevCveIds": [],
                    "coveragePercent": 100.0,
                    "providerCoverage": [],
                }
            )
            return [], 100, None, existing_report

        with mock.patch(
            "csa_console.pipeline.analyze_file",
            side_effect=analyze_stub,
        ) as analyze:
            result = ConsoleAnalysisPipeline(
                self.storage
            ).retry_analysis(
                self.assessment.assessment_id,
                submission_id,
                run_cve=True,
            )

        self.assertEqual(result.cve_analysis_status, "COMPLETE")
        self.assertEqual(result.cve_summary["uniqueCves"], 1)
        self.assertEqual(
            result.cve_summary["confirmedProductCveRelationships"], 2
        )
        self.assertFalse(analyze.call_args.kwargs["skip_cve"])
        stored = self.storage.read_json(
            self.assessment.assessment_id,
            "findings",
            f"{submission_id}.json",
        )
        self.assertEqual(stored["cveAnalysisStatus"], "COMPLETE")

    def test_failed_first_analysis_can_be_retried_from_normalized_data(
        self,
    ) -> None:
        submission_id = "SUB-RETRY-01"
        self._accept_and_analyze(submission_id)
        self.storage.path(
            self.assessment.assessment_id,
            "findings",
            f"{submission_id}.json",
        ).unlink()
        SubmissionService(self.storage).update_processing_state(
            self.assessment.assessment_id,
            submission_id,
            "ERROR",
        )

        analysis = ConsoleAnalysisPipeline(self.storage).retry_analysis(
            self.assessment.assessment_id,
            submission_id,
        )

        self.assertGreater(len(analysis.findings), 0)
        index = SubmissionService(self.storage).list_submissions(
            self.assessment.assessment_id
        )
        self.assertEqual(index[0]["processingState"], "COMPLETE")

    def test_thirteen_endpoint_synthetic_flow_generates_one_report(self) -> None:
        for index in range(13):
            self._accept_and_analyze(f"SUB-SYNTH-{index:02d}")
        self._write_lab_state(13)
        fleet = FleetAnalyzer(self.storage).analyze(
            self.assessment.assessment_id
        )
        self.assertEqual(fleet.endpoint_count, 13)
        output = UnifiedReportGenerator(self.storage).generate(
            self.assessment.assessment_id
        )
        model = UnifiedReportGenerator(self.storage).build_model(
            self.assessment.assessment_id
        )
        self.assertEqual(len(model["endpoints"]), 13)
        self.assertEqual(
            len({item["ruleId"] for item in model["findings"]}),
            len(model["findings"]),
        )
        self.assertTrue(output.is_file())


if __name__ == "__main__":
    unittest.main()
