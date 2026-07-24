"""Sprint 5.0 Assessment Console security and fleet tests."""

from __future__ import annotations

import json
import io
import stat
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

import requests

from csa_console.archive import (
    AssessmentArchiveError,
    export_assessment_archive,
    verify_assessment_archive,
)
from csa_console.capabilities import CapabilityRegistry, CollectionProfile
from csa_console.collector_package import (
    create_collector_package,
    verify_collector_package,
)
from csa_console.fleet import FleetAnalyzer
from csa_console.offline import (
    OfflineImportError,
    OfflineImportService,
    encrypt_offline_submission,
)
from csa_console.package import (
    EvidencePackageValidator,
    PackageValidationError,
    REQUIRED_FILES,
    build_evidence_package,
)
from csa_console.privacy import SensitiveDataScanner
from csa_console.receipts import verify_receipt
from csa_console.reporting import ConsoleReportGenerator
from csa_console.server import ConsoleHttpsServer
from csa_console.sessions import AssessmentSessionService
from csa_console.storage import AssessmentStorage
from csa_console.submission import SubmissionRejected, SubmissionService
from csa_console.tls import generate_session_certificate

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "canonical_windows_v2.json"


class Sprint5TestCase(unittest.TestCase):
    """Provide isolated assessment and package helpers."""

    def setUp(self) -> None:
        """Create one loopback session with a trusted test build."""

        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.storage = AssessmentStorage(Path(self.temporary.name) / "assessments")
        self.sessions = AssessmentSessionService(self.storage)
        self.assessment = self.sessions.create_assessment(
            "Windows 11 endpoint assessment",
            "CLIENT-TEST",
            assessment_id="CSA-2026-TEST",
        )
        self.session, self.token = self.sessions.open_session(
            self.assessment.assessment_id,
            expected_devices=13,
            allowed_submissions=20,
            listen_address="127.0.0.1",
            listen_port=0,
        )
        self.build_digest = "sha256:" + "a" * 64
        self.sessions.trust_collector_build(self.session, self.build_digest)

    def evidence(self) -> dict:
        """Return valid standard-user fixture evidence."""

        value = json.loads(FIXTURE.read_text(encoding="utf-8"))
        value["collectorVersion"] = "CSA-WINDOWS-COLLECTOR-5.0.0"
        value["collectionMode"] = "STANDARD_USER_COLLECTION"
        value["collectionProfile"] = "windows-standard-v1"
        value["privilegeContext"] = {
            "executionMode": "STANDARD_USER",
            "isElevated": False,
            "isLocalAdministratorMember": False,
            "integrityLevel": "MEDIUM",
            "effectiveUserHash": "sha256:" + "b" * 64,
            "collectionScope": "CURRENT_USER_AND_PUBLIC_MACHINE_STATE",
        }
        value["device"].update(
            {
                "hostname": "id-" + "1" * 12,
                "domain": "id-" + "2" * 12,
                "currentUser": "id-" + "3" * 12,
                "elevated": False,
            }
        )
        for service in value.get("services", {}).get("services", []):
            if isinstance(service, dict) and service.get("ServiceAccount"):
                service["ServiceAccount"] = "id-" + "4" * 12
        for task in value.get("services", {}).get("scheduledTasks", []):
            if isinstance(task, dict) and task.get("Principal"):
                task["Principal"] = "id-" + "5" * 12
        value["capabilityResults"] = self.capability_results()
        value.setdefault("metadata", {})["activeValidation"] = False
        return value

    def capability_results(self) -> list[dict]:
        """Return one result for every standard profile capability."""

        return [
            {
                "capabilityId": item,
                "status": (
                    "NOT_COLLECTED_PRIVILEGE_REQUIRED"
                    if item == "COL-AUDIT-POLICY-001"
                    else "COLLECTED"
                ),
                "startedAt": "2026-07-24T08:00:00Z",
                "completedAt": "2026-07-24T08:00:01Z",
                "evidenceCount": 1,
                "expectedEvidenceCount": 1,
                "limitationCode": (
                    "PRIVILEGE_REQUIRED"
                    if item == "COL-AUDIT-POLICY-001"
                    else None
                ),
            }
            for item in CollectionProfile.load().capability_ids
        ]

    def package(
        self,
        submission_id: str,
        nonce: str,
        output_name: str | None = None,
    ) -> Path:
        """Build a valid package for the active test session."""

        evidence = self.evidence()
        output = Path(self.temporary.name) / (
            output_name or f"{submission_id}.csa.zip"
        )
        return build_evidence_package(
            output,
            manifest_fields={
                "assessmentId": self.assessment.assessment_id,
                "sessionId": self.session.session_id,
                "submissionId": submission_id,
                "collectorVersion": "CSA-WINDOWS-COLLECTOR-5.0.0",
                "collectorBuildDigest": self.build_digest,
                "collectionProfile": "windows-standard-v1",
                "collectionProfileDigest": self.session.collection_profile_digest,
                "deviceId": "sha256:" + submission_id.encode().hex().ljust(64, "0")[:64],
                "startedAt": evidence["collectionStartedAt"],
                "completedAt": evidence["collectionCompletedAt"],
                "privilegeContext": "STANDARD_USER",
            },
            evidence=evidence,
            capability_results=self.capability_results(),
            collection_log={
                "schemaVersion": "5.0",
                "events": [],
                "endpointChangesPerformed": [],
                "activeValidationPerformed": False,
            },
            enrollment_token=self.token,
            nonce=nonce,
        )


class CapabilityAndSessionTests(Sprint5TestCase):
    """Verify standard-user capabilities and session contracts."""

    def test_capability_registry_and_profile_are_complete(self) -> None:
        """The profile should contain only unique registered capabilities."""

        registry = CapabilityRegistry()
        profile = CollectionProfile.load(registry=registry)
        self.assertGreaterEqual(len(registry.get_all()), 16)
        self.assertEqual(len(profile.capability_ids), len(set(profile.capability_ids)))
        self.assertEqual(profile.collector_mode, "STANDARD_USER_COLLECTION")

    def test_server_stores_only_token_hash(self) -> None:
        """Session persistence must never contain the enrollment token plaintext."""

        path = self.storage.path(
            self.assessment.assessment_id,
            "sessions",
            f"{self.session.session_id}.json",
        )
        text = path.read_text(encoding="utf-8")
        self.assertNotIn(self.token, text)
        self.assertIn(self.session.token_hash, text)

    def test_collector_package_is_minimal_and_bound(self) -> None:
        """Generated packages should verify and contain no server private key."""

        output = Path(self.temporary.name) / "collector-package"
        create_collector_package(self.session, self.token, output)
        manifest = verify_collector_package(output)
        self.assertEqual(manifest["sessionId"], self.session.session_id)
        names = {item["path"] for item in manifest["files"]}
        self.assertNotIn("active_validation", " ".join(names).casefold())
        self.assertFalse(any("private" in item.casefold() for item in names))
        self.assertTrue((output / "Invoke-CSACollector.ps1").exists())

    def test_privacy_scanner_rejects_secret_fields(self) -> None:
        """Credential-like fields should be rejected before packaging."""

        scanner = SensitiveDataScanner()
        self.assertEqual(scanner.scan({"passwordPolicy": {"minimum": 14}}), [])
        samples = (
            ({"password": "not-allowed"}, "FORBIDDEN_FIELD"),
            ({"Authorization": "Authorization: Bearer secret"}, "AUTH_MATERIAL"),
            ({"ntlmResponse": "opaque"}, "FORBIDDEN_FIELD"),
            ({"recoveryKey": "opaque"}, "FORBIDDEN_FIELD"),
            ({"browserCookie": "opaque"}, "FORBIDDEN_FIELD"),
            ({"privateKey": "opaque"}, "FORBIDDEN_FIELD"),
            ({"currentUser": "EXAMPLE\\Alice"}, "PLAINTEXT_IDENTIFIER"),
            ({"path": r"C:\Users\Alice\private.txt"}, "USER_PROFILE_PATH"),
        )
        for value, expected in samples:
            with self.subTest(expected=expected):
                self.assertIn(
                    expected,
                    {item.code for item in scanner.scan(value)},
                )


class SubmissionSecurityTests(Sprint5TestCase):
    """Verify nonce, integrity, source and replay controls."""

    def test_nonce_package_acceptance_and_receipt_signature(self) -> None:
        """A valid package should be accepted exactly once with a signed receipt."""

        service = SubmissionService(self.storage)
        submission_id = "SUB-VALID"
        nonce = service.request_nonce(
            self.assessment.assessment_id,
            self.session.session_id,
            submission_id,
            self.token,
            "127.0.0.1",
        )
        archive = self.package(submission_id, nonce).read_bytes()
        receipt, package, accepted_path = service.accept(
            assessment_id=self.assessment.assessment_id,
            session_id=self.session.session_id,
            submission_id=submission_id,
            enrollment_token=self.token,
            nonce=nonce,
            source_address="127.0.0.1",
            archive_bytes=archive,
        )
        self.assertTrue(accepted_path.exists())
        self.assertEqual(receipt.package_digest, package.package_digest)
        receipt_value = {
            "assessmentId": receipt.assessment_id,
            "sessionId": receipt.session_id,
            "submissionId": receipt.submission_id,
            "receivedAt": receipt.received_at,
            "packageDigest": receipt.package_digest,
            "validationStatus": receipt.validation_status,
            "serverReceiptId": receipt.server_receipt_id,
            "cleanupConfirmed": None,
            "serverSignature": receipt.server_signature,
        }
        self.assertTrue(
            verify_receipt(receipt_value, self.session.tls_certificate_path)
        )
        with self.assertRaises(SubmissionRejected):
            service.accept(
                assessment_id=self.assessment.assessment_id,
                session_id=self.session.session_id,
                submission_id=submission_id,
                enrollment_token=self.token,
                nonce=nonce,
                source_address="127.0.0.1",
                archive_bytes=archive,
            )

    def test_tampered_package_is_rejected(self) -> None:
        """Changing archive bytes must fail before permanent storage."""

        service = SubmissionService(self.storage)
        submission_id = "SUB-TAMPER"
        nonce = service.request_nonce(
            self.assessment.assessment_id,
            self.session.session_id,
            submission_id,
            self.token,
            "127.0.0.1",
        )
        raw = bytearray(self.package(submission_id, nonce).read_bytes())
        raw[-20] ^= 1
        with self.assertRaises(SubmissionRejected):
            service.accept(
                assessment_id=self.assessment.assessment_id,
                session_id=self.session.session_id,
                submission_id=submission_id,
                enrollment_token=self.token,
                nonce=nonce,
                source_address="127.0.0.1",
                archive_bytes=bytes(raw),
            )

    def test_wrong_source_and_token_fail_closed(self) -> None:
        """Source scope and token failures should not issue a nonce."""

        service = SubmissionService(self.storage)
        with self.assertRaises(SubmissionRejected):
            service.request_nonce(
                self.assessment.assessment_id,
                self.session.session_id,
                "SUB-SOURCE",
                self.token,
                "192.0.2.50",
            )
        with self.assertRaises(SubmissionRejected):
            service.request_nonce(
                self.assessment.assessment_id,
                self.session.session_id,
                "SUB-TOKEN",
                "wrong-token",
                "127.0.0.1",
            )

    def test_archive_path_traversal_is_rejected(self) -> None:
        """The ZIP validator must never accept traversal paths."""

        output = Path(self.temporary.name) / "unsafe.zip"
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("../evidence.json", "{}")
        with self.assertRaises(PackageValidationError) as raised:
            EvidencePackageValidator().peek_manifest(output.read_bytes())
        self.assertEqual(raised.exception.state, "REJECTED_ARCHIVE_SAFETY")

    def test_wrong_nonce_and_package_limit_fail_closed(self) -> None:
        """Nonce binding and compressed-size limits must be enforced."""

        archive = self.package("SUB-NONCE", "nonce:correct").read_bytes()
        with self.assertRaises(PackageValidationError) as raised:
            EvidencePackageValidator().validate(
                archive,
                enrollment_token=self.token,
                expected_assessment_id=self.assessment.assessment_id,
                expected_session_id=self.session.session_id,
                expected_submission_id="SUB-NONCE",
                expected_nonce="nonce:wrong",
                expected_profile_digest=self.session.collection_profile_digest,
            )
        self.assertEqual(raised.exception.state, "REJECTED_REPLAY")
        with self.assertRaises(PackageValidationError) as raised:
            EvidencePackageValidator(
                maximum_package_size=len(archive) - 1
            ).peek_manifest(archive)
        self.assertEqual(raised.exception.state, "REJECTED_PACKAGE_LIMIT")

    def test_symlink_and_unexpected_archive_members_are_rejected(self) -> None:
        """Only the exact regular-file package layout is accepted."""

        valid = self.package("SUB-ARCHIVE", "nonce:archive").read_bytes()
        with zipfile.ZipFile(io.BytesIO(valid), "r") as source:
            contents = {
                name: source.read(name) for name in source.namelist()
            }

        symlink_buffer = io.BytesIO()
        with zipfile.ZipFile(symlink_buffer, "w") as archive:
            for name in REQUIRED_FILES:
                info = zipfile.ZipInfo(name)
                if name == "evidence.json":
                    info.create_system = 3
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, contents[name])
        with self.assertRaises(PackageValidationError) as raised:
            EvidencePackageValidator().peek_manifest(symlink_buffer.getvalue())
        self.assertEqual(raised.exception.state, "REJECTED_ARCHIVE_SAFETY")

        extra_buffer = io.BytesIO()
        with zipfile.ZipFile(extra_buffer, "w") as archive:
            for name, value in contents.items():
                archive.writestr(name, value)
            archive.writestr("unexpected.exe", b"MZ")
        with self.assertRaises(PackageValidationError) as raised:
            EvidencePackageValidator().peek_manifest(extra_buffer.getvalue())
        self.assertEqual(raised.exception.state, "REJECTED_ARCHIVE_SAFETY")

    def test_expired_session_cannot_issue_nonce(self) -> None:
        """An expired session token must fail before evidence is accepted."""

        self.session.token_expires_at = "2000-01-01T00:00:00Z"
        self.sessions._write_session(self.session)
        with self.assertRaises(SubmissionRejected) as raised:
            SubmissionService(self.storage).request_nonce(
                self.assessment.assessment_id,
                self.session.session_id,
                "SUB-EXPIRED",
                self.token,
                "127.0.0.1",
            )
        self.assertEqual(raised.exception.state.value, "REJECTED_TOKEN")

    def test_untrusted_collector_build_is_rejected(self) -> None:
        """A valid token cannot authorize an unknown Collector build."""

        service = SubmissionService(self.storage)
        submission_id = "SUB-UNTRUSTED"
        nonce = service.request_nonce(
            self.assessment.assessment_id,
            self.session.session_id,
            submission_id,
            self.token,
            "127.0.0.1",
        )
        self.session.report_configuration["trustedCollectorBuildDigests"] = []
        self.sessions._write_session(self.session)
        with self.assertRaises(SubmissionRejected) as raised:
            service.accept(
                assessment_id=self.assessment.assessment_id,
                session_id=self.session.session_id,
                submission_id=submission_id,
                enrollment_token=self.token,
                nonce=nonce,
                source_address="127.0.0.1",
                archive_bytes=self.package(submission_id, nonce).read_bytes(),
            )
        self.assertEqual(
            raised.exception.state.value, "REJECTED_UNTRUSTED_COLLECTOR"
        )

    def test_real_https_listener_accepts_pinned_session_certificate(self) -> None:
        """The local API should operate only through the generated TLS identity."""

        server = ConsoleHttpsServer(
            self.assessment.assessment_id,
            self.session.session_id,
            self.storage,
            analyze_automatically=False,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        host, port = server.address
        headers = {"Authorization": f"CSA-Enrollment {self.token}"}
        submission_id = "SUB-HTTPS"
        nonce_response = requests.post(
            f"https://{host}:{port}/api/v1/nonce",
            json={"submissionId": submission_id},
            headers=headers,
            verify=self.session.tls_certificate_path,
            timeout=5,
        )
        self.assertEqual(nonce_response.status_code, 200)
        nonce = nonce_response.json()["nonce"]
        upload = requests.post(
            f"https://{host}:{port}/api/v1/submissions/{submission_id}",
            data=self.package(submission_id, nonce).read_bytes(),
            headers={
                **headers,
                "X-CSA-Nonce": nonce,
                "Content-Type": "application/vnd.csa.submission+zip",
            },
            verify=self.session.tls_certificate_path,
            timeout=5,
        )
        self.assertEqual(upload.status_code, 201, upload.text)
        self.assertEqual(upload.json()["validationStatus"], "ACCEPTED")
        server.shutdown()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())

    def test_real_https_listener_rejects_another_session_certificate(self) -> None:
        """A client trusting another session identity must reject the listener."""

        server = ConsoleHttpsServer(
            self.assessment.assessment_id,
            self.session.session_id,
            self.storage,
            analyze_automatically=False,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        host, port = server.address
        wrong_certificate = Path(self.temporary.name) / "wrong-session.crt"
        generate_session_certificate(
            wrong_certificate,
            Path(self.temporary.name) / "wrong-session.key",
            host,
        )
        with self.assertRaises(requests.exceptions.SSLError):
            requests.post(
                f"https://{host}:{port}/api/v1/nonce",
                json={"submissionId": "SUB-WRONG-CERTIFICATE"},
                headers={"Authorization": f"CSA-Enrollment {self.token}"},
                verify=wrong_certificate,
                timeout=5,
            )
        server.shutdown()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())


class OfflineAndArchiveTests(Sprint5TestCase):
    """Verify encrypted portable assessment flows."""

    def test_encrypted_offline_import_and_duplicate_detection(self) -> None:
        """Offline evidence should decrypt, validate and reject replay."""

        submission_id = "SUB-OFFLINE"
        nonce = "offline:test-nonce"
        archive = self.package(submission_id, nonce).read_bytes()
        associated = {
            "assessmentId": self.assessment.assessment_id,
            "packageDigest": EvidencePackageValidator().validate(
                archive,
                enrollment_token=self.token,
                expected_assessment_id=self.assessment.assessment_id,
                expected_session_id=self.session.session_id,
                expected_submission_id=submission_id,
                expected_nonce=nonce,
                expected_profile_digest=self.session.collection_profile_digest,
            ).package_digest,
            "sessionId": self.session.session_id,
            "submissionId": submission_id,
        }
        envelope = encrypt_offline_submission(
            Path(self.temporary.name) / "offline.csa",
            archive_bytes=archive,
            enrollment_token=self.token,
            nonce=nonce,
            associated_data=associated,
            public_key_xml_path=self.session.offline_public_key_path,
        )
        service = OfflineImportService(self.storage)
        package = service.import_file(
            self.assessment.assessment_id, envelope, analyze=False
        )
        self.assertEqual(package.manifest["submissionId"], submission_id)
        receipt = self.storage.read_json(
            self.assessment.assessment_id,
            "submissions",
            "accepted",
            f"{submission_id}.receipt.json",
        )
        self.assertEqual(receipt["validationStatus"], "ACCEPTED_OFFLINE")
        self.assertTrue(
            verify_receipt(receipt, self.session.tls_certificate_path)
        )
        with self.assertRaises(SubmissionRejected):
            service.import_file(
                self.assessment.assessment_id, envelope, analyze=False
            )
        raw = bytearray(envelope.read_bytes())
        raw[-10] ^= 1
        tampered = Path(self.temporary.name) / "tampered.csa"
        tampered.write_bytes(raw)
        with self.assertRaises((OfflineImportError, json.JSONDecodeError)):
            service.import_file(
                self.assessment.assessment_id, tampered, analyze=False
            )

    def test_assessment_archive_is_encrypted_and_verifiable(self) -> None:
        """Assessment exports should require the correct passphrase."""

        output = Path(self.temporary.name) / "assessment.csa"
        export_assessment_archive(
            self.storage,
            self.assessment.assessment_id,
            output,
            "correct horse battery staple",
        )
        self.assertNotIn(b"assessment.json", output.read_bytes())
        result = verify_assessment_archive(
            output, "correct horse battery staple"
        )
        self.assertEqual(result["archiveVerificationStatus"], "VERIFIED")
        with self.assertRaises(AssessmentArchiveError):
            verify_assessment_archive(output, "wrong passphrase")


class FleetAndReportTests(Sprint5TestCase):
    """Verify 13-endpoint deduplication and report safety."""

    def _seed_fleet(self) -> None:
        """Write deterministic endpoint analyses and normalized records."""

        for index in range(13):
            submission_id = f"SUB-{index:02d}"
            finding = {
                "finding": {
                    "rule_id": "PROTO-001",
                    "status": "FAIL" if index < 9 else "PASS",
                    "severity": "HIGH",
                    "evidence": {"setting": "LLMNR_ENABLED"},
                },
                "knowledge": {
                    "title": "LLMNR <script>alert(1)</script> enabled",
                    "description": "Name resolution fallback is enabled.",
                    "risk": "Network authentication can be exposed.",
                    "recommendation": "Disable LLMNR centrally.",
                    "frameworks": {"CIS": ["CIS-4.3"]},
                },
            }
            endpoint = {
                "assessmentId": self.assessment.assessment_id,
                "sessionId": self.session.session_id,
                "submissionId": submission_id,
                "deviceId": f"sha256:{index:064x}",
                "score": 70 if index < 9 else 100,
                "coverage": {
                    "overallCoveragePercent": 80.0,
                    "coverageByDomain": {"NETWORK": 80.0, "OS": 100.0},
                    "limitations": [],
                },
                "findings": [finding],
                "reportPath": None,
                "evidenceSetDigest": f"sha256:{index + 100:064x}",
                "analysisEngineVersion": "CSA-5.0",
            }
            self.storage.write_json(
                self.assessment.assessment_id,
                ("findings", f"{submission_id}.json"),
                endpoint,
            )
            self.storage.write_json(
                self.assessment.assessment_id,
                ("normalized", f"{submission_id}.json"),
                {
                    "schemaVersion": "5.0",
                    "operatingSystem": {"name": "Windows 11"},
                    "privilegeContext": {
                        "executionMode": "STANDARD_USER",
                        "isElevated": False,
                    },
                    "software": [],
                    "collectionLimitations": [
                        {
                            "capabilityId": "COL-AUDIT-POLICY-001",
                            "domain": "SECURITY_POLICY",
                            "reason": "PRIVILEGE_REQUIRED",
                        }
                    ],
                },
            )

    def test_thirteen_endpoint_fleet_deduplicates_systemic_risk(self) -> None:
        """Nine identical findings should become one prevalence-aware fleet finding."""

        self._seed_fleet()
        fleet = FleetAnalyzer(self.storage).analyze(
            self.assessment.assessment_id
        )
        self.assertEqual(fleet.endpoint_count, 13)
        self.assertEqual(len(fleet.fleet_findings), 1)
        self.assertEqual(fleet.fleet_findings[0].affected_endpoint_count, 9)
        self.assertEqual(fleet.fleet_findings[0].affected_percent, 69.2)
        self.assertTrue(fleet.fleet_findings[0].systemic)
        self.assertLessEqual(fleet.fleet_risk_score, 100)

    def test_latest_submission_per_device_drives_fleet_and_removal(self) -> None:
        """Repeat collections must not inflate endpoint prevalence."""

        self._seed_fleet()
        original = self.storage.read_json(
            self.assessment.assessment_id, "findings", "SUB-00.json"
        )
        repeat = json.loads(json.dumps(original))
        repeat["submissionId"] = "SUB-99"
        repeat["findings"][0]["finding"]["status"] = "PASS"
        self.storage.write_json(
            self.assessment.assessment_id,
            ("findings", "SUB-99.json"),
            repeat,
        )
        self.storage.write_json(
            self.assessment.assessment_id,
            ("normalized", "SUB-99.json"),
            {
                "schemaVersion": "5.0",
                "privilegeContext": {"executionMode": "STANDARD_USER"},
            },
        )
        items = [
            {
                "submissionId": f"SUB-{index:02d}",
                "deviceId": f"sha256:{index:064x}",
                "receivedAt": f"2026-07-24T08:{index:02d}:00Z",
            }
            for index in range(13)
        ]
        items.append(
            {
                "submissionId": "SUB-99",
                "deviceId": original["deviceId"],
                "receivedAt": "2026-07-24T09:00:00Z",
            }
        )
        self.storage.write_json(
            self.assessment.assessment_id,
            ("submissions", "index.json"),
            {"items": items},
        )

        fleet = FleetAnalyzer(self.storage).analyze(
            self.assessment.assessment_id
        )
        self.assertEqual(fleet.endpoint_count, 13)
        self.assertEqual(fleet.submission_count, 14)
        self.assertEqual(fleet.duplicate_endpoint_submission_count, 1)
        self.assertEqual(fleet.fleet_findings[0].affected_endpoint_count, 8)

        SubmissionService(self.storage).remove_submission(
            self.assessment.assessment_id, "SUB-99"
        )
        self.assertFalse(
            self.storage.path(
                self.assessment.assessment_id, "findings", "SUB-99.json"
            ).exists()
        )
        restored = FleetAnalyzer(self.storage).analyze(
            self.assessment.assessment_id
        )
        self.assertEqual(restored.endpoint_count, 13)
        self.assertEqual(restored.submission_count, 13)
        self.assertEqual(restored.fleet_findings[0].affected_endpoint_count, 9)

    def test_reports_escape_html_and_show_standard_user_limits(self) -> None:
        """Reports should be local, escaped and coverage-aware."""

        self._seed_fleet()
        reports = ConsoleReportGenerator(self.storage)
        endpoint = reports.generate_endpoint(
            self.assessment.assessment_id, "SUB-00"
        )
        fleet = reports.generate_fleet(self.assessment.assessment_id)
        executive = reports.generate_executive(self.assessment.assessment_id)
        dashboard = reports.generate_dashboard(self.assessment.assessment_id)
        endpoint_html = endpoint.read_text(encoding="utf-8")
        self.assertIn("Collection mode: STANDARD USER", endpoint_html)
        self.assertIn("Administrative rights used: NO", endpoint_html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", endpoint_html)
        self.assertTrue(
            reports.endpoint_model(
                self.assessment.assessment_id, "SUB-00"
            )["integrity"]["frameworkPackDigests"]
        )
        for path in (endpoint, fleet, executive, dashboard):
            html = path.read_text(encoding="utf-8")
            self.assertNotIn("cdn.", html.casefold())
            self.assertNotIn("https://", html.casefold())
            self.assertIn("style.css", html)


if __name__ == "__main__":
    unittest.main()
