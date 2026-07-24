"""Sprint 5.0 submission concurrency and isolation stress tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from csa_console.capabilities import CollectionProfile
from csa_console.package import build_evidence_package
from csa_console.sessions import AssessmentSessionService
from csa_console.storage import AssessmentStorage
from csa_console.submission import SubmissionService

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "canonical_windows_v2.json"


class ConsoleSubmissionStressTests(unittest.TestCase):
    """Exercise bounded sequential and near-parallel submissions."""

    def setUp(self) -> None:
        """Create one high-capacity loopback session."""

        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.storage = AssessmentStorage(Path(self.temporary.name) / "data")
        self.sessions = AssessmentSessionService(self.storage)
        assessment = self.sessions.create_assessment(
            "Stress assessment", "STRESS", assessment_id="CSA-STRESS"
        )
        self.session, self.token = self.sessions.open_session(
            assessment.assessment_id,
            expected_devices=40,
            allowed_submissions=40,
            listen_address="127.0.0.1",
            listen_port=0,
        )
        self.build_digest = "sha256:" + "c" * 64
        self.sessions.trust_collector_build(self.session, self.build_digest)
        self.service = SubmissionService(self.storage)

    def test_twenty_sequential_submissions_leave_consistent_state(self) -> None:
        """Twenty submissions should have unique IDs and no quarantine residue."""

        for index in range(20):
            self._submit(f"SUB-SEQ-{index:02d}")
        items = self.service.list_submissions(self.session.assessment_id)
        self.assertEqual(len(items), 20)
        self.assertEqual(len({item["submissionId"] for item in items}), 20)
        quarantine = self.storage.path(
            self.session.assessment_id, "submissions", "quarantine"
        )
        self.assertEqual(list(quarantine.iterdir()), [])

    def test_thirteen_parallel_submissions_are_isolated(self) -> None:
        """Near-parallel endpoint submissions must not overwrite each other."""

        with ThreadPoolExecutor(max_workers=13) as executor:
            results = list(
                executor.map(
                    self._submit,
                    [f"SUB-PAR-{index:02d}" for index in range(13)],
                )
            )
        self.assertEqual(len(set(results)), 13)
        items = self.service.list_submissions(self.session.assessment_id)
        self.assertEqual(len(items), 13)
        reloaded = self.sessions.load_session(
            self.session.assessment_id, self.session.session_id
        )
        self.assertEqual(reloaded.token_uses, 13)

    def _submit(self, submission_id: str) -> str:
        """Build and accept one isolated package."""

        nonce = self.service.request_nonce(
            self.session.assessment_id,
            self.session.session_id,
            submission_id,
            self.token,
            "127.0.0.1",
        )
        archive = self._package(submission_id, nonce)
        receipt, _package, _path = self.service.accept(
            assessment_id=self.session.assessment_id,
            session_id=self.session.session_id,
            submission_id=submission_id,
            enrollment_token=self.token,
            nonce=nonce,
            source_address="127.0.0.1",
            archive_bytes=archive.read_bytes(),
        )
        return receipt.server_receipt_id

    def _package(self, submission_id: str, nonce: str) -> Path:
        """Build a compact valid stress package."""

        evidence = json.loads(FIXTURE.read_text(encoding="utf-8"))
        evidence["collectorVersion"] = "CSA-WINDOWS-COLLECTOR-5.0.0"
        evidence["device"].update(
            {
                "hostname": "id-" + "1" * 12,
                "domain": "id-" + "2" * 12,
                "currentUser": "id-" + "3" * 12,
                "elevated": False,
            }
        )
        for service in evidence.get("services", {}).get("services", []):
            if isinstance(service, dict) and service.get("ServiceAccount"):
                service["ServiceAccount"] = "id-" + "4" * 12
        evidence["privilegeContext"] = {
            "executionMode": "STANDARD_USER",
            "isElevated": False,
            "integrityLevel": "MEDIUM",
        }
        capability_results = [
            {
                "capabilityId": item,
                "status": "COLLECTED",
                "evidenceCount": 1,
                "expectedEvidenceCount": 1,
            }
            for item in CollectionProfile.load().capability_ids
        ]
        output = Path(self.temporary.name) / f"{submission_id}.zip"
        return build_evidence_package(
            output,
            manifest_fields={
                "assessmentId": self.session.assessment_id,
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
            capability_results=capability_results,
            collection_log={"events": [], "activeValidationPerformed": False},
            enrollment_token=self.token,
            nonce=nonce,
        )


if __name__ == "__main__":
    unittest.main()
