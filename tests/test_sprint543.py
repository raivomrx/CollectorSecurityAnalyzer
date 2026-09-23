"""Sprint 5.4.3 cross-layer correctness regressions."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

from csa_console.offline import (
    decrypt_offline_submission,
    encrypt_offline_submission,
)
from csa_console.pipeline import ConsoleAnalysisPipeline
from csa_console.submission import SubmissionService
from csa_lab.unified_report import UnifiedReportGenerator
from tests.test_console_sprint5 import Sprint5TestCase


class Utf8RoundTripTests(Sprint5TestCase):
    """Preserve Estonian text through collection, transport and reporting."""

    def test_estonian_characters_round_trip_online_offline_and_report(self) -> None:
        """UTF-8 evidence must not become escaped, replaced or mojibake text."""

        evidence = self.evidence()
        evidence["device"]["hostname"] = "PÜHJA-ÕPPEARVUTI"
        evidence["device"]["currentUser"] = "PÜHJA\\Õpetaja Ääkküla"
        evidence.setdefault("software", {}).setdefault("items", []).append({
            "displayName": "Tööriist ÕÄÖÜ",
            "displayVersion": "1.0",
            "publisher": "Näidis OÜ",
            "architecture": "x64",
            "scope": "Machine",
        })
        service = SubmissionService(self.storage)
        submission_id = "SUB-UTF8-ROUNDTRIP"
        nonce = service.request_nonce(
            self.assessment.assessment_id,
            self.session.session_id,
            submission_id,
            self.token,
            "127.0.0.1",
        )
        package_path = self.package(
            submission_id, nonce, evidence=evidence,
        )

        offline_path = Path(self.temporary.name) / "utf8.csa"
        encrypt_offline_submission(
            offline_path,
            archive_bytes=package_path.read_bytes(),
            enrollment_token=self.token,
            nonce=nonce,
            associated_data={
                "assessmentId": self.assessment.assessment_id,
                "sessionId": self.session.session_id,
                "submissionId": submission_id,
                "packageDigest": "test-roundtrip",
            },
            public_key_xml_path=self.session.offline_public_key_path,
        )
        decrypted = decrypt_offline_submission(
            offline_path,
            self.session.offline_private_key_path,
        )
        with zipfile.ZipFile(io.BytesIO(decrypted.archive_bytes)) as archive:
            restored = json.loads(
                archive.read("evidence.json").decode("utf-8")
            )
        self.assertEqual(restored["device"]["hostname"], "PÜHJA-ÕPPEARVUTI")
        self.assertEqual(
            restored["device"]["currentUser"],
            "PÜHJA\\Õpetaja Ääkküla",
        )

        _, package, _ = service.accept(
            assessment_id=self.assessment.assessment_id,
            session_id=self.session.session_id,
            submission_id=submission_id,
            enrollment_token=self.token,
            nonce=nonce,
            source_address="127.0.0.1",
            archive_bytes=package_path.read_bytes(),
        )
        ConsoleAnalysisPipeline(self.storage).analyze(package)
        html = UnifiedReportGenerator(self.storage).generate(
            self.assessment.assessment_id
        ).read_text(encoding="utf-8")

        self.assertIn("PÜHJA-ÕPPEARVUTI", html)
        self.assertIn("Õpetaja Ääkküla", html)
        self.assertIn("Tööriist ÕÄÖÜ", html)
        self.assertIn("Näidis OÜ", html)
        for marker in ("Ã•", "Ã¤", "�"):
            self.assertNotIn(marker, html)
