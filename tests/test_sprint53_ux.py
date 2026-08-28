"""Sprint 5.3 theme, responsive-report and join UX contracts."""

from __future__ import annotations

import hashlib
import math
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from csa_console.portal import (
    JOIN_CODE_ALPHABET,
    PortalBinding,
    normalize_join_code,
)
from csa_lab.firewall import NullFirewallManager
from csa_lab.models import AssessmentWizardRequest
from csa_lab.service import LabApplicationService


ROOT = Path(__file__).resolve().parents[1]


class Sprint53UxTests(unittest.TestCase):
    """Verify durable UX and short-code security contracts."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        bootstrap = self.root / "collector.exe"
        bootstrap.write_bytes(b"MZ" + bytes(range(128)))
        self.service = LabApplicationService(
            self.root / "assessments",
            firewall=NullFirewallManager(),
            collector_bootstrap=bootstrap,
            executable_path=Path(__file__).resolve(),
        )
        self.addCleanup(self.service.shutdown)

    def _assessment(self, name: str = "Sprint 5.3"):
        return self.service.create_assessment(
            AssessmentWizardRequest(
                name=name,
                expected_endpoints=1,
                organization="CSA",
                source_subnet="127.0.0.0/8",
                network_profile="Private",
                listener_address="127.0.0.1",
                listener_port=8443,
            )
        )

    def test_join_code_format_entropy_and_assessment_binding(self) -> None:
        first = self._assessment("First")
        second = self._assessment("Second")
        first_code = self.service.join_code(first.assessment_id)
        second_code = self.service.join_code(second.assessment_id)

        self.assertRegex(
            first_code,
            r"^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{4}-"
            r"[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{4}$",
        )
        self.assertNotEqual(first_code, second_code)
        self.assertGreater(math.log2(len(JOIN_CODE_ALPHABET) ** 8), 39.5)
        self.assertFalse(set(first_code) & set("0O1IL"))

    def test_join_code_normalization_is_strict_but_human_friendly(self) -> None:
        self.assertEqual(normalize_join_code("k7m4x9q2"), "K7M4-X9Q2")
        self.assertEqual(normalize_join_code("K7M4-X9Q2"), "K7M4-X9Q2")
        for invalid in ("K7M4 X9Q2", "K7M4-X9Q0", "K7M4-X9QI", "Ｋ7M4-X9Q2"):
            self.assertEqual(normalize_join_code(invalid), "")

    def test_join_code_has_high_uniqueness_across_10000_contexts(self) -> None:
        original = self.service.load_state
        try:
            codes = set()
            for index in range(10_000):
                self.service.load_state = lambda _assessment_id, value=index: SimpleNamespace(
                    assessment_id=f"CSA-{value:05d}",
                    session_id=f"SES-{value:05d}",
                    expires_at=f"2026-08-{(value % 28) + 1:02d}T12:00:00Z",
                )
                codes.add(self.service.join_code(f"CSA-{index:05d}"))
        finally:
            self.service.load_state = original
        self.assertEqual(len(codes), 10_000)

    def test_portal_throttles_failures_without_storing_supplied_code(self) -> None:
        state = self._assessment()
        code = self.service.join_code(state.assessment_id)
        binding = PortalBinding(
            assessment_id=state.assessment_id,
            session_id=state.session_id,
            join_code_hash=hashlib.sha256(code.encode()).hexdigest(),
            collector_path=Path(state.collector_path),
            expires_at=state.expires_at,
            maximum_downloads=5,
            maximum_failed_attempts=3,
            storage=self.service.storage,
        )

        for _ in range(3):
            self.assertFalse(binding.authorize("AAAA-AAAA", "127.0.0.1"))
        self.assertFalse(binding.authorize(code.lower().replace("-", ""), "127.0.0.1"))
        self.assertEqual(binding.failed_authorization_count, 3)
        self.assertGreaterEqual(binding.throttled_authorization_count, 2)
        audit = self.service.storage.path(
            state.assessment_id, "audit", "audit.jsonl"
        ).read_text(encoding="utf-8")
        self.assertIn("collector_portal_authorization_failed", audit)
        self.assertNotIn("AAAA-AAAA", audit)

    def test_theme_preference_persists_outside_assessment_data(self) -> None:
        self.assertEqual(self.service.load_ui_preferences(), {"theme": "system"})
        self.service.save_ui_preferences("dark")
        self.assertEqual(self.service.load_ui_preferences(), {"theme": "dark"})
        self.assertTrue(
            (self.root / "config" / "ui-preferences.json").is_file()
        )
        with self.assertRaises(ValueError):
            self.service.save_ui_preferences("midnight")

    def test_lab_theme_bootstrap_and_join_controls_are_complete(self) -> None:
        html = (ROOT / "csa_lab" / "templates" / "lab.html").read_text(
            encoding="utf-8"
        )
        script = (ROOT / "csa_lab" / "templates" / "lab.js").read_text(
            encoding="utf-8"
        )
        style = (ROOT / "csa_lab" / "templates" / "lab.css").read_text(
            encoding="utf-8"
        )
        self.assertLess(html.index("__CSA_THEME__"), html.index("__CSA_STYLE__"))
        for value in ('value="system"', 'value="light"', 'value="dark"'):
            self.assertIn(value, html)
        for identifier in ("portal-server", "join-code", "copy-portal", "copy-join-code"):
            self.assertIn(f'id="{identifier}"', html)
        self.assertIn("prefers-color-scheme: dark", script)
        self.assertIn('html[data-theme="dark"]', style)

    def test_report_responsive_and_disclosure_contracts(self) -> None:
        html = (ROOT / "csa_lab" / "templates" / "unified.html").read_text(
            encoding="utf-8"
        )
        script = (ROOT / "csa_lab" / "templates" / "unified.js").read_text(
            encoding="utf-8"
        )
        style = (ROOT / "csa_lab" / "templates" / "unified.css").read_text(
            encoding="utf-8"
        )
        self.assertIn('id="theme-select"', html)
        self.assertIn('class="expanded-cve-details searchable hidden"', html)
        self.assertIn('<td colspan="8">', html)
        self.assertIn("Recommended action:", html)
        self.assertIn("Verification:", html)
        self.assertIn("responsive-cards", html)
        self.assertIn("Software outside vendor support", html)
        self.assertNotIn("Unsupported software", html)
        self.assertIn("width: min(96vw, 1680px)", style)
        self.assertIn("@media (max-width: 768px)", style)
        self.assertIn("data-cve-expand", script)
        self.assertIn("sessionStorage.setItem", script)


if __name__ == "__main__":
    unittest.main()
