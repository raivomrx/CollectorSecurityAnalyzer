"""Collector implementation and end-to-end contract tests."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from analyzer import analyze_file
from collector_schema.evidence_manifest import (
    load_evidence_manifest,
    manifest_declares_setting_id,
)
from collector_schema.loader import load_collector_document
from collector_schema.validation import validate_v2_document
from evidence.normalization import normalize_windows_evidence
from knowledge.models import UNKNOWN_TEXT
from knowledge.repository import KnowledgeRepository
from risk import Status
from rules.loader import load_registry

ROOT = Path(__file__).resolve().parents[1]
COLLECTOR_ROOT = ROOT / "collector" / "windows"
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "canonical_windows_v2.json"


class CollectorContractTests(unittest.TestCase):
    """Verify collector syntax, source contracts, and Knowledge coverage."""

    def test_powershell_sources_parse_when_runtime_is_available(self) -> None:
        """Every collector script should parse in an available PowerShell runtime."""

        executable = shutil.which("pwsh") or shutil.which("powershell")
        if executable is None:
            self.skipTest("PowerShell runtime is unavailable")
        command = (
            "$failed=$false; "
            "Get-ChildItem -LiteralPath . -Recurse -File | "
            "Where-Object {$_.Extension -in @('.ps1','.psm1')} | ForEach-Object {"
            "$tokens=$null;$parseErrors=$null;"
            "[System.Management.Automation.Language.Parser]::ParseFile("
            "$_.FullName,[ref]$tokens,[ref]$parseErrors)|Out-Null;"
            "if($parseErrors.Count -gt 0){$failed=$true}};"
            "if($failed){exit 1}"
        )
        completed = subprocess.run(
            [executable, "-NoProfile", "-NonInteractive", "-Command", command],
            cwd=COLLECTOR_ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)

    def test_every_enabled_windows_rule_has_collector_source(self) -> None:
        """Every dynamic evidence rule should reference a manifested setting."""

        manifest = load_evidence_manifest(COLLECTOR_ROOT / "evidence-manifest.json")
        registry = load_registry(log_startup=False)
        missing: list[str] = []
        for rule in registry.get_enabled():
            spec = getattr(rule.__class__, "spec", None)
            if spec is None:
                continue
            for setting_id in (spec.setting_id, spec.only_when_setting_id):
                if setting_id and not manifest_declares_setting_id(manifest, setting_id):
                    missing.append(f"{rule.metadata.id}:{setting_id}")
        self.assertEqual(missing, [])

    def test_every_enabled_rule_has_complete_knowledge(self) -> None:
        """Every enabled rule should resolve to complete audit knowledge."""

        registry = load_registry(log_startup=False)
        repository = KnowledgeRepository()
        missing: list[str] = []
        for rule in registry.get_enabled():
            knowledge = repository.get(rule.metadata.id)
            if (
                knowledge.title == UNKNOWN_TEXT
                or knowledge.description == UNKNOWN_TEXT
                or knowledge.risk == UNKNOWN_TEXT
                or knowledge.impact == UNKNOWN_TEXT
                or knowledge.recommendation == UNKNOWN_TEXT
                or knowledge.remediation == UNKNOWN_TEXT
                or knowledge.category == UNKNOWN_TEXT
                or not knowledge.references
                or not {"E-ITS", "CIS", "Microsoft"}.issubset(knowledge.frameworks)
            ):
                missing.append(rule.metadata.id)
        self.assertEqual(missing, [])

    def test_manifest_has_no_empty_production_module(self) -> None:
        """Every production collector module should declare output evidence."""

        manifest = load_evidence_manifest(COLLECTOR_ROOT / "evidence-manifest.json")
        empty = [
            item["module"]
            for item in manifest["modules"]
            if not item["mandatoryEvidence"]
            and not item["optionalEvidence"]
            and not item.get("inventoryDomains")
        ]
        self.assertEqual(empty, [])


class CollectorEndToEndTests(unittest.TestCase):
    """Verify the canonical collector document through the full local pipeline."""

    def test_canonical_v2_fixture_reaches_rules_compliance_and_report(self) -> None:
        """Canonical evidence should survive all analyzer layers conservatively."""

        data = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        validate_v2_document(data)
        document = load_collector_document(data, validate=True)
        evidence = normalize_windows_evidence(document)
        self.assertIsNotNone(evidence.get("DEFENDER_REALTIME_PROTECTION_ENABLED"))
        self.assertIsNotNone(evidence.get("WINDOWS_UPDATE_LAST_INSTALL_AGE_DAYS"))

        with tempfile.TemporaryDirectory() as temp_dir:
            findings, score, inventory, report_path = analyze_file(
                FIXTURE_PATH,
                output_dir=Path(temp_dir) / "output",
                skip_cve=True,
                skip_enrichment=True,
                validate_input=True,
                privacy_mode="strict",
            )
            html = report_path.read_text(encoding="utf-8")

        by_id = {item.finding.rule_id: item.finding for item in findings}
        self.assertEqual(by_id["BIT-001"].status, Status.FAIL)
        self.assertEqual(by_id["DEF-002"].status, Status.FAIL)
        self.assertEqual(by_id["FW-004"].status, Status.FAIL)
        self.assertEqual(by_id["PROTO-001"].status, Status.FAIL)
        self.assertEqual(by_id["ACC-004"].status, Status.PASS)
        self.assertEqual(by_id["UPD-004"].status, Status.FAIL)
        self.assertEqual(inventory.product_count, 1)
        self.assertLess(score, 100)
        self.assertIn("Compliance &amp; Policy Assessment", html)
        self.assertIn("TPM_READY", html)
        self.assertIn("Module invocation coverage", html)
        self.assertNotIn("CLIENT-SENSITIVE-01", html)
        self.assertNotIn("Alice", html)


if __name__ == "__main__":
    unittest.main()
