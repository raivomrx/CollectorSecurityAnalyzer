"""Evidence manifest integrity tests."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from collector_schema.evidence_manifest import (
    EvidenceManifestError,
    load_evidence_manifest,
    validate_emitted_setting_ids,
    validate_evidence_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "collector" / "windows" / "evidence-manifest.json"


class EvidenceManifestTests(unittest.TestCase):
    """Verify manifest source mapping and failure cases."""

    def setUp(self) -> None:
        """Load a fresh manifest for every mutation test."""

        self.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_production_manifest_and_module_sources_validate(self) -> None:
        """Every manifest module and literal should map to collector source."""

        loaded = load_evidence_manifest(MANIFEST_PATH)
        self.assertEqual(len(loaded["modules"]), 15)

    def test_literal_placeholder_is_rejected(self) -> None:
        """Literal entries must not conceal placeholder syntax."""

        entry = self.manifest["modules"][1]["mandatoryEvidence"][0]
        entry["matchType"] = "LITERAL"
        with self.assertRaises(EvidenceManifestError):
            validate_evidence_manifest(self.manifest)

    def test_wildcard_without_wildcard_is_rejected(self) -> None:
        """Wildcard entries must provide explicit wildcard semantics."""

        entry = self.manifest["modules"][1]["mandatoryEvidence"][0]
        entry["id"] = "BITLOCKER_PROTECTION_STATUS"
        with self.assertRaises(EvidenceManifestError):
            validate_evidence_manifest(self.manifest)

    def test_unknown_cardinality_is_rejected(self) -> None:
        """Unknown cardinality types must fail validation."""

        self.manifest["modules"][2]["mandatoryEvidence"][0]["cardinality"] = "PER_PROCESS"
        with self.assertRaises(EvidenceManifestError):
            validate_evidence_manifest(self.manifest)

    def test_alias_group_requires_one_canonical_entry(self) -> None:
        """Aliases may share a unit only with one canonical entry."""

        entries = self.manifest["modules"][1]["mandatoryEvidence"]
        entries[1]["canonical"] = True
        with self.assertRaises(EvidenceManifestError):
            validate_evidence_manifest(self.manifest)

    def test_setting_id_cannot_be_owned_by_two_modules(self) -> None:
        """One runtime setting ID must have exactly one module owner."""

        duplicate = copy.deepcopy(self.manifest["modules"][2]["mandatoryEvidence"][0])
        self.manifest["modules"][3]["mandatoryEvidence"].append(duplicate)
        with self.assertRaises(EvidenceManifestError):
            validate_evidence_manifest(self.manifest)

    def test_mandatory_optional_unit_overlap_is_rejected(self) -> None:
        """One canonical unit cannot be both mandatory and optional."""

        module = self.manifest["modules"][2]
        alias = copy.deepcopy(module["mandatoryEvidence"][0])
        alias["id"] = "DEFENDER_ENABLED_ALIAS"
        alias["canonical"] = False
        module["optionalEvidence"].append(alias)
        with self.assertRaises(EvidenceManifestError):
            validate_evidence_manifest(self.manifest)

    def test_runtime_unknown_setting_is_rejected(self) -> None:
        """A module must not emit setting IDs absent from the manifest."""

        with self.assertRaises(EvidenceManifestError):
            validate_emitted_setting_ids(self.manifest, "Defender", ["DEFENDER_SECRET_PATH"])

    def test_runtime_wildcard_setting_is_accepted(self) -> None:
        """Dynamic setting IDs should resolve through declared wildcard matching."""

        validate_emitted_setting_ids(
            self.manifest,
            "BitLocker",
            ["BITLOCKER_C_PROTECTION_STATUS", "BITLOCKER_C_ENCRYPTION_METHOD"],
        )


if __name__ == "__main__":
    unittest.main()
