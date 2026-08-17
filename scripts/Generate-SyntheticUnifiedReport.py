"""Generate a synthetic unified report artifact for CI inspection."""

from __future__ import annotations

import argparse
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from csa_console.pipeline import ConsoleAnalysisPipeline
from csa_console.submission import SubmissionService
from csa_lab.unified_report import UnifiedReportGenerator
from tests.test_console_sprint5 import Sprint5TestCase


def main() -> None:
    """Create an accepted synthetic assessment and copy its unified report."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--endpoints", type=int, default=1)
    parser.add_argument(
        "--search-fixtures",
        action="store_true",
        help="Add deterministic endpoint, software and CVE search fixtures.",
    )
    args = parser.parse_args()
    if args.endpoints < 1 or args.endpoints > 100:
        parser.error("--endpoints must be between 1 and 100")
    case = Sprint5TestCase(methodName="runTest")
    case.setUp()
    try:
        case.session.expected_device_count = args.endpoints
        case.session.allowed_submission_count = args.endpoints
        case.session.token_max_uses = args.endpoints
        case.sessions._write_session(case.session)
        service = SubmissionService(case.storage)
        for index in range(args.endpoints):
            submission_id = f"SUB-CI-UNIFIED-{index:03d}"
            nonce = service.request_nonce(
                case.assessment.assessment_id,
                case.session.session_id,
                submission_id,
                case.token,
                "127.0.0.1",
            )
            _receipt, package, _path = service.accept(
                assessment_id=case.assessment.assessment_id,
                session_id=case.session.session_id,
                submission_id=submission_id,
                enrollment_token=case.token,
                nonce=nonce,
                source_address="127.0.0.1",
                archive_bytes=case.package(
                    submission_id, nonce, f"{submission_id}.zip"
                ).read_bytes(),
            )
            ConsoleAnalysisPipeline(case.storage).analyze(package)
            if args.search_fixtures and index == 0:
                _add_search_fixtures(case, submission_id)
        started = time.perf_counter()
        report = UnifiedReportGenerator(case.storage).generate(
            case.assessment.assessment_id
        )
        elapsed = time.perf_counter() - started
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(report, output)
        print(
            f"{output.resolve()} endpoints={args.endpoints} "
            f"bytes={output.stat().st_size} seconds={elapsed:.3f}"
        )
    finally:
        case.doCleanups()


def _add_search_fixtures(case: Sprint5TestCase, submission_id: str) -> None:
    """Add deterministic customer-visible terms for browser search tests."""

    assessment_id = case.assessment.assessment_id
    normalized = case.storage.read_json(
        assessment_id,
        "normalized",
        f"{submission_id}.json",
    )
    normalized["identity"] = {
        **normalized.get("identity", {}),
        "computerName": "RIA-S9",
        "hostName": "RIA-S9",
        "currentUser": "LAB\\alice",
    }
    case.storage.write_json(
        assessment_id,
        ("normalized", f"{submission_id}.json"),
        normalized,
    )
    analysis = case.storage.read_json(
        assessment_id,
        "findings",
        f"{submission_id}.json",
    )
    analysis["cveAnalysisStatus"] = "COMPLETE"
    analysis["cveSummary"] = {
        "status": "COMPLETE",
        "installedSoftwareRecords": 1,
        "normalizedProducts": 1,
        "cveEligibleProducts": 1,
        "successfullyEvaluatedProducts": 1,
        "notEvaluatedProducts": 0,
        "confirmedCveIds": ["CVE-2026-5210"],
        "possibleCveIds": [],
        "criticalCveIds": [],
        "highCveIds": ["CVE-2026-5210"],
        "cisaKevCveIds": [],
        "confirmedProductCveRelationships": 1,
        "possibleProductCveRelationships": 0,
        "softwareResults": [
            {
                "productKey": "google|chrome|147.0.0",
                "displayName": "Google Chrome",
                "displayVersion": "147.0.0",
                "publisher": "Google LLC",
                "normalizedVendor": "Google",
                "normalizedProduct": "Google Chrome",
                "normalizedVersion": "147.0.0",
                "normalizationConfidence": 100,
                "securityStatus": "Known vulnerability detected",
                "lifecycleStatus": "SUPPORTED",
                "confirmedCveCount": 1,
                "possibleCveCount": 0,
                "cveDetails": [
                    {
                        "cveId": "CVE-2026-5210",
                        "severity": "HIGH",
                        "cvssScore": 8.8,
                        "matchStatus": "CONFIRMED",
                        "matchRationale": (
                            "Installed version is in the affected range"
                        ),
                        "cisaKev": False,
                    }
                ],
            }
        ],
    }
    case.storage.write_json(
        assessment_id,
        ("findings", f"{submission_id}.json"),
        analysis,
    )


if __name__ == "__main__":
    main()
