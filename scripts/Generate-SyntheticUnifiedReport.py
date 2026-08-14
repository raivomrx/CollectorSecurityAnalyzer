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


if __name__ == "__main__":
    main()
