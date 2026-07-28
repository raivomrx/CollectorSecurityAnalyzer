"""Generate a synthetic unified report artifact for CI inspection."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from csa_console.pipeline import ConsoleAnalysisPipeline
from csa_console.submission import SubmissionService
from csa_lab.unified_report import UnifiedReportGenerator
from tests.test_console_sprint5 import Sprint5TestCase


def main() -> None:
    """Create one accepted synthetic endpoint and copy its unified report."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    case = Sprint5TestCase(methodName="runTest")
    case.setUp()
    try:
        submission_id = "SUB-CI-UNIFIED"
        service = SubmissionService(case.storage)
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
            archive_bytes=case.package(submission_id, nonce).read_bytes(),
        )
        ConsoleAnalysisPipeline(case.storage).analyze(package)
        report = UnifiedReportGenerator(case.storage).generate(
            case.assessment.assessment_id
        )
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(report, output)
        print(output.resolve())
    finally:
        case.doCleanups()


if __name__ == "__main__":
    main()
