"""Generate a synthetic, offline 5.6.1 review report without live collection."""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from csa_console.canonical import read_json, write_canonical_json
from tests.test_console_sprint5 import Sprint5TestCase
from tests.test_sprint561_reporting import build_review_fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    case = Sprint5TestCase(methodName="runTest")
    case.setUp()
    try:
        generator = build_review_fixture(case)
        case.storage.write_json(case.assessment.assessment_id, ("lab-state.json",), {
            "organization": "Synthetic review",
            "description": "Synthetic demonstration of CSA 5.6.1 reporting corrections. This is not a real endpoint assessment or live-acceptance result.",
        })
        model = generator.build_model(case.assessment.assessment_id)
        report = generator.generate(case.assessment.assessment_id)
        shutil.copyfile(report, output)
        integrity = read_json(report.with_suffix(".integrity.json"))
        integrity["reportPath"] = output.name
        write_canonical_json(output.with_suffix(".integrity.json"), integrity)
        write_canonical_json(output.with_suffix(".model.json"), model)
        print("Synthetic review report: " + str(output))
        print("Observed administrator users: 1; affected endpoints: 2; membership NOT_EVALUATED: 1")
    finally:
        case.doCleanups()


if __name__ == "__main__":
    main()
