"""Generate the Sprint 5.3.1 mixed-fleet report and its inspectable model."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.test_console_sprint5 import Sprint5TestCase
from tests.test_sprint531_semantics import build_semantics_fixture


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    case = Sprint5TestCase(methodName="runTest")
    case.setUp()
    try:
        generator = build_semantics_fixture(case)
        report = generator.generate(case.assessment.assessment_id)
        shutil.copy2(report, output)
        model = generator.build_model(case.assessment.assessment_id)
        output.with_suffix(".model.json").write_text(json.dumps(model, indent=2), encoding="utf-8")
        print(output.resolve())
    finally:
        case.doCleanups()


if __name__ == "__main__":
    main()
