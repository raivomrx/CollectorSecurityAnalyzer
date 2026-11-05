"""Generate a synthetic offline report and verify its independent digest."""
import argparse
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from csa_console.canonical import sha256_bytes, write_canonical_json
from tests.test_report_clarity import ReportClarityTests, prepare_clarity_report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    case = ReportClarityTests("runTest")
    case.setUp()
    try:
        generator = prepare_clarity_report(case)
        model = generator.build_model(case.assessment.assessment_id)
        report = generator.generate(case.assessment.assessment_id)
        sidecar = json.loads(report.with_suffix(".integrity.json").read_text(encoding="utf-8"))
        shutil.copyfile(report, output)
        sidecar["reportPath"] = output.name
        write_canonical_json(output.with_suffix(".integrity.json"), sidecar)
        write_canonical_json(output.with_suffix(".model.json"), model)
        assert sha256_bytes(output.read_bytes()) == sidecar["reportDigest"]
        assert model["executiveEndpointMetrics"]["bitLockerReportedOnEndpoints"] == 1
        assert model["executiveEndpointMetrics"]["bitLockerEnabledEndpoints"] == 0
        assert model["cve"]["confirmedUniqueCves"] == 206
        assert model["cve"]["confirmedProductCveRelationships"] == 231
        print("Synthetic report PASS. BitLocker reported 1/2, confirmed 0/2. CVEs 206 unique, 231 relationships.")
        print(f"Findings {len(model['findings'])}, remediation items {len(model['remediationPlan'])}.")
        print(f"Independent report digest {sidecar['reportDigest']}")
    finally:
        case.doCleanups()


if __name__ == "__main__":
    main()
