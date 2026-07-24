"""Real Windows standard-user Collector to Console acceptance harness."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import threading
from pathlib import Path
from typing import Any

from csa_console.collector_package import (
    create_collector_package,
    verify_collector_package,
)
from csa_console.identifiers import random_id
from csa_console.server import ConsoleHttpsServer
from csa_console.sessions import AssessmentSessionService
from csa_console.storage import AssessmentStorage
from csa_console.submission import SubmissionService


def run_live_acceptance(
    output_root: str | Path,
    *,
    allow_admin_member: bool = False,
) -> dict[str, Any]:
    """Run a real non-elevated Windows Collector through the HTTPS Console."""

    if os.name != "nt":
        raise RuntimeError("Standard-user live acceptance requires Windows")
    output = Path(output_root).resolve()
    output.mkdir(parents=True, exist_ok=False)
    storage = AssessmentStorage(output / "assessments")
    sessions = AssessmentSessionService(storage)
    assessment_id = "CSA-LIVE-" + random_id()[-10:]
    assessment = sessions.create_assessment(
        "Windows 11 standard-user live acceptance",
        "LOCAL-LAB",
        assessment_id=assessment_id,
    )
    session, token = sessions.open_session(
        assessment.assessment_id,
        expected_devices=1,
        allowed_submissions=2,
        listen_address="127.0.0.1",
        listen_port=0,
    )
    server = ConsoleHttpsServer(
        assessment.assessment_id,
        session.session_id,
        storage,
        analyze_automatically=True,
    )
    host, port = server.address
    package_root = output / "collector-package"
    create_collector_package(
        session,
        token,
        package_root,
        server_url=f"https://{host}:{port}",
    )
    package_manifest = verify_collector_package(package_root)
    sessions.trust_collector_build(
        session, str(package_manifest["collectorBuildDigest"])
    )
    before_temp = _temp_children()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(package_root / "Invoke-CSACollector.ps1"),
            ],
            cwd=package_root,
            capture_output=True,
            text=True,
            timeout=240,
            check=False,
        )
    finally:
        server.shutdown()
        thread.join(timeout=10)
    submissions = SubmissionService(storage).list_submissions(
        assessment.assessment_id
    )
    after_temp = _temp_children()
    leaked_temp = sorted(after_temp - before_temp)
    if completed.returncode != 0:
        raise RuntimeError(
            "Collector live execution failed: "
            + _safe_process_summary(completed.stdout, completed.stderr)
        )
    if len(submissions) != 1:
        raise RuntimeError(
            f"Expected one accepted live submission, received {len(submissions)}"
        )
    submission_id = str(submissions[0]["submissionId"])
    evidence_path = storage.path(
        assessment.assessment_id,
        "submissions",
        "accepted",
        f"{submission_id}.evidence.json",
    )
    analysis_path = storage.path(
        assessment.assessment_id, "findings", f"{submission_id}.json"
    )
    report_path = storage.path(
        assessment.assessment_id,
        "reports",
        "endpoints",
        f"{submission_id}.console.html",
    )
    if not evidence_path.exists() or not analysis_path.exists() or not report_path.exists():
        raise RuntimeError("Live submission did not complete analysis and reporting")
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    privilege = evidence.get("privilegeContext", {})
    execution_mode = str(privilege.get("executionMode", "UNKNOWN"))
    integrity = str(privilege.get("integrityLevel", "UNKNOWN"))
    if bool(privilege.get("isElevated")) or integrity != "MEDIUM":
        raise RuntimeError("Collector did not run in a medium non-elevated context")
    production_non_admin = execution_mode == "STANDARD_USER"
    if not production_non_admin and not allow_admin_member:
        raise RuntimeError(
            "Live process used a filtered administrator-member token; "
            "rerun under a true standard-user account"
        )
    metadata = evidence.get("metadata", {})
    if metadata.get("endpointChangesPerformed") not in ([], None):
        raise RuntimeError("Collector reported unexpected endpoint changes")
    if bool(metadata.get("activeValidation")):
        raise RuntimeError("Collector unexpectedly enabled Active Validation")
    if leaked_temp:
        raise RuntimeError("Collector left temporary directories behind")
    result = {
        "assessmentId": assessment.assessment_id,
        "sessionId": session.session_id,
        "submissionId": submission_id,
        "collectorExitCode": completed.returncode,
        "submissionAccepted": True,
        "analysisCompleted": True,
        "endpointReportGenerated": True,
        "executionMode": execution_mode,
        "integrityLevel": integrity,
        "isElevated": False,
        "uacPromptTriggered": False,
        "activeValidationPerformed": False,
        "endpointChangesPerformed": [],
        "temporaryDirectoriesLeaked": leaked_temp,
        "productionNonAdminAcceptance": production_non_admin,
        "reportPath": str(report_path),
        "safeCollectorOutput": _safe_process_summary(
            completed.stdout, completed.stderr
        ),
    }
    result_path = output / "acceptance-result.json"
    from csa_console.canonical import write_canonical_json

    write_canonical_json(result_path, result)
    return result


def _temp_children() -> set[str]:
    """Return current CSA temporary child names."""

    root = Path(os.environ.get("TEMP", ".")) / "CSA"
    if not root.exists():
        return set()
    return {item.name for item in root.iterdir()}


def _safe_process_summary(stdout: str, stderr: str) -> str:
    """Retain only known non-sensitive Collector status lines."""

    allowed_prefixes = (
        "Assessment:",
        "Organization reference:",
        "Collector mode:",
        "Administrator rights required:",
        "Active security testing:",
        "Data destination:",
        "Collection completed",
        "Submission accepted",
        "Receipt ID:",
        "Local temporary data removed:",
        "CSA Collector failed:",
    )
    values = [
        line.strip()
        for line in (stdout + "\n" + stderr).splitlines()
        if line.strip().startswith(allowed_prefixes)
    ]
    return "\n".join(values)


def main() -> None:
    """Run the live acceptance harness from the command line."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--allow-admin-member", action="store_true")
    args = parser.parse_args()
    result = run_live_acceptance(
        args.output_root,
        allow_admin_member=args.allow_admin_member,
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
