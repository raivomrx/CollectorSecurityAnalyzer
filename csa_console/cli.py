"""Command-line interface for the CSA Assessment Console."""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
from pathlib import Path
from typing import Any

from csa_console.audit import ConsoleAuditLog
from csa_console.archive import export_assessment_archive, verify_assessment_archive
from csa_console.collector_package import (
    create_collector_package,
    verify_collector_package,
)
from csa_console.fleet import FleetAnalyzer
from csa_console.reporting import ConsoleReportGenerator
from csa_console.server import ConsoleHttpsServer, request_server_stop
from csa_console.sessions import AssessmentSessionService
from csa_console.storage import AssessmentStorage
from csa_console.submission import SubmissionService
from csa_console.enums import SessionStatus

LOGGER = logging.getLogger(__name__)


def main(argv: list[str] | None = None) -> None:
    """Run the Assessment Console CLI."""

    parser = _parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    storage = AssessmentStorage(args.data_root)
    try:
        _dispatch(args, storage)
    except (ValueError, OSError, KeyError) as error:
        parser.error(str(error))


def _parser() -> argparse.ArgumentParser:
    """Build the nested Console argument parser."""

    parser = argparse.ArgumentParser(description="CSA Assessment Console")
    parser.add_argument(
        "--data-root",
        default=os.environ.get("CSA_DATA_ROOT", "assessments"),
        help="Assessment storage root",
    )
    parser.add_argument("--log-level", default="INFO")
    commands = parser.add_subparsers(dest="command", required=True)

    assessment = commands.add_parser("assessment")
    assessment_commands = assessment.add_subparsers(
        dest="assessment_command", required=True
    )
    create = assessment_commands.add_parser("create")
    create.add_argument("--name", required=True)
    create.add_argument("--customer-reference", required=True)
    create.add_argument("--created-by", default="assessment-operator")
    create.add_argument("--assessment-id")
    assessment_commands.add_parser("list")
    status = assessment_commands.add_parser("status")
    status.add_argument("--assessment", required=True)
    close = assessment_commands.add_parser("close")
    close.add_argument("--assessment", required=True)
    export = assessment_commands.add_parser("export")
    export.add_argument("--assessment", required=True)
    export.add_argument("--output", required=True)
    export.add_argument("--encrypt", action="store_true", default=True)
    verify = assessment_commands.add_parser("verify")
    verify_group = verify.add_mutually_exclusive_group(required=True)
    verify_group.add_argument("--assessment")
    verify_group.add_argument("--file")

    session = commands.add_parser("session")
    session_commands = session.add_subparsers(dest="session_command", required=True)
    open_command = session_commands.add_parser("open")
    open_command.add_argument("--assessment", required=True)
    open_command.add_argument("--profile")
    open_command.add_argument("--expected-devices", type=int, default=13)
    open_command.add_argument("--allowed-submissions", type=int, default=20)
    open_command.add_argument("--expires-hours", type=int, default=10)
    open_command.add_argument("--allowed-source-network", action="append", default=[])
    open_command.add_argument("--allowed-source-address", action="append", default=[])
    open_command.add_argument("--listen-address", default="127.0.0.1")
    open_command.add_argument("--port", type=int, default=8443)
    for name in ("pause", "resume", "close"):
        item = session_commands.add_parser(name)
        item.add_argument("--assessment", required=True)
        item.add_argument("--session", required=True)

    package = commands.add_parser("collector-package")
    package_commands = package.add_subparsers(dest="package_command", required=True)
    package_create = package_commands.add_parser("create")
    package_create.add_argument("--assessment", required=True)
    package_create.add_argument("--session", required=True)
    package_create.add_argument("--server-url")
    package_create.add_argument("--output", required=True)
    package_verify = package_commands.add_parser("verify")
    package_verify.add_argument("--path", required=True)

    server = commands.add_parser("server")
    server_commands = server.add_subparsers(dest="server_command", required=True)
    server_start = server_commands.add_parser("start")
    server_start.add_argument("--assessment", required=True)
    server_start.add_argument("--session", required=True)
    server_start.add_argument("--allow-wildcard-bind", action="store_true")
    server_start.add_argument("--no-auto-analyze", action="store_true")
    server_stop = server_commands.add_parser("stop")
    server_stop.add_argument("--assessment", required=True)
    server_stop.add_argument("--session", required=True)

    submission = commands.add_parser("submission")
    submission_commands = submission.add_subparsers(
        dest="submission_command", required=True
    )
    submission_list = submission_commands.add_parser("list")
    submission_list.add_argument("--assessment", required=True)
    submission_show = submission_commands.add_parser("show")
    submission_show.add_argument("--assessment", required=True)
    submission_show.add_argument("--submission", required=True)
    submission_import = submission_commands.add_parser("import")
    submission_import.add_argument("--assessment", required=True)
    submission_import.add_argument("--file", required=True)
    submission_retry = submission_commands.add_parser("retry-analysis")
    submission_retry.add_argument("--assessment", required=True)
    submission_retry.add_argument("--submission", required=True)
    submission_remove = submission_commands.add_parser("remove")
    submission_remove.add_argument("--assessment", required=True)
    submission_remove.add_argument("--submission", required=True)

    analyze = commands.add_parser("analyze")
    analyze_commands = analyze.add_subparsers(dest="analyze_command", required=True)
    endpoint = analyze_commands.add_parser("endpoint")
    endpoint.add_argument("--assessment", required=True)
    endpoint.add_argument("--submission", required=True)
    fleet = analyze_commands.add_parser("fleet")
    fleet.add_argument("--assessment", required=True)

    report = commands.add_parser("report")
    report_commands = report.add_subparsers(dest="report_command", required=True)
    endpoint_report = report_commands.add_parser("endpoint")
    endpoint_report.add_argument("--assessment", required=True)
    endpoint_report.add_argument("--submission", required=True)
    for name in ("fleet", "executive", "generate-all"):
        item = report_commands.add_parser(name)
        item.add_argument("--assessment", required=True)
    return parser


def _dispatch(args: argparse.Namespace, storage: AssessmentStorage) -> None:
    """Execute one parsed Console command."""

    sessions = AssessmentSessionService(storage)
    if args.command == "assessment":
        if args.assessment_command == "create":
            value = sessions.create_assessment(
                args.name,
                args.customer_reference,
                args.created_by,
                args.assessment_id,
            )
            _output({"assessmentId": value.assessment_id, "status": value.status.value})
        elif args.assessment_command == "list":
            values = []
            for path in sorted(storage.root.glob("*/assessment.json")):
                values.append(json.loads(path.read_text(encoding="utf-8")))
            _output({"assessments": values})
        elif args.assessment_command == "status":
            assessment = sessions.load_assessment(args.assessment)
            session_files = sorted(
                storage.path(args.assessment, "sessions").glob("*.json")
            )
            submissions = SubmissionService(storage).list_submissions(args.assessment)
            _output(
                {
                    "assessmentId": assessment.assessment_id,
                    "status": assessment.status.value,
                    "sessions": len(session_files),
                    "acceptedSubmissions": len(submissions),
                }
            )
        elif args.assessment_command == "close":
            value = sessions.close_assessment(args.assessment)
            _output({"assessmentId": value.assessment_id, "status": value.status.value})
        elif args.assessment_command == "export":
            passphrase = getpass.getpass("Assessment archive passphrase: ")
            confirmation = getpass.getpass("Confirm passphrase: ")
            if passphrase != confirmation:
                raise ValueError("Assessment archive passphrases do not match")
            output = export_assessment_archive(
                storage, args.assessment, args.output, passphrase
            )
            _output({"assessmentArchive": str(output), "encrypted": True})
        elif args.assessment_command == "verify":
            if args.file:
                passphrase = getpass.getpass("Assessment archive passphrase: ")
                _output(verify_assessment_archive(args.file, passphrase))
            else:
                audit = ConsoleAuditLog(
                    storage.path(args.assessment, "audit", "audit.jsonl")
                )
                _output(audit.verify())
        return

    if args.command == "session":
        if args.session_command == "open":
            value, token = sessions.open_session(
                args.assessment,
                profile_path=args.profile,
                expected_devices=args.expected_devices,
                allowed_submissions=args.allowed_submissions,
                expires_in_hours=args.expires_hours,
                allowed_source_networks=args.allowed_source_network,
                allowed_source_addresses=args.allowed_source_address,
                listen_address=args.listen_address,
                listen_port=args.port,
            )
            _output(
                {
                    "assessmentId": value.assessment_id,
                    "sessionId": value.session_id,
                    "status": value.status.value,
                    "expiresAt": value.expires_at,
                    "tlsFingerprint": value.tls_fingerprint,
                    "enrollmentToken": token,
                    "warning": "The enrollment token is shown once and stored only as a hash.",
                }
            )
        elif args.submission_command == "retry-analysis":
            status = {
                "pause": SessionStatus.PAUSED,
                "resume": SessionStatus.OPEN,
                "close": SessionStatus.CLOSED,
            }[args.session_command]
            value = sessions.set_session_status(
                args.assessment, args.session, status
            )
            _output({"sessionId": value.session_id, "status": value.status.value})
        return

    if args.command == "collector-package":
        if args.package_command == "create":
            session = sessions.load_session(args.assessment, args.session)
            token = os.environ.get("CSA_ENROLLMENT_TOKEN") or getpass.getpass(
                "Enrollment token: "
            )
            sessions.verify_token(session, token)
            output = create_collector_package(
                session, token, args.output, args.server_url
            )
            package_manifest = verify_collector_package(output)
            sessions.trust_collector_build(
                session, package_manifest["collectorBuildDigest"]
            )
            ConsoleAuditLog(
                storage.path(args.assessment, "audit", "audit.jsonl")
            ).append(
                "collector_package_generated",
                {
                    "sessionId": args.session,
                    "collectorBuildDigest": package_manifest[
                        "collectorBuildDigest"
                    ],
                },
            )
            _output({"collectorPackage": str(output)})
        else:
            _output(verify_collector_package(args.path))
        return

    if args.command == "server":
        if args.server_command == "start":
            server = ConsoleHttpsServer(
                args.assessment,
                args.session,
                storage,
                allow_wildcard_bind=args.allow_wildcard_bind,
                analyze_automatically=not args.no_auto_analyze,
            )
            session = sessions.load_session(args.assessment, args.session)
            _output(
                {
                    "title": "CSA Assessment Console",
                    "assessment": args.assessment,
                    "session": args.session,
                    "listenAddress": server.address[0],
                    "httpsPort": server.address[1],
                    "tlsFingerprint": session.tls_fingerprint,
                    "allowedSourceNetworks": session.allowed_source_networks,
                    "collectorProfile": session.collection_profile,
                    "administrativeRightsRequiredOnEndpoints": False,
                    "activeValidation": "DISABLED",
                }
            )
            server.serve_forever()
        else:
            path = request_server_stop(
                storage, args.assessment, args.session
            )
            _output({"stopRequested": True, "signalPath": str(path)})
        return

    if args.command == "submission":
        service = SubmissionService(storage)
        if args.submission_command == "list":
            _output({"items": service.list_submissions(args.assessment)})
        elif args.submission_command == "show":
            values = [
                item
                for item in service.list_submissions(args.assessment)
                if item.get("submissionId") == args.submission
            ]
            if not values:
                raise ValueError("Submission was not found")
            _output(values[0])
        elif args.submission_command == "import":
            from csa_console.offline import OfflineImportService

            package = OfflineImportService(storage).import_file(
                args.assessment, args.file
            )
            _output(
                {
                    "submissionId": package.manifest["submissionId"],
                    "validationStatus": "ACCEPTED",
                    "packageDigest": package.package_digest,
                }
            )
        elif args.submission_command == "retry-analysis":
            from csa_console.pipeline import ConsoleAnalysisPipeline
            from csa_console.serde import model_to_dict

            analysis = ConsoleAnalysisPipeline(storage).retry_analysis(
                args.assessment, args.submission
            )
            _output(model_to_dict(analysis))
        elif args.submission_command == "remove":
            service.remove_submission(args.assessment, args.submission)
            _output(
                {
                    "submissionId": args.submission,
                    "removed": True,
                }
            )
        return

    if args.command == "analyze":
        from csa_console.serde import model_to_dict

        if args.analyze_command == "fleet":
            value = FleetAnalyzer(storage).analyze(args.assessment)
        else:
            from csa_console.pipeline import ConsoleAnalysisPipeline

            value = ConsoleAnalysisPipeline(storage).retry_analysis(
                args.assessment, args.submission
            )
        _output(model_to_dict(value))
        return

    if args.command == "report":
        reports = ConsoleReportGenerator(storage)
        if args.report_command == "endpoint":
            outputs = [reports.generate_endpoint(args.assessment, args.submission)]
        elif args.report_command == "fleet":
            outputs = [reports.generate_fleet(args.assessment)]
        elif args.report_command == "executive":
            outputs = [reports.generate_executive(args.assessment)]
        else:
            outputs = reports.generate_all(args.assessment)
        _output({"reports": [str(item) for item in outputs]})


def _output(value: Any) -> None:
    """Write stable human-readable JSON to stdout."""

    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
