"""Localhost-only CSA Lab administration UI and JSON adapter."""

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
import subprocess
import tempfile
import threading
import time
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from csa_console.audit import ConsoleAuditLog
from csa_console.serde import model_to_dict
from csa_lab.models import AssessmentWizardRequest
from csa_lab.network import discover_network_interfaces
from csa_lab.service import LabApplicationService

LOGGER = logging.getLogger(__name__)
TEMPLATE_ROOT = Path(__file__).resolve().parent / "templates"
MAX_JSON = 256 * 1024
MAX_OFFLINE = 30 * 1024 * 1024


class LabAdminServer:
    """Serve the CSA Lab UI only on an ephemeral localhost port."""

    def __init__(
        self,
        service: LabApplicationService,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        browser_timeout_seconds: int = 60,
    ) -> None:
        """Create the local administration server."""

        if host not in {"127.0.0.1", "::1"}:
            raise ValueError("CSA Lab administration UI must bind to localhost")
        self.service = service
        self.csrf_token = secrets.token_urlsafe(32)
        self.browser_timeout_seconds = browser_timeout_seconds
        self._last_heartbeat = time.monotonic()
        self._heartbeat_seen = threading.Event()
        self._shutdown_requested = threading.Event()
        handler = _admin_handler_factory(self)
        self.server = ThreadingHTTPServer((host, port), handler)
        self.server.daemon_threads = True

    @property
    def url(self) -> str:
        """Return the exact local UI URL."""

        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}/"

    def run(self, *, open_browser: bool = True) -> None:
        """Run until the UI closes or shutdown is requested."""

        monitor = threading.Thread(
            target=self._monitor_browser,
            name="CSA-Lab-Browser-Monitor",
            daemon=True,
        )
        monitor.start()
        if open_browser:
            webbrowser.open(self.url)
        try:
            self.server.serve_forever(poll_interval=0.25)
        finally:
            self.server.server_close()
            self.service.shutdown()

    def shutdown(self) -> None:
        """Request deterministic local application shutdown."""

        self._shutdown_requested.set()
        threading.Thread(target=self.server.shutdown, daemon=True).start()

    def heartbeat(self) -> None:
        """Record that the browser application remains open."""

        self._last_heartbeat = time.monotonic()
        self._heartbeat_seen.set()

    def _monitor_browser(self) -> None:
        while not self._shutdown_requested.wait(2):
            if (
                self._heartbeat_seen.is_set()
                and time.monotonic() - self._last_heartbeat
                > self.browser_timeout_seconds
            ):
                LOGGER.info("CSA Lab browser heartbeat ended; cleaning up")
                self.shutdown()
                return


def _admin_handler_factory(application: LabAdminServer):
    service = application.service

    class AdminHandler(BaseHTTPRequestHandler):
        server_version = "CSA-Lab-Admin/5.1"
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            try:
                if path == "/":
                    self._page()
                elif path == "/api/v1/heartbeat":
                    application.heartbeat()
                    self._json(HTTPStatus.OK, {"status": "ALIVE"})
                elif path == "/api/v1/interfaces":
                    self._json(
                        HTTPStatus.OK,
                        {
                            "interfaces": model_to_dict(
                                discover_network_interfaces()
                            )
                        },
                    )
                elif path == "/api/v1/assessments":
                    self._json(
                        HTTPStatus.OK,
                        {"assessments": service.list_assessments()},
                    )
                elif path.startswith("/api/v1/assessments/"):
                    assessment_id, action = self._assessment_route(path)
                    if action == "cve-analysis-status":
                        self._json(
                            HTTPStatus.OK,
                            {
                                "progress": service.cve_analysis_progress(
                                    assessment_id
                                )
                            },
                        )
                    elif action:
                        self._json(HTTPStatus.NOT_FOUND, {"error": "NOT_FOUND"})
                    else:
                        self._json(
                            HTTPStatus.OK,
                            _assessment_payload(service, assessment_id),
                        )
                elif path.startswith("/reports/"):
                    assessment_id = unquote(path[len("/reports/") :])
                    state = service.load_state(assessment_id)
                    report = Path(state.report_path)
                    if not report.is_file():
                        self._json(
                            HTTPStatus.NOT_FOUND,
                            {"error": "REPORT_NOT_FOUND"},
                        )
                    else:
                        service._audit(assessment_id).append(
                            "unified_report_opened",
                            {"reportName": report.name},
                        )
                        self._bytes(
                            HTTPStatus.OK,
                            report.read_bytes(),
                            "text/html; charset=utf-8",
                        )
                else:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "NOT_FOUND"})
            except Exception as error:
                LOGGER.exception("CSA Lab local GET failed")
                self._json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"error": "CSA-LAB-001", "message": _safe_error(error)},
                )

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            if not secrets.compare_digest(
                self.headers.get("X-CSA-Lab-CSRF", ""),
                application.csrf_token,
            ):
                self._json(HTTPStatus.FORBIDDEN, {"error": "CSRF_REJECTED"})
                return
            try:
                if path == "/api/v1/assessments":
                    data = self._read_json(MAX_JSON)
                    request = AssessmentWizardRequest(
                        name=str(data.get("name", "")),
                        expected_endpoints=int(
                            data.get("expectedEndpoints", 1)
                        ),
                        organization=str(data.get("organization", "")),
                        reference_number=str(
                            data.get("referenceNumber", "")
                        ),
                        assessor_notes=str(data.get("assessorNotes", "")),
                        description=str(data.get("description", "")),
                        collection_profile=str(
                            data.get(
                                "collectionProfile", "windows-standard-v1"
                            )
                        ),
                        session_expiry_hours=int(
                            data.get("sessionExpiryHours", 2)
                        ),
                        allowed_submissions=(
                            int(data["allowedSubmissions"])
                            if data.get("allowedSubmissions") not in {
                                None,
                                "",
                            }
                            else None
                        ),
                        source_subnet=str(data.get("sourceSubnet", "")),
                        network_profile=str(
                            data.get("networkProfile", "Private")
                        ),
                        interface_id=str(data.get("interfaceId", "")),
                        listener_address=str(
                            data.get("listenerAddress", "127.0.0.1")
                        ),
                        listener_port=int(data.get("listenerPort", 8443)),
                        offline_collection=bool(
                            data.get("offlineCollection", True)
                        ),
                        active_validation=False,
                    )
                    state = service.create_assessment(request)
                    self._json(
                        HTTPStatus.CREATED,
                        {"assessment": model_to_dict(state)},
                    )
                    return
                if not path.startswith("/api/v1/assessments/"):
                    if path == "/api/v1/shutdown":
                        self._json(HTTPStatus.ACCEPTED, {"status": "CLOSING"})
                        application.shutdown()
                        return
                    if path == "/api/v1/diagnostics":
                        bundle = service.export_diagnostic_bundle()
                        self._json(
                            HTTPStatus.CREATED,
                            {"bundleName": bundle.name},
                        )
                        return
                    self._json(HTTPStatus.NOT_FOUND, {"error": "NOT_FOUND"})
                    return
                assessment_id, action = self._assessment_route(path)
                if action == "start":
                    state = service.start_collection(assessment_id)
                    self._json(
                        HTTPStatus.OK, {"assessment": model_to_dict(state)}
                    )
                elif action == "pause":
                    state = service.pause_collection(assessment_id)
                    self._json(
                        HTTPStatus.OK, {"assessment": model_to_dict(state)}
                    )
                elif action == "resume":
                    state = service.resume_collection(assessment_id)
                    self._json(
                        HTTPStatus.OK, {"assessment": model_to_dict(state)}
                    )
                elif action == "stop":
                    state = service.stop_collection(assessment_id)
                    self._json(
                        HTTPStatus.OK, {"assessment": model_to_dict(state)}
                    )
                elif action == "delete":
                    service.delete_assessment(assessment_id)
                    self._json(HTTPStatus.OK, {"status": "DELETED"})
                elif action == "recovery-cleanup":
                    state = service.cleanup_recovery(assessment_id)
                    self._json(
                        HTTPStatus.OK, {"assessment": model_to_dict(state)}
                    )
                elif action == "cve-analysis":
                    progress = service.start_cve_analysis(assessment_id)
                    self._json(
                        HTTPStatus.ACCEPTED,
                        {"progress": progress},
                    )
                elif action == "report":
                    data = self._read_json(MAX_JSON)
                    report = service.generate_unified_report(
                        assessment_id,
                        include_technical_evidence=bool(
                            data.get("includeTechnicalEvidence", True)
                        ),
                        include_audit=bool(data.get("includeAudit", True)),
                        include_endpoint_details=bool(
                            data.get("includeEndpointDetails", True)
                        ),
                        allow_without_cve=bool(
                            data.get("allowWithoutCve", False)
                        ),
                    )
                    self._json(
                        HTTPStatus.CREATED,
                        {
                            "reportName": report.name,
                            "reportUrl": f"/reports/{assessment_id}",
                        },
                    )
                elif action == "export":
                    data = self._read_json(MAX_JSON)
                    archive = service.export_archive(
                        assessment_id,
                        str(data.get("passphrase", "")),
                    )
                    self._json(
                        HTTPStatus.CREATED,
                        {"archiveName": archive.name},
                    )
                elif action == "offline":
                    body = self._read_body(MAX_OFFLINE)
                    with tempfile.NamedTemporaryFile(
                        suffix=".csa", delete=False
                    ) as handle:
                        handle.write(body)
                        temporary = Path(handle.name)
                    try:
                        item = service.import_offline(
                            assessment_id, temporary
                        )
                    finally:
                        temporary.unlink(missing_ok=True)
                    self._json(
                        HTTPStatus.CREATED,
                        {"endpoint": model_to_dict(item)},
                    )
                elif action == "show-report":
                    state = service.load_state(assessment_id)
                    report = Path(state.report_path)
                    if not report.is_file():
                        raise FileNotFoundError("Assessment report is unavailable")
                    subprocess.Popen(
                        ["explorer.exe", f"/select,{report}"],
                        close_fds=True,
                    )
                    service._audit(assessment_id).append(
                        "unified_report_folder_opened",
                        {"reportName": report.name},
                    )
                    self._json(HTTPStatus.OK, {"status": "OPENED"})
                else:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "NOT_FOUND"})
            except (ValueError, OSError, KeyError) as error:
                LOGGER.warning("CSA Lab request rejected: %s", error)
                self._json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "CSA-LAB-INPUT", "message": _safe_error(error)},
                )
            except Exception as error:
                LOGGER.exception("CSA Lab local action failed")
                self._json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"error": "CSA-LAB-002", "message": _safe_error(error)},
                )

        def _page(self) -> None:
            html = (TEMPLATE_ROOT / "lab.html").read_text(encoding="utf-8")
            style = (TEMPLATE_ROOT / "lab.css").read_text(encoding="utf-8")
            script = (TEMPLATE_ROOT / "lab.js").read_text(encoding="utf-8")
            html = html.replace("/*__CSA_STYLE__*/", style)
            html = html.replace("/*__CSA_SCRIPT__*/", script)
            html = html.replace("__CSA_CSRF__", application.csrf_token)
            logo = Path(__file__).resolve().parents[1] / "assets" / "logo.png"
            logo_uri = (
                "data:image/png;base64,"
                + base64.b64encode(logo.read_bytes()).decode("ascii")
            )
            html = html.replace("__CSA_LOGO__", logo_uri)
            self._bytes(
                HTTPStatus.OK,
                html.encode("utf-8"),
                "text/html; charset=utf-8",
                csp=(
                    "default-src 'none'; style-src 'unsafe-inline'; "
                    "script-src 'unsafe-inline'; img-src 'self' data:; "
                    "connect-src 'self'; base-uri 'none'; form-action 'self'; "
                    "frame-ancestors 'none'"
                ),
            )

        def _assessment_route(self, path: str) -> tuple[str, str]:
            parts = path.strip("/").split("/")
            if len(parts) not in {4, 5}:
                raise ValueError("Invalid assessment route")
            return unquote(parts[3]), unquote(parts[4]) if len(parts) == 5 else ""

        def _read_json(self, maximum: int) -> dict[str, Any]:
            body = self._read_body(maximum)
            value = json.loads(body.decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError("Request JSON must be an object")
            return value

        def _read_body(self, maximum: int) -> bytes:
            if self.headers.get("Transfer-Encoding"):
                raise ValueError("Chunked request bodies are not accepted")
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError as error:
                raise ValueError("Content-Length is required") from error
            if length < 0 or length > maximum:
                raise ValueError("Request body is outside the allowed size")
            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError("Request body is incomplete")
            return body

        def _json(self, status: HTTPStatus, value: dict[str, Any]) -> None:
            body = json.dumps(
                value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            self._bytes(status, body, "application/json")

        def _bytes(
            self,
            status: HTTPStatus,
            body: bytes,
            content_type: str,
            *,
            csp: str | None = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            if csp:
                self.send_header("Content-Security-Policy", csp)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            LOGGER.info(
                "Local admin request completed status=%s",
                args[1] if len(args) > 1 else "unknown",
            )

    return AdminHandler


def _assessment_payload(
    service: LabApplicationService, assessment_id: str
) -> dict[str, Any]:
    state = service.load_state(assessment_id)
    endpoints = service.dashboard(assessment_id)
    try:
        audit = service.audit_status(assessment_id)
    except Exception:
        audit = {"auditVerificationStatus": "FAILED"}
    rejected = list(
        service.storage.path(
            assessment_id, "submissions", "rejected"
        ).glob("*.json")
    )
    return {
        "assessment": model_to_dict(state),
        "portalUrl": (
            service.portal_url(assessment_id)
            if state.status.value == "COLLECTING"
            else ""
        ),
        "endpoints": model_to_dict(endpoints),
        "acceptedSubmissionCount": len(
            service.submissions.list_submissions(assessment_id)
        ),
        "rejectedSubmissionCount": len(rejected),
        "audit": audit,
    }


def _safe_error(error: Exception) -> str:
    return str(error).replace("\r", " ").replace("\n", " ")[:500]
