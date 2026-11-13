"""Scoped HTTPS submission server for the local Assessment Console."""

from __future__ import annotations

import json
import logging
import ssl
import threading
import time
from collections import defaultdict, deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
import uuid
import re
from urllib.parse import urlparse

from csa_console.network import validate_listen_address
from csa_console.portal import PortalBinding
from csa_console.distribution import DistributionDenied
from csa_console.quick_start import PORTAL_SCRIPT_HASH
from csa_console.trusted_network import TrustedNetworkService
from csa_console.pipeline import ConsoleAnalysisPipeline
from csa_console.reporting import ConsoleReportGenerator
from csa_console.serde import model_to_dict
from csa_console.sessions import AssessmentSessionService
from csa_console.storage import AssessmentStorage
from csa_console.submission import SubmissionRejected, SubmissionService
from csa_console.canonical import write_canonical_json
from csa_console.audit import ConsoleAuditLog
from csa_console.identifiers import utc_text

LOGGER = logging.getLogger(__name__)


class _SafeThreadingHTTPServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        LOGGER.warning("CSA-HTTP-CONNECTION-CLOSED: request stopped before a safe response was available")


class _HttpRequestError(ValueError):
    """Represent a safe client request error and its HTTP response."""

    def __init__(self, status: HTTPStatus, code: str) -> None:
        """Create a bounded request rejection."""

        super().__init__(code)
        self.status = status
        self.code = code


class ConsoleHttpsServer:
    """Receive bounded endpoint submissions on one explicit TLS address."""

    def __init__(
        self,
        assessment_id: str,
        session_id: str,
        storage: AssessmentStorage | None = None,
        *,
        allow_wildcard_bind: bool = False,
        analyze_automatically: bool = True,
        portal: PortalBinding | None = None,
        trusted_network: TrustedNetworkService | None = None,
        simple_delivery=None,
    ) -> None:
        """Create a configured but not yet started HTTPS server."""

        self.storage = storage or AssessmentStorage()
        self.assessment_id = assessment_id
        self.session_id = session_id
        self.portal = portal
        self.simple_delivery = simple_delivery
        self.trusted_network = trusted_network or TrustedNetworkService(self.storage, assessment_id, session_id)
        self.session = AssessmentSessionService(self.storage).load_session(
            assessment_id, session_id
        )
        self._stop_path = self.storage.path(
            assessment_id, "sessions", f"{session_id}.stop.json"
        )
        self._stop_path.unlink(missing_ok=True)
        self._stopped = threading.Event()
        self._serving = threading.Event()
        self._close_lock = threading.Lock()
        self._closed = False
        validate_listen_address(
            self.session.listen_address, allow_wildcard=allow_wildcard_bind
        )
        if not self.session.tls_certificate_path or not self.session.tls_private_key_path:
            raise ValueError("Session TLS material is unavailable")
        handler = _handler_factory(
            assessment_id,
            session_id,
            self.storage,
            analyze_automatically,
            portal,
            self.trusted_network,
            simple_delivery,
        )
        self._server = _SafeThreadingHTTPServer(
            (self.session.listen_address, self.session.listen_port), handler
        )
        self._server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(
            self.session.tls_certificate_path,
            self.session.tls_private_key_path,
        )
        self._server.socket = context.wrap_socket(
            self._server.socket, server_side=True
        )

    def serve_forever(self) -> None:
        """Run until interrupted and close the socket deterministically."""

        monitor = threading.Thread(target=self._monitor_stop, daemon=True)
        monitor.start()
        self._serving.set()
        try:
            self._server.serve_forever(poll_interval=0.2)
        finally:
            self._serving.clear()
            self._stopped.set()
            self._close_server()

    def shutdown(self) -> None:
        """Stop accepting requests and close the listener."""

        if self._serving.is_set():
            self._server.shutdown()
        self._stopped.set()
        self._close_server()

    @property
    def address(self) -> tuple[str, int]:
        """Return the concrete listener address."""

        host, port = self._server.server_address[:2]
        return str(host), int(port)

    def _monitor_stop(self) -> None:
        """Stop on a local assessment-scoped operator signal."""

        while not self._stopped.is_set():
            if self._stop_path.exists():
                self._stop_path.unlink(missing_ok=True)
                self._server.shutdown()
                return
            self._stopped.wait(0.25)

    def _close_server(self) -> None:
        """Close the listener socket exactly once across shutdown paths."""

        with self._close_lock:
            if self._closed:
                return
            self._server.server_close()
            self._closed = True


def request_server_stop(
    storage: AssessmentStorage,
    assessment_id: str,
    session_id: str,
) -> Path:
    """Request local server shutdown without a network control endpoint."""

    AssessmentSessionService(storage).load_session(assessment_id, session_id)
    path = storage.path(
        assessment_id, "sessions", f"{session_id}.stop.json"
    )
    write_canonical_json(
        path,
        {
            "sessionId": session_id,
            "requestedAt": utc_text(),
            "action": "STOP",
        },
    )
    return path


class _RateLimiter:
    """Bound nonce and upload requests per source address."""

    def __init__(self, limit: int = 30, window_seconds: int = 60) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self.values: dict[str, deque[float]] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, source: str) -> bool:
        """Return whether a source remains within the request budget."""

        now = time.monotonic()
        with self.lock:
            values = self.values[source]
            while values and values[0] <= now - self.window_seconds:
                values.popleft()
            if len(values) >= self.limit:
                return False
            values.append(now)
            return True


def _handler_factory(
    assessment_id: str,
    session_id: str,
    storage: AssessmentStorage,
    analyze_automatically: bool,
    portal: PortalBinding | None = None,
    trusted_network: TrustedNetworkService | None = None,
    simple_delivery=None,
):
    """Build a request handler bound to one assessment session."""

    submission_service = SubmissionService(storage)
    pipeline = ConsoleAnalysisPipeline(storage)
    reporter = ConsoleReportGenerator(storage)
    limiter = _RateLimiter()
    trusted_network = trusted_network or TrustedNetworkService(storage, assessment_id, session_id)
    from csa_lab.pilot_launch import PilotLaunchService
    pilot_launch = PilotLaunchService(storage,assessment_id,session_id)

    class SubmissionHandler(BaseHTTPRequestHandler):
        server_version = "CSA-Lab/5.6.8.5"
        protocol_version = "HTTP/1.1"

        def _pilot_cookie(self, name="__Host-CSA-Pilot"):
            from http.cookies import SimpleCookie, CookieError
            try:
                cookie=SimpleCookie(self.headers.get("Cookie",""))
                return cookie[name].value if name in cookie else ""
            except CookieError:
                return ""

        def _pilot_route(self):
            parts=self._request_path().strip("/").split("/")
            if len(parts)!=5 or parts[:3]!=["api","v1","pilot-launch"] or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}",parts[3]):
                raise _HttpRequestError(HTTPStatus.NOT_FOUND,"NOT_FOUND")
            return parts[3],parts[4]

        def _customer_error(self, status, code):
            self.diagnostic_code=code
            from csa_console.customer_launch import render
            self._bytes(status,render(""),"text/html; charset=utf-8")

        def handle_one_request(self):
            self.correlation_id = uuid.uuid4().hex
            self.diagnostic_stage = "REQUEST_VALIDATION"
            self.diagnostic_code = "HTTP_REQUEST"
            self.connection.settimeout(max(1, min(15, submission_service.sessions.load_session(assessment_id, session_id).request_timeout)))
            return super().handle_one_request()

        def send_error(self, code, message=None, explain=None):
            # Never echo a malformed request, URL or injected header into HTML/logs.
            self.close_connection = True
            self._json(HTTPStatus(code), {"error": "HTTP_REQUEST_REJECTED"})

        def _require_legacy(self, source):
            if portal is None:
                raise DistributionDenied()
            portal.distribution_policy.require_legacy(source)
            session = submission_service.sessions.load_session(assessment_id, session_id)
            if trusted_network.grants.required(session):
                raise DistributionDenied()

        def _legacy_available(self, source):
            try:
                self._require_legacy(source)
                return True
            except DistributionDenied:
                return False

        def _request_path(self):
            if not self.path.startswith("/") or self.path.startswith("//"):
                raise _HttpRequestError(HTTPStatus.BAD_REQUEST, "INVALID_REQUEST_TARGET")
            try:
                return urlparse(self.path).path
            except ValueError:
                raise _HttpRequestError(HTTPStatus.BAD_REQUEST, "INVALID_REQUEST_TARGET") from None

        def _trusted_route(self):
            parts = self._request_path().strip("/").split("/")
            if len(parts) != 5 or parts[:3] != ["api", "v2", "trusted"] or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", parts[3]):
                raise _HttpRequestError(HTTPStatus.NOT_FOUND, "NOT_FOUND")
            return parts[3], parts[4]

        def _credential(self, prefix):
            values = self.headers.get_all("Authorization", [])
            if len(values) != 1 or len(values[0]) > 256 or not values[0].startswith(prefix):
                raise _HttpRequestError(HTTPStatus.FORBIDDEN, "CSA-TRUST-AUTHORIZATION")
            return values[0][len(prefix):]

        def _trusted_result(self, callback):
            try:
                return callback()
            except (OSError, ValueError, KeyError) as error:
                value = str(error)
                code = value if re.fullmatch(r"(?:CSA-(?:TRUST|NETWORK)-[A-Z0-9-]+|TRUST_NOT_ESTABLISHED|TRUST_ENROLLMENT_PENDING)", value) else "CSA-TRUST-REQUEST"
                raise _HttpRequestError(HTTPStatus.FORBIDDEN, code) from None

        def _trusted_get(self, source):
            envelope, action = self._trusted_route()
            if action == "metadata":
                self.diagnostic_stage = "TRUSTED_METADATA"
                result = self._trusted_result(lambda: trusted_network.metadata(envelope, source))
            elif action == "challenge":
                self.diagnostic_stage = "TRUSTED_CHALLENGE"
                result = self._trusted_result(lambda: trusted_network.challenge(envelope, source))
            else:
                raise _HttpRequestError(HTTPStatus.NOT_FOUND, "NOT_FOUND")
            self._json(HTTPStatus.OK, result)

        def _trusted_post(self, source):
            envelope, action = self._trusted_route()
            if action == "authorize":
                self.diagnostic_stage = "TRUSTED_AUTHORIZATION"
                if self.headers.get_content_type() != "application/json":
                    raise _HttpRequestError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "CONTENT_TYPE")
                body = self._read_json(4096)
                secret = self._credential("CSA-Assessor ")
                result = self._trusted_result(lambda: trusted_network.authorize(envelope, source, body, secret))
            elif action == "download-grant":
                self.diagnostic_stage = "TRUSTED_DOWNLOAD_GRANT"
                if self._read_json(64) != {}:
                    raise _HttpRequestError(HTTPStatus.BAD_REQUEST, "INVALID_REQUEST")
                ticket = self._credential("CSA-Authorization ")
                result = self._trusted_result(lambda: trusted_network.download_grant(envelope, source, ticket))
            elif action == "package":
                self.diagnostic_stage = "TRUSTED_PACKAGE_DOWNLOAD"
                self._read_body(0)
                grant = self._credential("CSA-Download ")
                data = self._trusted_result(lambda: trusted_network.package(envelope, source, grant))
                self._bytes(HTTPStatus.OK, data, "application/zip")
                return
            else:
                raise _HttpRequestError(HTTPStatus.NOT_FOUND, "NOT_FOUND")
            self._json(HTTPStatus.OK, result)

        def do_GET(self) -> None:
            self.correlation_id = uuid.uuid4().hex
            self.diagnostic_stage = "PORTAL_JOIN"
            source = str(self.client_address[0])
            try:
                path = self._request_path()
                if path.startswith("/api/v1/pilot-launch/"):
                    self.diagnostic_stage="PILOT_BOOTSTRAP"
                    identifier,action=self._pilot_route()
                    if not limiter.allow(source):
                        raise DistributionDenied()
                    if action=="starter.ps1" and simple_delivery is not None:
                        self._bytes(HTTPStatus.OK,simple_delivery.starter(identifier,source),"text/plain; charset=utf-8")
                        return
                    if action=="collector.exe" and simple_delivery is not None:
                        self.diagnostic_stage="COLLECTOR_DOWNLOAD"
                        self._bytes(HTTPStatus.OK,simple_delivery.download(identifier,source),
                            "application/vnd.microsoft.portable-executable",attachment="CSA-Collector.exe")
                        return
                    if action!="bootstrap.ps1":
                        raise DistributionDenied()
                    self._bytes(HTTPStatus.OK,pilot_launch.bootstrap(identifier,source),"text/plain; charset=utf-8")
                    return
                if path.startswith("/api/v2/trusted/"):
                    if not limiter.allow(source):
                        raise _HttpRequestError(HTTPStatus.TOO_MANY_REQUESTS, "RATE_LIMIT")
                    self._trusted_get(source)
                    return
                if portal is None:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "NOT_FOUND"})
                    return
                prefix = "/join/"
                if not path.startswith(prefix):
                    self._json(HTTPStatus.NOT_FOUND, {"error": "NOT_FOUND"})
                    return
                remainder = path[len(prefix) :].strip("/")
                parts = remainder.split("/") if remainder else []
                if not parts or len(parts) > 2:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "NOT_FOUND"})
                    return
                join_code = parts[0]
                self.diagnostic_stage = "PORTAL_DOWNLOAD" if len(parts) == 2 else "PORTAL_JOIN"
                if not portal.authorize(join_code, source):
                    self._bytes(
                        HTTPStatus.GONE,
                        portal.render_unavailable_page(),
                        "text/html; charset=utf-8",
                    )
                    return
                if len(parts) == 2 and parts[1] in {"download", "download-powershell", "download-launcher"}:
                    self._require_legacy(source)
                if len(parts) == 1:
                    if not path.endswith("/"):
                        self._redirect(f"{path}/")
                        return
                    from csa_console.customer_launch import render
                    if simple_delivery is not None:
                        if not limiter.allow(source):
                            raise DistributionDenied()
                        self.diagnostic_stage="COLLECTOR_PREPARATION"
                        view=simple_delivery.view(source)
                    else:
                        view=pilot_launch.customer_view(self._pilot_cookie(),source)
                    body = render(
                        submission_service.sessions.load_session(
                            assessment_id, session_id
                        ).assessment_name,
                        view,
                        network_options=self._trusted_result(lambda: trusted_network.advertisements(source)),
                        development=self._legacy_available(source),
                        activation_available=pilot_launch.has_authorized(source),
                    )
                    self._bytes(
                        HTTPStatus.OK,
                        body,
                        "text/html; charset=utf-8",
                    )
                    return
                if parts[1]=="pilot-download":
                    self.diagnostic_stage="PILOT_PRIVATE_PACKAGE"
                    view=pilot_launch.customer_view(self._pilot_cookie(),source)
                    if view is None:
                        raise DistributionDenied()
                    ticket=self._pilot_cookie("__Host-CSA-Download")
                    if not ticket:
                        ticket=pilot_launch.ticket(view["handoffId"],source,cookie=self._pilot_cookie())["ticket"]
                        self._response_cookie="__Host-CSA-Download="+ticket+"; Secure; HttpOnly; SameSite=Strict; Path=/"
                    data=pilot_launch.package(view["handoffId"],source,ticket)
                    self._bytes(HTTPStatus.OK,data,"application/zip",attachment="CSA-Windows-Collector.zip")
                    return
                if parts[1] == "download":
                    self.diagnostic_stage = "PORTAL_DOWNLOAD"
                    download_path = portal.collector_path
                    content_type = "application/vnd.microsoft.portable-executable"
                    filename = "CSA-Collector.exe"
                elif parts[1] == "download-powershell" and portal.script_collector_path is not None:
                    download_path = portal.script_collector_path
                    content_type = "application/zip"
                    filename = "CSA-PowerShell-Collector.zip"
                elif parts[1] == "download-launcher" and portal.launcher_bytes:
                    portal.record_download(source)
                    self._bytes(HTTPStatus.OK, portal.launcher_bytes, "application/octet-stream", attachment="Start-CSACollector.ps1")
                    return
                else:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "NOT_FOUND"})
                    return
                body = download_path.read_bytes()
                portal.record_download(source)
                self._bytes(
                    HTTPStatus.OK,
                    body,
                    content_type,
                    attachment=filename,
                )
            except DistributionDenied as error:
                reason=getattr(error,"reason_code","TRUST_NOT_ESTABLISHED")
                self.diagnostic_code=reason
                if simple_delivery is not None:
                    simple_delivery.record_diagnostic(self.diagnostic_stage,reason,self.correlation_id)
                ConsoleAuditLog(storage.path(assessment_id,"audit","audit.jsonl")).append("collector_delivery_rejected",
                    {"correlationId":self.correlation_id,"stage":self.diagnostic_stage,"reasonCode":reason})
                if self.path.startswith("/join/"):
                    self._customer_error(HTTPStatus.FORBIDDEN,reason)
                else:
                    self._json(HTTPStatus(getattr(error,"http_status",403)), {"error": reason,
                        "reason":reason,"retryAfterSeconds":getattr(error,"retry_after",0)})
            except _HttpRequestError as error:
                if self.path.startswith("/join/"):
                    self._customer_error(error.status,error.code)
                else:
                    self._json(error.status, {"error": error.code})
            except (OSError, ValueError):
                LOGGER.warning("CSA-PORTAL-ERROR correlation=%s stage=%s", self.correlation_id, self.diagnostic_stage)
                self.diagnostic_code = "CSA-PORTAL-ERROR"
                self._bytes(HTTPStatus.INTERNAL_SERVER_ERROR,
                    PortalBinding.render_error_page(self.correlation_id), "text/html; charset=utf-8")

        def do_POST(self) -> None:
            self.correlation_id = uuid.uuid4().hex
            self.diagnostic_stage = "REQUEST_AUTHORIZATION"
            source = str(self.client_address[0])
            if not limiter.allow(source):
                self._json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "RATE_LIMIT"})
                return
            try:
                path = self._request_path()
                if path.startswith("/api/v1/pilot-launch/"):
                    identifier,action=self._pilot_route()
                    if action=="diagnostic" and simple_delivery is not None:
                        self.diagnostic_stage="CLIENT_DIAGNOSTIC"
                        value=json.loads(self._read_body(4096).decode('utf-8'))
                        simple_delivery.client_diagnostic(identifier,source,value)
                        self._json(HTTPStatus.OK,{"recorded":True,"assurance":"CLIENT_REPORTED_NOT_ATTESTATION"})
                        return
                    self._read_body(0)
                    self.diagnostic_stage="PILOT_PRIVATE_DELIVERY"
                    if action=="ticket":
                        code=self._credential("CSA-Pilot ")
                        self._json(HTTPStatus.OK,pilot_launch.ticket(identifier,source,code=code))
                    elif action=="package":
                        ticket=self._credential("CSA-Pilot-Ticket ")
                        self._bytes(HTTPStatus.OK,pilot_launch.package(identifier,source,ticket),"application/zip")
                    else:
                        raise _HttpRequestError(HTTPStatus.NOT_FOUND,"NOT_FOUND")
                elif path.startswith("/join/") and path.endswith("/pilot-activate"):
                    self.diagnostic_stage="PILOT_CUSTOMER_AUTHORIZATION"
                    from urllib.parse import parse_qs
                    parts=path.strip("/").split("/")
                    if len(parts)!=3 or portal is None or not portal.authorize(parts[1],source):
                        raise DistributionDenied()
                    if self.headers.get_content_type()!="application/x-www-form-urlencoded":
                        raise DistributionDenied()
                    data=parse_qs(self._read_body(512).decode("ascii"),strict_parsing=True)
                    if set(data)!={"code"} or len(data["code"])!=1:
                        raise DistributionDenied()
                    cookie=pilot_launch.login(data["code"][0],source)
                    self.send_response(HTTPStatus.SEE_OTHER)
                    self.send_header("Location","/join/"+parts[1]+"/")
                    self.send_header("Set-Cookie","__Host-CSA-Pilot="+cookie+"; Secure; HttpOnly; SameSite=Strict; Path=/")
                    self.send_header("Content-Length","0");self.send_header("Cache-Control","no-store")
                    self.end_headers()
                elif path.startswith("/api/v2/trusted/"):
                    self._trusted_post(source)
                elif path == "/api/v1/collector-package":
                    self.diagnostic_stage = "PACKAGE_DOWNLOAD"
                    self._read_body(0)
                    self._require_legacy(source)
                    authorization = self.headers.get("Authorization", "")
                    credential = authorization[len("CSA-Launcher "):] if authorization.startswith("CSA-Launcher ") else ""
                    if (portal is None or portal.script_collector_path is None or
                            not portal.authorize_launcher(credential, source)):
                        self._json(HTTPStatus.FORBIDDEN, {"error": "LAUNCHER_UNAVAILABLE"})
                        return
                    body = portal.script_collector_path.read_bytes()
                    portal.record_download(source)
                    self._bytes(HTTPStatus.OK, body, "application/zip")
                elif path == "/api/v1/nonce":
                    self.diagnostic_stage = "SUBMISSION_AUTHORIZATION"
                    self._nonce(source)
                elif path.startswith("/api/v1/submissions/"):
                    self.diagnostic_stage = "EVIDENCE_VALIDATION"
                    submission_id = path.rsplit("/", 1)[-1]
                    self._submission(source, submission_id)
                else:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "NOT_FOUND"})
            except DistributionDenied:
                if self.path.startswith("/join/"):
                    self._customer_error(HTTPStatus.FORBIDDEN,"TRUST_NOT_ESTABLISHED")
                else:
                    self._json(HTTPStatus.FORBIDDEN, {"error": "TRUST_NOT_ESTABLISHED"})
            except SubmissionRejected as error:
                self._json(
                    HTTPStatus.FORBIDDEN,
                    {"error": error.state.value, "message": error.safe_message},
                )
            except _HttpRequestError as error:
                if self.path.startswith("/join/"):
                    self._customer_error(error.status,error.code)
                else:
                    self._json(error.status, {"error": error.code})
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                if self.path.startswith("/join/"):
                    self._customer_error(HTTPStatus.BAD_REQUEST,"INVALID_REQUEST")
                else:
                    self._json(HTTPStatus.BAD_REQUEST,{"error":"INVALID_REQUEST"})
            except Exception:
                LOGGER.warning("CSA-SUBMISSION-ERROR correlation=%s stage=%s", self.correlation_id, self.diagnostic_stage)
                self._json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"error": "INTERNAL_ERROR"},
                )

        def _nonce(self, source: str) -> None:
            if self.headers.get_content_type() != "application/json":
                self._json(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                    {"error": "CONTENT_TYPE"},
                )
                return
            data = self._read_json(4096)
            submission_id = data.get("submissionId", "")
            token = self._token()
            if not submission_id or not token:
                self._json(
                    HTTPStatus.BAD_REQUEST, {"error": "MISSING_BINDING"}
                )
                return
            self._validate_submission_id(submission_id)
            nonce = submission_service.request_nonce(
                assessment_id,
                session_id,
                submission_id,
                token,
                source,
                trusted_envelope=(self.headers.get("X-CSA-Envelope", ""), self.headers.get("X-CSA-Envelope-Nonce", "")),
                requested_execution_mode=self.headers.get("X-CSA-Execution-Transport", "NOT_RECORDED"),
            )
            self._json(HTTPStatus.OK, {"nonce": nonce, "expiresIn": 120})

        def _submission(self, source: str, submission_id: str) -> None:
            self._validate_submission_id(submission_id)
            if self.headers.get_content_type() not in {
                "application/zip",
                "application/vnd.csa.submission+zip",
            }:
                self._json(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                    {"error": "CONTENT_TYPE"},
                )
                return
            token = self._token()
            nonce = str(self.headers.get("X-CSA-Nonce", ""))
            if not token or not nonce:
                self._json(
                    HTTPStatus.BAD_REQUEST, {"error": "MISSING_BINDING"}
                )
                return
            archive = self._read_body(
                submission_service.sessions.load_session(
                    assessment_id, session_id
                ).maximum_package_size
            )
            receipt, package, _path = submission_service.accept(
                assessment_id=assessment_id,
                session_id=session_id,
                submission_id=submission_id,
                enrollment_token=token,
                nonce=nonce,
                source_address=source,
                archive_bytes=archive,
            )
            analysis_state = "PENDING"
            if analyze_automatically:
                try:
                    pipeline.analyze(package)
                    reporter.generate_endpoint(assessment_id, submission_id)
                    analysis_state = "COMPLETED"
                except Exception:
                    LOGGER.warning("CSA-ANALYSIS-ERROR correlation=%s stage=POST_ACCEPTANCE", self.correlation_id)
                    analysis_state = "FAILED"
                    try:
                        submission_service.update_processing_state(assessment_id, submission_id, "ERROR")
                    except (OSError, ValueError):
                        LOGGER.warning("CSA-STATE-WRITE-FAILED correlation=%s stage=POST_ACCEPTANCE", self.correlation_id)
                    try:
                        ConsoleAuditLog(storage.path(assessment_id, "audit", "audit.jsonl")).append("post_acceptance_analysis_failed", {
                            "correlationId": self.correlation_id, "submissionId": submission_id,
                            "httpStatus": 201, "stage": "EVIDENCE_ACCEPTED_ANALYSIS_FAILED", "eventClass": "ACCEPTED_ANALYSIS_FAILED",
                            "code": "CSA-ANALYSIS-ERROR"})
                    except (OSError, ValueError):
                        LOGGER.warning("CSA-AUDIT-WRITE-FAILED correlation=%s stage=POST_ACCEPTANCE", self.correlation_id)
            response = model_to_dict(receipt)
            response["analysisState"] = analysis_state
            self.diagnostic_stage = "EVIDENCE_ACCEPTED_ANALYSIS_FAILED" if analysis_state == "FAILED" else "EVIDENCE_ACCEPTED"
            if analysis_state != "FAILED":
                try:
                    ConsoleAuditLog(storage.path(assessment_id, "audit", "audit.jsonl")).append("http_evidence_accepted", {
                        "correlationId": self.correlation_id, "submissionId": submission_id, "httpStatus": 201,
                        "stage": self.diagnostic_stage, "eventClass": "ACCEPTED", "code": "CSA-EVIDENCE-ACCEPTED"})
                except (OSError, ValueError):
                    LOGGER.warning("CSA-AUDIT-WRITE-FAILED correlation=%s stage=%s", self.correlation_id, self.diagnostic_stage)
            self._json(HTTPStatus.CREATED, response)

        def _token(self) -> str:
            values = self.headers.get_all("Authorization", [])
            value = values[0] if len(values) == 1 and len(values[0]) <= 256 else ""
            prefix = "CSA-Enrollment "
            return value[len(prefix) :] if value.startswith(prefix) else ""

        @staticmethod
        def _validate_submission_id(submission_id):
            if not isinstance(submission_id, str) or not re.fullmatch(r"SUB-[A-Za-z0-9_-]{1,96}", submission_id):
                raise _HttpRequestError(HTTPStatus.BAD_REQUEST, "INVALID_SUBMISSION_ID")

        def _read_json(self, maximum: int) -> dict[str, Any]:
            raw = self._read_body(maximum)
            def unique(pairs):
                result = {}
                for key, item in pairs:
                    if key in result:
                        raise _HttpRequestError(HTTPStatus.BAD_REQUEST, "DUPLICATE_JSON_FIELD")
                    result[key] = item
                return result
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
            if not isinstance(value, dict):
                raise ValueError("Request JSON root must be an object")
            return value

        def _read_body(self, maximum: int) -> bytes:
            if self.headers.get_all("Transfer-Encoding"):
                raise _HttpRequestError(
                    HTTPStatus.BAD_REQUEST, "CHUNKED_BODY_NOT_ACCEPTED"
                )
            try:
                lengths = self.headers.get_all("Content-Length", [])
                if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,10}", lengths[0]):
                    raise ValueError
                length = int(lengths[0])
            except ValueError as error:
                raise _HttpRequestError(
                    HTTPStatus.LENGTH_REQUIRED, "CONTENT_LENGTH_REQUIRED"
                ) from error
            if length < 0:
                raise _HttpRequestError(
                    HTTPStatus.BAD_REQUEST, "INVALID_CONTENT_LENGTH"
                )
            if length > maximum:
                raise _HttpRequestError(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    "REQUEST_BODY_TOO_LARGE",
                )
            body = self.rfile.read(length)
            if len(body) != length:
                raise _HttpRequestError(
                    HTTPStatus.BAD_REQUEST, "INCOMPLETE_REQUEST_BODY"
                )
            return body

        def _json(self, status: HTTPStatus, value: dict[str, Any]) -> None:
            if status >= 400:
                candidate = str(value.get("error", "HTTP_REQUEST_REJECTED"))
                self.diagnostic_code = candidate if re.fullmatch(r"[A-Z][A-Z0-9_-]{0,80}", candidate) else "HTTP_REQUEST_REJECTED"
                value = {**value, "correlationId": self.correlation_id, "stage": self.diagnostic_stage,
                         "eventClass": "REJECTED", "httpStatus": int(status)}
            body = json.dumps(
                value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
            self._bytes(status, body, "application/json")

        def _redirect(self, location: str) -> None:
            """Redirect an authorized portal URL to its canonical path."""

            self.send_response(HTTPStatus.PERMANENT_REDIRECT)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-CSA-Correlation-ID", getattr(self, "correlation_id", ""))
            self.send_header("X-CSA-Stage", getattr(self, "diagnostic_stage", "REQUEST"))
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()

        def _bytes(
            self,
            status: HTTPStatus,
            body: bytes,
            content_type: str,
            *,
            attachment: str | None = None,
        ) -> None:
            stage = getattr(self, "diagnostic_stage", "REQUEST_VALIDATION")
            event_class = ("REJECTED" if status >= 400 else "ACCEPTED_ANALYSIS_FAILED" if stage == "EVIDENCE_ACCEPTED_ANALYSIS_FAILED"
                           else "ACCEPTED" if stage == "EVIDENCE_ACCEPTED" else "DELIVERED")
            if status >= 400:
                self.close_connection = True
                code = getattr(self, "diagnostic_code", "HTTP_REQUEST_REJECTED")
                LOGGER.warning("CSA-HTTP-REJECTED correlation=%s stage=%s status=%s eventClass=%s code=%s",
                    self.correlation_id, stage, int(status), event_class, code)
                try:
                    ConsoleAuditLog(storage.path(assessment_id, "audit", "audit.jsonl")).append("http_request_rejected", {
                        "correlationId": self.correlation_id, "stage": stage, "httpStatus": int(status),
                        "eventClass": event_class, "code": code})
                except (OSError, ValueError):
                    LOGGER.warning("CSA-AUDIT-WRITE-FAILED correlation=%s stage=%s", self.correlation_id, stage)
            elif stage.startswith("TRUSTED_"):
                try:
                    ConsoleAuditLog(storage.path(assessment_id, "audit", "audit.jsonl")).append("http_trusted_phase_delivered", {
                        "correlationId": self.correlation_id, "stage": stage, "httpStatus": int(status),
                        "eventClass": event_class})
                except (OSError, ValueError):
                    LOGGER.warning("CSA-AUDIT-WRITE-FAILED correlation=%s stage=%s", self.correlation_id, stage)
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Pragma", "no-cache")
            if getattr(self,"_response_cookie",None):
                self.send_header("Set-Cookie",self._response_cookie)
                self._response_cookie=None
            if status >= 400:
                self.send_header("Connection", "close")
            self.send_header("X-CSA-Correlation-ID", getattr(self, "correlation_id", ""))
            self.send_header("X-CSA-Stage", getattr(self, "diagnostic_stage", "REQUEST"))
            self.send_header("X-CSA-Event-Class", event_class)
            self.send_header("X-CSA-Code", getattr(self, "diagnostic_code", "HTTP_REQUEST"))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-" + PORTAL_SCRIPT_HASH + "'; "
                "base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
            )
            self.send_header(
                "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
            )
            if attachment is not None:
                self.send_header(
                    "Content-Disposition", f'attachment; filename="{attachment}"'
                )
            self.end_headers()
            try:
                self.wfile.write(body)
            except (OSError, ConnectionError):
                LOGGER.warning("CSA-NETWORK-DELIVERY-INTERRUPTED correlation=%s stage=%s status=%s",
                    self.correlation_id, stage, int(status))
                self.close_connection = True

        def log_message(self, format: str, *args: Any) -> None:
            # BaseHTTPRequestHandler also calls this for malformed requests.
            # Its free-form error text can contain a URL or user-supplied bytes.
            status = str(args[1]) if len(args) > 1 else ""
            status = status if len(status) == 3 and status.isascii() and status.isdigit() else "unknown"
            LOGGER.info(
                "HTTPS request completed correlation=%s stage=%s status=%s",
                getattr(self, "correlation_id", ""),
                getattr(self, "diagnostic_stage", "REQUEST"),
                status,
            )

    return SubmissionHandler
