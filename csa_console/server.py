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
from urllib.parse import urlparse

from csa_console.network import validate_listen_address
from csa_console.pipeline import ConsoleAnalysisPipeline
from csa_console.reporting import ConsoleReportGenerator
from csa_console.serde import model_to_dict
from csa_console.sessions import AssessmentSessionService
from csa_console.storage import AssessmentStorage
from csa_console.submission import SubmissionRejected, SubmissionService
from csa_console.canonical import write_canonical_json
from csa_console.identifiers import utc_text

LOGGER = logging.getLogger(__name__)


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
    ) -> None:
        """Create a configured but not yet started HTTPS server."""

        self.storage = storage or AssessmentStorage()
        self.assessment_id = assessment_id
        self.session_id = session_id
        self.session = AssessmentSessionService(self.storage).load_session(
            assessment_id, session_id
        )
        self._stop_path = self.storage.path(
            assessment_id, "sessions", f"{session_id}.stop.json"
        )
        self._stop_path.unlink(missing_ok=True)
        self._stopped = threading.Event()
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
        )
        self._server = ThreadingHTTPServer(
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
        try:
            self._server.serve_forever(poll_interval=0.2)
        finally:
            self._stopped.set()
            self._server.server_close()

    def shutdown(self) -> None:
        """Stop accepting requests and close the listener."""

        self._server.shutdown()
        self._stopped.set()
        self._server.server_close()

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
):
    """Build a request handler bound to one assessment session."""

    submission_service = SubmissionService(storage)
    pipeline = ConsoleAnalysisPipeline(storage)
    reporter = ConsoleReportGenerator(storage)
    limiter = _RateLimiter()

    class SubmissionHandler(BaseHTTPRequestHandler):
        server_version = "CSA-Console/5.0"
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:
            source = str(self.client_address[0])
            if not limiter.allow(source):
                self._json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "RATE_LIMIT"})
                return
            path = urlparse(self.path).path
            try:
                if path == "/api/v1/nonce":
                    self._nonce(source)
                elif path.startswith("/api/v1/submissions/"):
                    submission_id = path.rsplit("/", 1)[-1]
                    self._submission(source, submission_id)
                else:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "NOT_FOUND"})
            except SubmissionRejected as error:
                self._json(
                    HTTPStatus.FORBIDDEN,
                    {"error": error.state.value, "message": error.safe_message},
                )
            except _HttpRequestError as error:
                self._json(error.status, {"error": error.code})
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                self._json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "INVALID_REQUEST"},
                )
            except Exception:
                LOGGER.exception("Submission request failed safely")
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
            submission_id = str(data.get("submissionId", ""))
            token = self._token()
            if not submission_id or not token:
                self._json(
                    HTTPStatus.BAD_REQUEST, {"error": "MISSING_BINDING"}
                )
                return
            nonce = submission_service.request_nonce(
                assessment_id,
                session_id,
                submission_id,
                token,
                source,
            )
            self._json(HTTPStatus.OK, {"nonce": nonce, "expiresIn": 120})

        def _submission(self, source: str, submission_id: str) -> None:
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
                    LOGGER.exception(
                        "Accepted submission analysis failed: %s", submission_id
                    )
                    analysis_state = "FAILED"
            response = model_to_dict(receipt)
            response["analysisState"] = analysis_state
            self._json(HTTPStatus.CREATED, response)

        def _token(self) -> str:
            value = str(self.headers.get("Authorization", ""))
            prefix = "CSA-Enrollment "
            return value[len(prefix) :] if value.startswith(prefix) else ""

        def _read_json(self, maximum: int) -> dict[str, Any]:
            raw = self._read_body(maximum)
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError("Request JSON root must be an object")
            return value

        def _read_body(self, maximum: int) -> bytes:
            if self.headers.get("Transfer-Encoding"):
                raise _HttpRequestError(
                    HTTPStatus.BAD_REQUEST, "CHUNKED_BODY_NOT_ACCEPTED"
                )
            try:
                length = int(self.headers.get("Content-Length", ""))
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
            body = json.dumps(
                value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            LOGGER.info("HTTPS request from %s: %s", self.client_address[0], args[0])

    return SubmissionHandler
