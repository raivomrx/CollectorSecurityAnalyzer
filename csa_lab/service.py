"""Shared CSA Lab application service used by GUI and automation adapters."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sys
import threading
import zipfile
from dataclasses import fields
from pathlib import Path
from typing import Any

from csa_console.audit import ConsoleAuditLog
from csa_console.archive import export_assessment_archive
from csa_console.collector_package import (
    create_collector_package,
    verify_collector_package,
)
from csa_console.enums import SessionStatus
from csa_console.fleet import FleetAnalyzer
from csa_console.identifiers import utc_text
from csa_console.offline import OfflineImportService
from csa_console.portal import PortalBinding
from csa_console.pipeline import ConsoleAnalysisPipeline
from csa_console.serde import model_to_dict
from csa_console.server import ConsoleHttpsServer
from csa_console.sessions import AssessmentSessionService
from csa_console.storage import AssessmentStorage
from csa_console.submission import SubmissionService
from csa_lab.collector_executable import build_bound_collector
from csa_lab.firewall import (
    FirewallManager,
    NullFirewallManager,
    WindowsFirewallManager,
)
from csa_lab.models import (
    AssessmentWizardRequest,
    EndpointDashboardItem,
    EndpointUiStatus,
    FirewallRuleSpec,
    LabAssessmentState,
    LabAssessmentStatus,
)


class LabApplicationService:
    """Orchestrate assessments without exposing security credentials to the UI."""

    def __init__(
        self,
        data_root: str | Path | None = None,
        *,
        firewall: FirewallManager | None = None,
        collector_bootstrap: str | Path | None = None,
        executable_path: str | Path | None = None,
    ) -> None:
        """Create the shared application service and scan for orphaned state."""

        root = Path(data_root) if data_root else default_data_root() / "assessments"
        self.storage = AssessmentStorage(root)
        self.sessions = AssessmentSessionService(self.storage)
        self.submissions = SubmissionService(self.storage)
        self.firewall = firewall or (
            WindowsFirewallManager() if os.name == "nt" else NullFirewallManager()
        )
        self.collector_bootstrap = Path(
            collector_bootstrap or _default_collector_bootstrap()
        ).resolve()
        self.executable_path = str(
            Path(executable_path or sys.executable).resolve()
        )
        self._servers: dict[str, ConsoleHttpsServer] = {}
        self._threads: dict[str, threading.Thread] = {}
        self._lock = threading.RLock()
        self._secret = self._load_or_create_join_secret()
        self._application_audit().append(
            "application_started",
            {"version": "5.1", "processId": os.getpid()},
        )
        self.detect_recovery_items()

    def create_assessment(
        self, request: AssessmentWizardRequest
    ) -> LabAssessmentState:
        """Create an assessment, bounded session and ready Collector executable."""

        request.validate()
        reference = request.reference_number or request.organization or "UNSPECIFIED"
        assessment = self.sessions.create_assessment(
            request.name,
            reference,
            created_by="CSA Lab",
        )
        try:
            session, token = self.sessions.open_session(
                assessment.assessment_id,
                expected_devices=request.expected_endpoints,
                allowed_submissions=int(request.allowed_submissions or 0),
                expires_in_hours=request.session_expiry_hours,
                allowed_source_networks=(
                    [request.source_subnet] if request.source_subnet else []
                ),
                listen_address=request.listener_address,
                listen_port=request.listener_port,
                created_by="CSA Lab",
            )
            package_directory = self.storage.path(
                assessment.assessment_id,
                "downloads",
                session.session_id,
                "package",
            )
            package_directory.mkdir(parents=True, exist_ok=True)
            create_collector_package(
                session,
                token,
                package_directory,
                server_url=(
                    f"https://{request.listener_address}:"
                    f"{request.listener_port}"
                ),
            )
            manifest = verify_collector_package(package_directory)
            self.sessions.trust_collector_build(
                session, str(manifest["collectorBuildDigest"])
            )
            collector_path = self.storage.path(
                assessment.assessment_id,
                "downloads",
                session.session_id,
                "CSA-Collector.exe",
            )
            build_bound_collector(
                self.collector_bootstrap,
                package_directory,
                collector_path,
            )
            state = LabAssessmentState(
                assessment_id=assessment.assessment_id,
                session_id=session.session_id,
                name=request.name,
                organization=request.organization,
                reference_number=request.reference_number,
                assessor_notes=request.assessor_notes,
                description=request.description,
                created_at=assessment.created_at,
                expected_endpoints=request.expected_endpoints,
                listener_address=request.listener_address,
                listener_port=request.listener_port,
                source_subnet=request.source_subnet,
                network_profile=request.network_profile,
                interface_id=request.interface_id,
                status=LabAssessmentStatus.DRAFT,
                expires_at=session.expires_at,
                offline_collection=request.offline_collection,
                firewall_rule_name=(
                    f"{WindowsFirewallManager.RULE_PREFIX}"
                    f"{assessment.assessment_id} {session.session_id[-8:]}"
                ),
                collector_path=str(collector_path),
                settings={
                    "collectionProfile": request.collection_profile,
                    "activeValidation": False,
                    "privacyMode": "strict",
                    "includeTechnicalEvidence": True,
                    "includeAudit": True,
                    "includeEndpointDetails": True,
                },
            )
            self._write_state(state)
            self._audit(assessment.assessment_id).append(
                "assessment_configuration_created",
                {
                    "sessionId": session.session_id,
                    "expectedEndpoints": request.expected_endpoints,
                    "offlineEnabled": request.offline_collection,
                },
            )
            self._audit(assessment.assessment_id).append(
                "certificate_created",
                {
                    "sessionId": session.session_id,
                    "certificateMode": "GENERATED",
                    "expiresAt": session.expires_at,
                },
            )
            return state
        except Exception:
            self._audit(assessment.assessment_id).append(
                "assessment_creation_failed", {"stage": "SESSION_OR_COLLECTOR"}
            )
            raise
        finally:
            token = ""

    def list_assessments(self) -> list[dict[str, Any]]:
        """Return newest-first GUI summaries without secret material."""

        values: list[dict[str, Any]] = []
        for path in sorted(
            self.storage.root.glob("*/lab-state.json"),
            key=lambda item: item.parent.name,
            reverse=True,
        ):
            state = self.load_state(path.parent.name)
            submissions = self.submissions.list_submissions(state.assessment_id)
            latest, all_items, _index = FleetAnalyzer(
                self.storage
            ).load_latest_endpoint_data(state.assessment_id)
            values.append(
                {
                    "assessmentId": state.assessment_id,
                    "name": state.name,
                    "createdAt": state.created_at,
                    "status": state.status.value,
                    "expectedEndpoints": state.expected_endpoints,
                    "uniqueEndpoints": len(latest),
                    "acceptedSubmissions": len(submissions),
                    "duplicateSubmissions": max(0, len(all_items) - len(latest)),
                    "reportStatus": (
                        "GENERATED" if state.report_path else "NOT_GENERATED"
                    ),
                }
            )
        return values

    def delete_draft_assessment(self, assessment_id: str) -> None:
        """Delete an empty draft after closing its unused session."""

        state = self.load_state(assessment_id)
        if state.status != LabAssessmentStatus.DRAFT:
            raise ValueError("Only an empty draft assessment can be deleted")
        self.delete_assessment(assessment_id)

    def delete_assessment(self, assessment_id: str) -> None:
        """Permanently delete a draft or terminal local assessment."""

        with self._lock:
            state = self.load_state(assessment_id)
            allowed_statuses = {
                LabAssessmentStatus.DRAFT,
                LabAssessmentStatus.CLOSED,
                LabAssessmentStatus.COMPLETED,
            }
            if state.status not in allowed_statuses:
                raise ValueError(
                    "Only a draft, closed, or completed assessment can be "
                    "deleted"
                )
            if assessment_id in self._servers:
                raise ValueError("Stop collection before deleting an assessment")
            if (
                state.status == LabAssessmentStatus.DRAFT
                and (
                    state.download_count
                    or state.report_path
                    or self.submissions.list_submissions(assessment_id)
                    or self.dashboard(assessment_id)
                )
            ):
                raise ValueError(
                    "This assessment contains activity or evidence and cannot "
                    "be deleted as a draft"
                )
            if self.firewall.exists(state.firewall_rule_name):
                raise ValueError(
                    "Temporary network access must be cleaned up before "
                    "deleting this assessment"
                )
            session = self.sessions.load_session(
                assessment_id, state.session_id
            )
            if session.status in {SessionStatus.OPEN, SessionStatus.PAUSED}:
                self.sessions.set_session_status(
                    assessment_id,
                    state.session_id,
                    SessionStatus.CLOSED,
                )
            self.sessions.close_assessment(assessment_id)
            assessment_audit = self._audit(assessment_id)
            assessment_audit.append(
                "assessment_deletion_requested",
                {
                    "assessmentId": assessment_id,
                    "sessionId": state.session_id,
                    "status": state.status.value,
                },
            )
            final_hash = assessment_audit.final_hash()
            self._application_audit().append(
                "assessment_deletion_started",
                {
                    "assessmentId": assessment_id,
                    "assessmentAuditFinalHash": final_hash,
                    "status": state.status.value,
                },
            )
            shutil.rmtree(self.storage.assessment_path(assessment_id))
            self._application_audit().append(
                "assessment_deleted",
                {
                    "assessmentId": assessment_id,
                    "assessmentAuditFinalHash": final_hash,
                    "status": state.status.value,
                },
            )

    def load_state(self, assessment_id: str) -> LabAssessmentState:
        """Load one persisted Lab assessment state."""

        data = self.storage.read_json(assessment_id, "lab-state.json")
        known = {item.name for item in fields(LabAssessmentState)}
        values: dict[str, Any] = {}
        for name in known:
            camel = name.split("_")[0] + "".join(
                part[:1].upper() + part[1:] for part in name.split("_")[1:]
            )
            if camel in data:
                values[name] = data[camel]
        values["status"] = LabAssessmentStatus(values["status"])
        state = LabAssessmentState(**values)
        portal_path = self.storage.path(
            assessment_id,
            "sessions",
            f"{state.session_id}.portal.json",
        )
        if portal_path.exists():
            portal = self.storage.read_json(
                assessment_id,
                "sessions",
                f"{state.session_id}.portal.json",
            )
            state.download_count = int(portal.get("downloadCount", 0))
        return state

    def start_collection(self, assessment_id: str) -> LabAssessmentState:
        """Start the scoped HTTPS portal and temporary firewall lifecycle."""

        with self._lock:
            if assessment_id in self._servers:
                return self.load_state(assessment_id)
            state = self.load_state(assessment_id)
            session = self.sessions.load_session(
                assessment_id, state.session_id
            )
            if session.status == SessionStatus.PAUSED:
                session = self.sessions.set_session_status(
                    assessment_id, state.session_id, SessionStatus.OPEN
                )
            if session.status != SessionStatus.OPEN:
                raise ValueError("Collection session is no longer active")
            code = self.join_code(assessment_id)
            portal = PortalBinding(
                assessment_id=assessment_id,
                session_id=state.session_id,
                join_code_hash=hashlib.sha256(code.encode("utf-8")).hexdigest(),
                collector_path=Path(state.collector_path),
                expires_at=state.expires_at,
                maximum_downloads=max(
                    state.expected_endpoints + 10,
                    session.allowed_submission_count + 5,
                ),
                storage=self.storage,
                download_count=state.download_count,
            )
            server = ConsoleHttpsServer(
                assessment_id,
                state.session_id,
                self.storage,
                portal=portal,
                analyze_automatically=True,
            )
            spec = FirewallRuleSpec(
                rule_name=state.firewall_rule_name,
                program_path=self.executable_path,
                local_address=state.listener_address,
                local_port=state.listener_port,
                remote_subnet=state.source_subnet,
                profile=state.network_profile,
            )
            try:
                self.firewall.create(spec)
                self._audit(assessment_id).append(
                    "firewall_rule_created",
                    {
                        "sessionId": state.session_id,
                        "ruleName": state.firewall_rule_name,
                        "localPort": state.listener_port,
                        "remoteSubnet": state.source_subnet,
                    },
                )
                thread = threading.Thread(
                    target=server.serve_forever,
                    name=f"CSA-{state.session_id[-8:]}",
                    daemon=True,
                )
                thread.start()
                self._servers[assessment_id] = server
                self._threads[assessment_id] = thread
                self._write_portal_status(state, active=True)
                self._audit(assessment_id).append(
                    "download_portal_activated",
                    {
                        "sessionId": state.session_id,
                        "expiresAt": state.expires_at,
                    },
                )
            except Exception:
                server.shutdown()
                self.firewall.remove(state.firewall_rule_name)
                raise
            state.status = LabAssessmentStatus.COLLECTING
            state.recovery_details = []
            self._write_state(state)
            self._audit(assessment_id).append(
                "collection_started",
                {
                    "sessionId": state.session_id,
                    "listenAddress": state.listener_address,
                    "listenPort": state.listener_port,
                },
            )
            return state

    def pause_collection(self, assessment_id: str) -> LabAssessmentState:
        """Pause new activity while preserving all received evidence."""

        with self._lock:
            state = self.load_state(assessment_id)
            self._stop_runtime(state)
            self.sessions.set_session_status(
                assessment_id, state.session_id, SessionStatus.PAUSED
            )
            state.status = LabAssessmentStatus.PAUSED
            self._write_state(state)
            self._audit(assessment_id).append(
                "collection_paused", {"sessionId": state.session_id}
            )
            return state

    def resume_collection(self, assessment_id: str) -> LabAssessmentState:
        """Resume a paused session with the same scoped security controls."""

        state = self.load_state(assessment_id)
        if state.status not in {
            LabAssessmentStatus.PAUSED,
            LabAssessmentStatus.RECOVERY_REQUIRED,
        }:
            raise ValueError("Only a paused assessment can be resumed")
        self.sessions.set_session_status(
            assessment_id, state.session_id, SessionStatus.OPEN
        )
        self._audit(assessment_id).append(
            "collection_resumed", {"sessionId": state.session_id}
        )
        return self.start_collection(assessment_id)

    def stop_collection(self, assessment_id: str) -> LabAssessmentState:
        """Close credentials, listener, portal and temporary firewall access."""

        with self._lock:
            state = self.load_state(assessment_id)
            self._stop_runtime(state)
            session = self.sessions.load_session(
                assessment_id, state.session_id
            )
            if session.status != SessionStatus.CLOSED:
                self.sessions.set_session_status(
                    assessment_id, state.session_id, SessionStatus.CLOSED
                )
            endpoint_count = len(self.dashboard(assessment_id))
            state.status = (
                LabAssessmentStatus.READY_FOR_REPORT
                if endpoint_count
                else LabAssessmentStatus.CLOSED
            )
            state.recovery_details = []
            self._write_state(state)
            self._audit(assessment_id).append(
                "collection_stopped", {"sessionId": state.session_id}
            )
            return state

    def join_code(self, assessment_id: str) -> str:
        """Derive a high-entropy non-persisted code for the active session."""

        state = self.load_state(assessment_id)
        digest = hmac.digest(
            self._secret,
            f"{state.assessment_id}|{state.session_id}".encode("utf-8"),
            "sha256",
        )
        value = base64.b32encode(digest).decode("ascii").rstrip("=")[:24]
        return value

    def portal_url(self, assessment_id: str) -> str:
        """Return the user-facing portal address for one assessment."""

        state = self.load_state(assessment_id)
        return (
            f"https://{state.listener_address}:{state.listener_port}/join/"
            f"{self.join_code(assessment_id)}/"
        )

    def dashboard(self, assessment_id: str) -> list[EndpointDashboardItem]:
        """Build a latest-submission endpoint dashboard."""

        latest, _all, index = FleetAnalyzer(
            self.storage
        ).load_latest_endpoint_data(assessment_id)
        metadata = {
            str(item.get("submissionId")): item
            for item in index
            if isinstance(item, dict)
        }
        result: list[EndpointDashboardItem] = []
        analyzed_submissions: set[str] = set()
        for endpoint in latest:
            submission_id = str(endpoint["submissionId"])
            analyzed_submissions.add(submission_id)
            item = metadata.get(submission_id, {})
            evidence_path = self.storage.path(
                assessment_id, "normalized", f"{submission_id}.json"
            )
            evidence = (
                self.storage.read_json(
                    assessment_id, "normalized", f"{submission_id}.json"
                )
                if evidence_path.exists()
                else {}
            )
            privilege = evidence.get("privilegeContext", {})
            severity_counts: dict[str, int] = {}
            for finding in endpoint.get("findings", []):
                value = finding.get("finding", {})
                if value.get("status") not in {"FAIL", "WARNING"}:
                    continue
                severity = str(value.get("severity", "INFO"))
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            limitations = endpoint.get("coverage", {}).get("limitations", [])
            receipt_path = self.storage.path(
                assessment_id,
                "submissions",
                "accepted",
                f"{submission_id}.receipt.json",
            )
            receipt_status = "VERIFIED" if receipt_path.exists() else "MISSING"
            result.append(
                EndpointDashboardItem(
                    device_id=str(endpoint.get("deviceId", "UNKNOWN")),
                    submission_id=submission_id,
                    status=EndpointUiStatus.COMPLETE,
                    transport=_transport_label(
                        str(item.get("transport", "UNKNOWN"))
                    ),
                    coverage_percent=float(
                        endpoint.get("coverage", {}).get(
                            "overallCoveragePercent", 0.0
                        )
                    ),
                    finding_count=len(endpoint.get("findings", [])),
                    received_at=str(item.get("receivedAt", "")),
                    collector_version=str(
                        evidence.get("collectorVersion", "UNKNOWN")
                    ),
                    execution_mode=str(
                        privilege.get("executionMode", "UNKNOWN")
                    ),
                    integrity_level=str(
                        privilege.get("integrityLevel", "UNKNOWN")
                    ),
                    is_elevated=bool(privilege.get("isElevated", False)),
                    local_administrator_member=privilege.get(
                        "isLocalAdministratorMember"
                    ),
                    receipt_status=receipt_status,
                    evidence_digest=str(endpoint.get("evidenceSetDigest", "")),
                    severity_counts=dict(sorted(severity_counts.items())),
                    capability_gaps=[
                        value for value in limitations if isinstance(value, dict)
                    ],
                    cve_analysis_status=str(
                        endpoint.get(
                            "cveAnalysisStatus", "NOT_PERFORMED"
                        )
                    ),
                    cve_summary=dict(endpoint.get("cveSummary", {})),
                )
            )
        pending_states = {
            "RECEIVED": EndpointUiStatus.RECEIVED,
            "VALIDATING": EndpointUiStatus.VALIDATING,
            "NORMALIZING": EndpointUiStatus.NORMALIZING,
            "ANALYZING": EndpointUiStatus.ANALYZING,
            "ERROR": EndpointUiStatus.ERROR,
        }
        for item in index:
            submission_id = str(item.get("submissionId", ""))
            if not submission_id or submission_id in analyzed_submissions:
                continue
            processing = str(
                item.get("processingState", "RECEIVED")
            )
            result.append(
                EndpointDashboardItem(
                    device_id=str(item.get("deviceId", "UNKNOWN")),
                    submission_id=submission_id,
                    status=pending_states.get(
                        processing, EndpointUiStatus.RECEIVED
                    ),
                    transport=_transport_label(
                        str(item.get("transport", "UNKNOWN"))
                    ),
                    coverage_percent=None,
                    finding_count=None,
                    received_at=str(item.get("receivedAt", "")),
                    collector_version="PENDING",
                    execution_mode="PENDING",
                    integrity_level="PENDING",
                    is_elevated=False,
                    local_administrator_member=None,
                    receipt_status="PENDING",
                    evidence_digest=str(item.get("packageDigest", "")),
                    cve_analysis_status="PENDING",
                )
            )
        latest_by_device: dict[str, EndpointDashboardItem] = {}
        for item in sorted(
            result, key=lambda value: (value.received_at, value.submission_id)
        ):
            latest_by_device[item.device_id] = item
        return [
            latest_by_device[key] for key in sorted(latest_by_device)
        ]

    def import_offline(
        self, assessment_id: str, package_path: str | Path
    ) -> EndpointDashboardItem:
        """Import and analyze one authenticated encrypted offline package."""

        package = OfflineImportService(self.storage).import_file(
            assessment_id, package_path, analyze=True
        )
        self._audit(assessment_id).append(
            "offline_import_completed",
            {"submissionId": str(package.manifest["submissionId"])},
        )
        item = next(
            value
            for value in self.dashboard(assessment_id)
            if value.submission_id == package.manifest["submissionId"]
        )
        return item

    def run_cve_analysis(
        self, assessment_id: str
    ) -> list[EndpointDashboardItem]:
        """Run CVE analysis for every latest completed endpoint."""

        state = self.load_state(assessment_id)
        if state.status == LabAssessmentStatus.DRAFT:
            raise ValueError(
                "At least one completed endpoint analysis is required"
            )
        latest, _all, _index = FleetAnalyzer(
            self.storage
        ).load_latest_endpoint_data(assessment_id)
        if not latest:
            raise ValueError(
                "At least one completed endpoint analysis is required"
            )
        audit = self._audit(assessment_id)
        audit.append(
            "assessment_cve_analysis_started",
            {"endpointCount": len(latest)},
        )
        pipeline = ConsoleAnalysisPipeline(self.storage)
        completed = 0
        partial = 0
        failed = 0
        for endpoint in latest:
            result = pipeline.retry_analysis(
                assessment_id,
                str(endpoint["submissionId"]),
                run_cve=True,
            )
            if result.cve_analysis_status == "COMPLETE":
                completed += 1
            elif result.cve_analysis_status == "PARTIAL":
                partial += 1
            else:
                failed += 1
        audit.append(
            "assessment_cve_analysis_completed",
            {
                "endpointCount": len(latest),
                "complete": completed,
                "partial": partial,
                "failed": failed,
            },
        )
        if state.report_path:
            state.report_path = ""
            state.report_generated_at = ""
            if state.status == LabAssessmentStatus.COMPLETED:
                state.status = LabAssessmentStatus.READY_FOR_REPORT
            self._write_state(state)
        return self.dashboard(assessment_id)

    def generate_unified_report(
        self,
        assessment_id: str,
        *,
        include_technical_evidence: bool = True,
        include_audit: bool = True,
        include_endpoint_details: bool = True,
        allow_without_cve: bool = False,
    ) -> Path:
        """Generate the one primary self-contained assessment report."""

        from csa_lab.unified_report import UnifiedReportGenerator

        state = self.load_state(assessment_id)
        if state.status not in {
            LabAssessmentStatus.READY_FOR_REPORT,
            LabAssessmentStatus.COMPLETED,
        }:
            raise ValueError(
                "Stop collection before generating the final report"
            )
        endpoints = self.dashboard(assessment_id)
        if not any(
            item.status == EndpointUiStatus.COMPLETE for item in endpoints
        ):
            raise ValueError(
                "At least one completed endpoint analysis is required"
            )
        incomplete_cve = [
            item
            for item in endpoints
            if item.status == EndpointUiStatus.COMPLETE
            and item.cve_analysis_status != "COMPLETE"
        ]
        if incomplete_cve and not allow_without_cve:
            raise ValueError("CVE analysis is not complete")
        if incomplete_cve:
            self._audit(assessment_id).append(
                "report_without_complete_cve_acknowledged",
                {
                    "endpointCount": len(incomplete_cve),
                    "statuses": sorted(
                        {
                            item.cve_analysis_status
                            for item in incomplete_cve
                        }
                    ),
                },
            )
        output = UnifiedReportGenerator(self.storage).generate(
            assessment_id,
            include_technical_evidence=include_technical_evidence,
            include_audit=include_audit,
            include_endpoint_details=include_endpoint_details,
        )
        state.report_path = str(output)
        state.report_generated_at = utc_text()
        state.status = LabAssessmentStatus.COMPLETED
        self._write_state(state)
        return output

    def audit_status(self, assessment_id: str) -> dict[str, Any]:
        """Verify and return the assessment audit chain summary."""

        return self._audit(assessment_id).verify()

    def export_archive(
        self,
        assessment_id: str,
        passphrase: str,
    ) -> Path:
        """Export one assessment as an encrypted, verifiable archive."""

        self.load_state(assessment_id)
        export_root = self.storage.root.parent / "exports"
        export_root.mkdir(parents=True, exist_ok=True)
        stamp = utc_text().replace(":", "").replace("-", "")
        output = export_root / f"{assessment_id}-{stamp}.csa-archive"
        return export_assessment_archive(
            self.storage,
            assessment_id,
            output,
            passphrase,
        )

    def export_diagnostic_bundle(self) -> Path:
        """Export sanitized logs and aggregate health metadata for support."""

        application_root = self.storage.root.parent
        diagnostics_root = application_root / "diagnostics"
        diagnostics_root.mkdir(parents=True, exist_ok=True)
        stamp = utc_text().replace(":", "").replace("-", "")
        output = diagnostics_root / f"CSA-Diagnostics-{stamp}.zip"
        assessments: list[dict[str, Any]] = []
        for item in self.list_assessments():
            assessment_id = str(item["assessmentId"])
            try:
                audit = self.audit_status(assessment_id)
            except Exception:
                audit = {"auditVerificationStatus": "FAILED"}
            assessments.append(
                {
                    "assessmentReference": hashlib.sha256(
                        assessment_id.encode("utf-8")
                    ).hexdigest()[:16],
                    "status": item["status"],
                    "auditStatus": audit.get(
                        "auditVerificationStatus", "FAILED"
                    ),
                }
            )
        summary = {
            "schemaVersion": "5.1",
            "generatedAt": utc_text(),
            "applicationVersion": "5.1",
            "assessmentCount": len(assessments),
            "assessments": assessments,
            "containsEvidence": False,
            "containsCredentials": False,
        }
        with zipfile.ZipFile(
            output,
            "w",
            zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            archive.writestr(
                "diagnostic-summary.json",
                json.dumps(
                    summary,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                ),
            )
            log_root = application_root / "logs"
            for path in sorted(log_root.glob("csa-lab.log*")):
                if not path.is_file():
                    continue
                content = path.read_text(
                    encoding="utf-8", errors="replace"
                )
                archive.writestr(
                    f"logs/{path.name}",
                    _sanitize_diagnostic_log(content),
                )
        self._application_audit().append(
            "diagnostic_bundle_exported",
            {"bundleDigest": hashlib.sha256(output.read_bytes()).hexdigest()},
        )
        return output

    def detect_recovery_items(self) -> list[LabAssessmentState]:
        """Mark orphaned active state without deleting evidence."""

        recovered: list[LabAssessmentState] = []
        for path in self.storage.root.glob("*/lab-state.json"):
            state = self.load_state(path.parent.name)
            details: list[str] = []
            if state.status == LabAssessmentStatus.COLLECTING:
                details.append("Collection was active when CSA Lab stopped")
            if self.firewall.exists(state.firewall_rule_name):
                details.append("Temporary firewall rule remains active")
            stop_marker = self.storage.path(
                state.assessment_id,
                "sessions",
                f"{state.session_id}.stop.json",
            )
            if stop_marker.exists():
                details.append("Stale listener stop marker exists")
            if details:
                state.status = LabAssessmentStatus.RECOVERY_REQUIRED
                state.recovery_details = details
                self._write_state(state)
                self._audit(state.assessment_id).append(
                    "crash_recovery_detected",
                    {
                        "sessionId": state.session_id,
                        "conditionCount": len(details),
                    },
                )
                recovered.append(state)
        return recovered

    def cleanup_recovery(self, assessment_id: str) -> LabAssessmentState:
        """Close orphaned access while retaining assessment evidence."""

        state = self.load_state(assessment_id)
        self._stop_runtime(state)
        marker = self.storage.path(
            assessment_id,
            "sessions",
            f"{state.session_id}.stop.json",
        )
        marker.unlink(missing_ok=True)
        session = self.sessions.load_session(assessment_id, state.session_id)
        if session.status != SessionStatus.CLOSED:
            self.sessions.set_session_status(
                assessment_id, state.session_id, SessionStatus.CLOSED
            )
        state.status = (
            LabAssessmentStatus.READY_FOR_REPORT
            if self.dashboard(assessment_id)
            else LabAssessmentStatus.CLOSED
        )
        state.recovery_details = []
        self._write_state(state)
        self._audit(assessment_id).append(
            "crash_recovery_cleaned",
            {"sessionId": state.session_id, "evidenceRetained": True},
        )
        return state

    def shutdown(self) -> None:
        """Stop all in-process listeners and remove temporary firewall rules."""

        with self._lock:
            for assessment_id in list(self._servers):
                state = self.load_state(assessment_id)
                self._stop_runtime(state)
                self.sessions.set_session_status(
                    assessment_id, state.session_id, SessionStatus.PAUSED
                )
                state.status = LabAssessmentStatus.PAUSED
                self._write_state(state)
                self._audit(assessment_id).append(
                    "application_collection_shutdown",
                    {"sessionId": state.session_id},
                )
            self._application_audit().append(
                "application_shutdown", {"processId": os.getpid()}
            )

    def _stop_runtime(self, state: LabAssessmentState) -> None:
        server = self._servers.pop(state.assessment_id, None)
        thread = self._threads.pop(state.assessment_id, None)
        if server is not None:
            server.shutdown()
        if thread is not None:
            thread.join(timeout=10)
        rule_existed = self.firewall.exists(state.firewall_rule_name)
        self.firewall.remove(state.firewall_rule_name)
        self._write_portal_status(state, active=False)
        audit = self._audit(state.assessment_id)
        audit.append(
            "download_portal_deactivated",
            {"sessionId": state.session_id},
        )
        if rule_existed:
            audit.append(
                "firewall_rule_removed",
                {
                    "sessionId": state.session_id,
                    "ruleName": state.firewall_rule_name,
                },
            )

    def _write_state(self, state: LabAssessmentState) -> Path:
        return self.storage.write_json(
            state.assessment_id, ("lab-state.json",), model_to_dict(state)
        )

    def _write_portal_status(
        self, state: LabAssessmentState, *, active: bool
    ) -> Path:
        """Persist non-secret portal lifecycle metadata."""

        existing_path = self.storage.path(
            state.assessment_id,
            "sessions",
            f"{state.session_id}.portal.json",
        )
        download_count = state.download_count
        maximum_downloads = state.expected_endpoints + 10
        if existing_path.exists():
            existing = self.storage.read_json(
                state.assessment_id,
                "sessions",
                f"{state.session_id}.portal.json",
            )
            download_count = int(existing.get("downloadCount", download_count))
            maximum_downloads = int(
                existing.get("maximumDownloads", maximum_downloads)
            )
        return self.storage.write_json(
            state.assessment_id,
            ("sessions", f"{state.session_id}.portal.json"),
            {
                "assessmentId": state.assessment_id,
                "sessionId": state.session_id,
                "expiresAt": state.expires_at,
                "maximumDownloads": maximum_downloads,
                "downloadCount": download_count,
                "active": active,
            },
        )

    def _audit(self, assessment_id: str) -> ConsoleAuditLog:
        return ConsoleAuditLog(
            self.storage.path(assessment_id, "audit", "audit.jsonl")
        )

    def _application_audit(self) -> ConsoleAuditLog:
        return ConsoleAuditLog(
            self.storage.root.parent / "audit" / "application.jsonl"
        )

    def _load_or_create_join_secret(self) -> bytes:
        config = self.storage.root.parent / "config"
        config.mkdir(parents=True, exist_ok=True)
        path = config / "join-secret.bin"
        if not path.exists():
            temporary = path.with_suffix(".tmp")
            temporary.write_bytes(secrets.token_bytes(32))
            temporary.replace(path)
            path.chmod(0o600)
        secret = path.read_bytes()
        if len(secret) != 32:
            raise ValueError("CSA Lab join secret is invalid")
        return secret


def default_data_root() -> Path:
    """Return the Windows application data root used by packaged CSA Lab."""

    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "CSA"
    return Path.home() / ".csa-lab"


def _transport_label(value: str) -> str:
    """Return a precise user-facing transport label."""

    labels = {
        "HTTPS": "HTTPS submission",
        "OFFLINE_ENCRYPTED": "Encrypted offline import",
    }
    return labels.get(value, value.replace("_", " ").title())


def _default_collector_bootstrap() -> Path:
    override = os.environ.get("CSA_COLLECTOR_BOOTSTRAP")
    if override:
        return Path(override)
    packaged = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
    candidates = (
        packaged / "collector-bootstrapper" / "CSA-Collector.exe",
        Path(__file__).resolve().parents[1]
        / "build"
        / "collector"
        / "CSA-Collector.exe",
    )
    return next((item for item in candidates if item.exists()), candidates[-1])


def _sanitize_diagnostic_log(value: str) -> str:
    """Remove credentials, network identities and local paths from logs."""

    sanitized = re.sub(
        r"(?i)\b(token|password|secret|private[_ ]?key)"
        r"\s*[=:]\s*[^\s,;]+",
        r"\1=[REDACTED]",
        value,
    )
    sanitized = re.sub(
        r"(?<![0-9a-fA-F])(?:\d{1,3}\.){3}\d{1,3}(?![0-9a-fA-F])",
        "[REDACTED_IP]",
        sanitized,
    )
    return re.sub(
        r"(?i)\b[A-Z]:\\(?:[^\\\r\n]+\\)*[^\\\r\n]*",
        "[REDACTED_PATH]",
        sanitized,
    )
