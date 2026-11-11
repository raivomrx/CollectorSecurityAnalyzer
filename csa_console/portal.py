"""Assessment-bound Collector download portal state and authorization."""

from __future__ import annotations

import hashlib
import hmac
import html
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from csa_console.audit import ConsoleAuditLog
from csa_console.distribution import DistributionPolicy, DistributionState
from csa_console.quick_start import PORTAL_SCRIPT, quick_start_command
from csa_console.canonical import write_canonical_json
from csa_console.enums import SessionStatus
from csa_console.network import source_is_allowed
from csa_console.sessions import AssessmentSessionService
from csa_console.storage import AssessmentStorage


JOIN_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
JOIN_CODE_LENGTH = 8


def normalize_join_code(value: str) -> str:
    """Return the canonical human-readable join-code representation."""

    normalized = value.strip().upper()
    if len(normalized) == JOIN_CODE_LENGTH + 1:
        if normalized[4] != "-":
            return ""
        compact = normalized[:4] + normalized[5:]
    elif len(normalized) == JOIN_CODE_LENGTH and "-" not in normalized:
        compact = normalized
    else:
        return ""
    if len(compact) != JOIN_CODE_LENGTH or any(
        character not in JOIN_CODE_ALPHABET for character in compact
    ):
        return ""
    return f"{compact[:4]}-{compact[4:]}"


@dataclass(slots=True)
class PortalBinding:
    """Bind one opaque join code to the session's Collector transports."""

    assessment_id: str
    session_id: str
    join_code_hash: str
    collector_path: Path
    expires_at: str
    maximum_downloads: int
    storage: AssessmentStorage
    script_collector_path: Path | None = None
    launcher_bytes: bytes = field(default=b"", repr=False)
    launcher_token_hash: str = field(default="", repr=False)
    download_count: int = 0
    maximum_failed_attempts: int = 5
    failure_window_seconds: float = 60.0
    throttle_seconds: float = 30.0
    failed_authorization_count: int = 0
    distribution_policy: DistributionPolicy = field(default_factory=DistributionPolicy)
    throttled_authorization_count: int = 0
    _failed_attempts: dict[str, list[float]] = field(
        default_factory=dict, repr=False, compare=False
    )
    _blocked_until: dict[str, float] = field(
        default_factory=dict, repr=False, compare=False
    )
    _lock: threading.Lock = field(
        default_factory=threading.Lock, repr=False, compare=False
    )

    def authorize(self, join_code: str, source_address: str) -> bool:
        """Validate code, session, expiry, source scope and download budget."""

        now = time.monotonic()
        with self._lock:
            if now < self._blocked_until.get(source_address, 0.0):
                self.throttled_authorization_count += 1
                return False

        normalized = normalize_join_code(join_code)
        supplied = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(supplied, self.join_code_hash):
            self._record_failed_authorization(source_address, now)
            return False
        return self._authorize_session(source_address)

    def authorize_launcher(self, credential: str, source_address: str) -> bool:
        """Check a download-only header credential; never use a secret URL."""
        now = time.monotonic()
        with self._lock:
            if now < self._blocked_until.get(source_address, 0.0):
                self.throttled_authorization_count += 1
                return False
        supplied = hashlib.sha256(credential.encode("utf-8")).hexdigest()
        if not self.launcher_token_hash or not hmac.compare_digest(supplied, self.launcher_token_hash):
            self._record_failed_authorization(source_address, now)
            return False
        return self._authorize_session(source_address)

    def _authorize_session(self, source_address: str) -> bool:
        """Apply the same source, state, expiry and budget to all transports."""
        now = time.monotonic()
        session = AssessmentSessionService(self.storage).load_session(
            self.assessment_id, self.session_id
        )
        if session.status != SessionStatus.OPEN:
            return False
        if datetime.now(timezone.utc) >= datetime.fromisoformat(
            self.expires_at.replace("Z", "+00:00")
        ):
            return False
        if not source_is_allowed(session, source_address):
            self._record_failed_authorization(source_address, now)
            return False
        with self._lock:
            return self.download_count < self.maximum_downloads

    def _record_failed_authorization(
        self, source_address: str, now: float
    ) -> None:
        """Count a failed attempt without retaining attacker-supplied data."""

        with self._lock:
            cutoff = now - self.failure_window_seconds
            attempts = [
                attempt
                for attempt in self._failed_attempts.get(source_address, [])
                if attempt >= cutoff
            ]
            attempts.append(now)
            self._failed_attempts[source_address] = attempts
            self.failed_authorization_count += 1
            if len(attempts) >= self.maximum_failed_attempts:
                self._blocked_until[source_address] = now + self.throttle_seconds
                self.throttled_authorization_count += 1
        ConsoleAuditLog(
            self.storage.path(self.assessment_id, "audit", "audit.jsonl")
        ).append(
            "collector_portal_authorization_failed",
            {
                "sessionId": self.session_id,
                "sourceAddressHash": "sha256:" + hashlib.sha256(source_address.encode("utf-8")).hexdigest(),
                "failedAttemptCount": self.failed_authorization_count,
            },
        )

    def record_download(self, source_address: str) -> None:
        """Atomically count and audit a successful download without the code."""

        with self._lock:
            if self.download_count >= self.maximum_downloads:
                raise ValueError("Collector download limit reached")
            self.download_count += 1
            count = self.download_count
            write_canonical_json(
                self.storage.path(
                    self.assessment_id,
                    "sessions",
                    f"{self.session_id}.portal.json",
                ),
                {
                    "assessmentId": self.assessment_id,
                    "sessionId": self.session_id,
                    "expiresAt": self.expires_at,
                    "maximumDownloads": self.maximum_downloads,
                    "downloadCount": count,
                    "active": True,
                },
            )
        ConsoleAuditLog(
            self.storage.path(self.assessment_id, "audit", "audit.jsonl")
        ).append(
            "collector_downloaded",
            {
                "sessionId": self.session_id,
                "sourceAddressHash": "sha256:" + hashlib.sha256(source_address.encode("utf-8")).hexdigest(),
                "downloadCount": count,
            },
        )

    def render_page(self, assessment_name: str, network_options=None, *, development_available=False) -> bytes:
        """Render the small remote-safe download page."""

        safe_name = html.escape(assessment_name)
        safe_expiry = html.escape(self.expires_at)
        development = self.distribution_policy.state == DistributionState.DEVELOPMENT_UNSIGNED and development_available
        distribution_label = (DistributionState.DEVELOPMENT_UNSIGNED if development
                              else DistributionState.TRUST_ENROLLMENT_PENDING).value
        network_options = network_options or []
        if network_options:
            development = False
            distribution_label = "TEST_ONLY — isolated loopback fixtures" if any(option["assurance"] == "TEST_ONLY" for option in network_options) else network_options[0]["approvalState"]
            if distribution_label in {"PILOT_APPROVED", "RELEASE_APPROVED"}:
                distribution_label = "PILOT_READY"
        legacy_option = ('''<p><strong>Restricted assessor development only — UNSIGNED LAB ONLY.</strong></p>
  <p><a class="button" href="download">Development Collector (.exe) — unsigned; not approved for customers</a></p>'''
            if development else '''<p><strong>TRUST_NOT_ESTABLISHED</strong>: customer downloads are blocked.</p>
  <p>Ask the assessor for an independently approved signed handoff. No executable or script download is authorized by this page.</p>''')
        if network_options:
            legacy_option = '<p>Unsigned legacy downloads are blocked. The authenticated Collector options are below.</p>'
        quick_options = []
        for index, option in enumerate(network_options):
            from csa_console.quick_start import exe_start_command
            from datetime import datetime, timezone
            expiry = datetime.fromtimestamp(option["expiresAt"], timezone.utc).isoformat()
            quick_options.append('<article><p>Recipient: ' + html.escape(option["recipientId"]) +
                '<br>Publisher key: ' + html.escape(option["publisherKeyId"]) +
                '<br>Publisher certificate SHA-256: ' + html.escape(option["publisherCertificateSha256"]) +
                '<br>Target Lab: ' + html.escape(option["labId"]) + ' / ' + html.escape(option["origin"]) +
                '<br>Command expires (UTC): ' + html.escape(expiry) +
                '<br>Independent enrollment: ' + html.escape(option["copyState"]) + '</p>')
            quick_options.append('<p><strong>EXE Collector — enrolled launcher (CMD)</strong></p><pre><code>' +
                html.escape(exe_start_command(option["labId"], option["envelopeId"])) +
                '</code></pre><p>The signed immutable EXE is independently supplied once; no session overlay modifies it. Choose EXE or PowerShell for this one-use invitation; a second run requires a new invitation.</p>')
            for quick_run in (False, True):
                identifier = 'trusted-command-' + str(index) + ('-quick' if quick_run else '-standard')
                command = quick_start_command(option["labId"], option["envelopeId"], quick_run=quick_run)
                label = 'Quick Run – ExecutionPolicy Bypass' if quick_run else 'Copy command — standard policy'
                quick_options.append('<pre><code id="' + identifier + '">' + html.escape(command) + '</code></pre>' +
                    '<button type="button" data-copy-command="' + identifier + '">' + label + '</button>')
            quick_options.append('<p>Paste only after independently authenticating this command source. Enter the separately delivered one-time assessor authorization only when the installed verifier prompts after trust checks.</p></article>')
        quick_content = ''.join(quick_options) if quick_options else '''<p id="copy-quick-start-status"><strong>TRUST_ENROLLMENT_PENDING / TRUST_NOT_ESTABLISHED</strong>.
      There is no current invitation with independent publisher, Lab and command-origin approval. Ask the assessor for an authorized handoff.</p>
    <p><strong>SETUP_REQUIRED</strong>: the assessor opens local Lab Settings → Distribution → Pilot readiness / Enroll trust. Check the selected transport's package identity, exact origin/TLS, independent handoff, endpoint scope/expiry and acceptance evidence. This public page cannot approve them.</p>
    <button type="button" disabled aria-describedby="copy-quick-start-status">Copy command</button>
    <button type="button" disabled aria-describedby="copy-quick-start-status">Quick Run – ExecutionPolicy Bypass</button>'''
        script_option = ""
        if development and self.script_collector_path is not None and self.script_collector_path.is_file():
            script_option = """<p><a class="button" href="download-powershell">PowerShell Offline Package (.zip) — Manual/offline fallback</a></p>
  <p>Extract all files from <strong>CSA-PowerShell-Collector.zip</strong> into a new folder.
     Open a standard-user PowerShell window in that folder and run:</p>
  <pre><code>.\\Invoke-CSACollector.ps1</code></pre>
  <p>Organization execution restrictions still apply. The ZIP can be transferred for manual/offline use;
     use <code>-NoSubmit -ExportPath &lt;path&gt;</code> for an encrypted offline submission.</p>"""
        launcher_option = ""
        if development and self.launcher_bytes:
            launcher_option = """<p><a class="button" href="download-launcher">Download PowerShell Quick Start (.ps1) — Existing Lab workflow</a></p>
  <p>Save <strong>Start-CSACollector.ps1</strong>. Open a standard-user Windows PowerShell window
     in its download folder and copy this command:</p>
  <pre><code>powershell.exe -NoProfile -File .\\Start-CSACollector.ps1</code></pre>
  <p>The launcher downloads and verifies this session's existing Collector package automatically.
     No manual ZIP extraction is needed. Keep the launcher private and delete it after use.</p>
  <p>Group Policy and Windows application control still apply. If execution policy blocks this route, contact the assessor for an enterprise-approved signed or offline handoff.
     If Windows blocks the script, use an IT-approved signed EXE or contact the assessor for the approved offline handoff.</p>"""
        document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <title>CSA Security Assessment</title>
  <style>
    :root {{ color-scheme: light dark; font-family: "Segoe UI", Arial, sans-serif;
      --bg: #f3f5f7; --surface: #fff; --text: #17202a; --border: #d8dee5;
      --muted: #4f5b66; --accent: #176b3a; }}
    @media (prefers-color-scheme: dark) {{ :root {{ --bg: #12171b;
      --surface: #1d252b; --text: #edf2f5; --border: #4c5a64;
      --muted: #b9c5cc; --accent: #2d9b68; }} }}
    body {{ margin: 0; background: var(--bg); color: var(--text); }}
    main {{ max-width: 720px; margin: 7vh auto; padding: 36px;
      background: var(--surface); border: 1px solid var(--border); border-radius: 8px; }}
    h1 {{ margin-top: 0; font-size: 28px; }}
    .assessment {{ padding: 14px 0; border-block: 1px solid #e4e8ec; }}
    ul {{ line-height: 1.7; }}
    a.button {{ display: inline-block; padding: 12px 18px; background: var(--accent);
      color: white; text-decoration: none; border-radius: 5px; font-weight: 650; }}
    .quick-start {{ padding: 12px 18px; border: 1px solid var(--border); border-radius: 5px; }}
    .quick-start h2 {{ margin-top: 0; font-size: 20px; }}
    .meta {{ margin-top: 24px; color: var(--muted); font-size: 14px; }}
  </style>
</head>
<body>
<main>
  <h1>CSA Security Assessment</h1>
  <p><strong>{distribution_label} · Release HOLD</strong></p>
  <p class="assessment"><strong>Assessment:</strong> {safe_name}</p>
  <p>This collector:</p>
  <ul>
    <li>runs as the current standard user</li>
    <li>does not install software or require administrator rights</li>
    <li>does not modify the endpoint firewall or registry</li>
    <li>sends security configuration evidence to the assessment computer</li>
    <li>removes temporary collection files after submission</li>
  </ul>
  <p>CSA does not collect passwords, browser credentials, private keys,
     recovery keys, or user document contents.</p>
  <p><strong>If Windows blocks the Collector, record the exact Windows Security message.</strong>
     Do not disable Smart App Control as the default remediation. Use a trusted,
     signed CSA Collector build or contact the assessment administrator.</p>
  {legacy_option}
  <section class="quick-start" aria-labelledby="copy-quick-start-heading">
    <h2 id="copy-quick-start-heading">PowerShell Copy &amp; Paste — one command</h2>
    <p>One paste in Windows PowerShell or CMD <strong>after one-time trusted launcher enrollment</strong>.
      A client administrator or managed channel performs provisioning separately. The engine is temporary; the trusted launcher and policy remain installed.</p>
    {quick_content}
    <p>Quick Run is an approved alternative using a process-only execution policy. It requires the same independent trust checks.
      Defender, AMSI, WDAC, AppLocker and enforced Group Policy remain active; no persistent execution policy is changed.</p>
    <p>The workflow runs once as a standard user. It downloads and cleans up the engine automatically in
      temporary storage, with no persistent agent. The authorized assessment and session expiry define its scope.
      Group Policy and Windows application control apply.</p>
    <p>Use only the independently approved Collector command or the assessor's verified offline/enterprise handoff.</p>
    <p>ENDPOINT_POLICY_BLOCKED: if Windows refuses execution, record the exact control name (Defender, Smart App Control, WDAC, AppLocker or GPO); if unknown, retain UNKNOWN. Contact the assessor for the approved alternative. Do not disable protection.</p>
    <p>SUBMISSION_FAILED / PORTAL_ERROR: retain the safe correlation ID and stage shown in the response and ask the assessor to inspect the matching audit event. Reissue a consumed or expired invitation; do not reuse its private code.</p>
    <p lang="et">Ühe käsuga PowerShelli käivitus muutub kättesaadavaks pärast
      väljaandja, Labi ja käsu päritolu sõltumatut kontrolli. Kasuta kinnitatud EXE- või võrguühenduseta töövoogu.</p>
  </section>
  {launcher_option}
  {script_option}
  <p>The download options use the same Collector engine, session, integrity checks and privacy controls.</p>
  <p class="meta">Collector version: 5.6.8.2<br>Package expires: {safe_expiry}</p>
</main>
{f'<script>{PORTAL_SCRIPT}</script>' if quick_options else ''}
</body>
</html>"""
        return document.encode("utf-8")

    @staticmethod
    def render_error_page(correlation_id: str) -> bytes:
        reference = html.escape(correlation_id)
        return (
            '<!doctype html><html lang="en"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<title>CSA Collector download stopped</title><main>'
            '<h1>Collector download could not complete</h1>'
            '<p>CSA-PORTAL-ERROR. Contact the assessor and provide reference '
            + reference + '.</p><p>Confirm the assessment is collecting and use its current Collector page. '
            'If the failure repeats, use the independently approved signed or offline handoff.</p></main></html>'
        ).encode("utf-8")

    @staticmethod
    def render_unavailable_page() -> bytes:
        """Render a safe explanation for an invalid or expired portal URL."""

        document = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <title>CSA Collector Page Unavailable</title>
  <style>
    :root { color-scheme: light dark; font-family: "Segoe UI", Arial, sans-serif; }
    body { margin: 0; background: Canvas; color: CanvasText; }
    main { max-width: 680px; margin: 9vh auto; padding: 36px;
      border: 1px solid GrayText; border-radius: 8px; }
    h1 { margin-top: 0; font-size: 28px; }
    p { line-height: 1.6; }
  </style>
</head>
<body>
<main>
  <h1>Collector page unavailable</h1>
  <p>This link is invalid, expired, or belongs to another assessment.</p>
  <p>On the assessment computer, open the active <strong>COLLECTING</strong>
     assessment and select <strong>Copy Collector Page</strong>. Close the old
     browser tab and paste the complete new address into the address bar.</p>
</main>
</body>
</html>"""
        return document.encode("utf-8")
