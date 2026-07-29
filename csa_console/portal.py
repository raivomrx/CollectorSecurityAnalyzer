"""Assessment-bound Collector download portal state and authorization."""

from __future__ import annotations

import hashlib
import hmac
import html
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from csa_console.audit import ConsoleAuditLog
from csa_console.canonical import write_canonical_json
from csa_console.enums import SessionStatus
from csa_console.network import source_is_allowed
from csa_console.sessions import AssessmentSessionService
from csa_console.storage import AssessmentStorage


@dataclass(slots=True)
class PortalBinding:
    """Bind one opaque join code to one bounded Collector executable."""

    assessment_id: str
    session_id: str
    join_code_hash: str
    collector_path: Path
    expires_at: str
    maximum_downloads: int
    storage: AssessmentStorage
    download_count: int = 0
    _lock: threading.Lock = field(
        default_factory=threading.Lock, repr=False, compare=False
    )

    def authorize(self, join_code: str, source_address: str) -> bool:
        """Validate code, session, expiry, source scope and download budget."""

        supplied = hashlib.sha256(join_code.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(supplied, self.join_code_hash):
            return False
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
            return False
        with self._lock:
            return self.download_count < self.maximum_downloads

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
                "sourceAddress": source_address,
                "downloadCount": count,
            },
        )

    def render_page(self, assessment_name: str) -> bytes:
        """Render the small remote-safe download page."""

        safe_name = html.escape(assessment_name)
        safe_expiry = html.escape(self.expires_at)
        document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <title>CSA Security Assessment</title>
  <style>
    :root {{ color-scheme: light; font-family: "Segoe UI", Arial, sans-serif; }}
    body {{ margin: 0; background: #f3f5f7; color: #17202a; }}
    main {{ max-width: 720px; margin: 7vh auto; padding: 36px;
      background: white; border: 1px solid #d8dee5; border-radius: 8px; }}
    h1 {{ margin-top: 0; font-size: 28px; }}
    .assessment {{ padding: 14px 0; border-block: 1px solid #e4e8ec; }}
    ul {{ line-height: 1.7; }}
    a.button {{ display: inline-block; padding: 12px 18px; background: #176b3a;
      color: white; text-decoration: none; border-radius: 5px; font-weight: 650; }}
    .meta {{ margin-top: 24px; color: #4f5b66; font-size: 14px; }}
  </style>
</head>
<body>
<main>
  <h1>CSA Security Assessment</h1>
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
  <p><a class="button" href="download">Download CSA Collector</a></p>
  <ol>
    <li>Open <strong>CSA-Collector.exe</strong>.</li>
    <li>Wait for <strong>Submission accepted</strong>.</li>
    <li>Close the collector.</li>
  </ol>
  <p class="meta">Collector version: 5.1.x<br>Package expires: {safe_expiry}</p>
</main>
</body>
</html>"""
        return document.encode("utf-8")

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
