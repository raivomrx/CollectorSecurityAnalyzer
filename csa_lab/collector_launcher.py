"""Create a session-bound launcher without putting credentials in URLs."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.parse import urlsplit
import zipfile

from csa_console.canonical import canonical_bytes
from csa_console.file_security import restrict_directory

TEMPLATE = Path(__file__).parent / "powershell" / "Start-CSACollector.ps1.in"


def build_powershell_launcher(archive_path, session, server_url: str, credential: str,
                             signing_directory: Path | None = None) -> bytes:
    """Anchor archive and manifest digests in the downloaded launcher.

    The launcher contains a download-only credential. Enrollment stays inside
    the existing trusted package and is sent only through its existing engine.
    """
    origin = urlsplit(server_url)
    if (origin.scheme != "https" or not origin.hostname or origin.username or
            origin.password or origin.query or origin.fragment or origin.path not in {"", "/"}):
        raise ValueError("Launcher server identity must be an HTTPS origin")
    payload = Path(archive_path).read_bytes()
    with zipfile.ZipFile(Path(archive_path)) as archive:
        manifest_bytes = archive.read("trusted-manifest.json")
    manifest = json.loads(manifest_bytes)
    expected = {
        "assessmentId": session.assessment_id, "sessionId": session.session_id,
        "collectionProfile": session.collection_profile,
        "collectionProfileDigest": session.collection_profile_digest,
        "serverCertificateFingerprint": session.tls_fingerprint,
        "expiration": session.expires_at,
    }
    if manifest.get("schemaVersion") != "5.0" or any(manifest.get(key) != value for key, value in expected.items()):
        raise ValueError("Launcher package session binding is invalid")
    signing = manifest.get("scriptSigning", {})
    binding = {**expected, "schemaVersion": "1.0", "serverUrl": server_url.rstrip("/"),
               "downloadCredential": credential, "packageSize": len(payload),
               "packageDigest": "sha256:" + hashlib.sha256(payload).hexdigest(),
               "manifestDigest": "sha256:" + hashlib.sha256(manifest_bytes).hexdigest(),
               "scriptSignerThumbprint": signing.get("thumbprint", "")}
    template = TEMPLATE.read_text(encoding="utf-8-sig")
    if template.count("__CSA_SESSION_BINDING_BASE64__") != 1:
        raise ValueError("Launcher template binding is invalid")
    encoded = base64.b64encode(canonical_bytes(binding)).decode("ascii")
    result = template.replace("__CSA_SESSION_BINDING_BASE64__", encoded).encode("utf-8-sig")
    thumbprint = os.environ.get("CSA_LAUNCHER_SIGNING_THUMBPRINT", "")
    if thumbprint:
        if signing_directory is None or not re.fullmatch(r"[0-9A-Fa-f]{40}", thumbprint):
            raise ValueError("Launcher signing configuration is invalid")
        result = _sign_launcher(result, thumbprint, signing_directory)
    return result


def _sign_launcher(content: bytes, thumbprint: str, parent: Path) -> bytes:
    """Use an explicitly configured Windows certificate; never ship its key."""
    parent.mkdir(parents=True, exist_ok=True)
    restrict_directory(parent)
    temporary = Path(tempfile.mkdtemp(prefix="launcher-sign-", dir=parent)).resolve()
    try:
        restrict_directory(temporary)
        path = temporary / "Start-CSACollector.ps1"
        path.write_bytes(content)
        completed = subprocess.run([
            str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"),
            "-NoProfile", "-NonInteractive", "-File",
            str(TEMPLATE.with_name("Sign-CSALauncher.ps1")),
            "-Path", str(path), "-Thumbprint", thumbprint,
        ], capture_output=True, timeout=90, check=False)
        if completed.returncode:
            raise ValueError("Configured launcher signing failed; no unsigned fallback was issued")
        return path.read_bytes()
    finally:
        # Only this function's unique child directory is removed.
        shutil.rmtree(temporary)
