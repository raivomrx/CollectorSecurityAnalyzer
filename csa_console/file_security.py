"""Restrictive filesystem permissions for assessment data."""

from __future__ import annotations

import csv
import os
import subprocess
from pathlib import Path


def restrict_directory(path: str | Path) -> None:
    """Restrict a directory to the current identity and Local System."""

    target = Path(path)
    if os.name != "nt":
        target.chmod(0o700)
        return
    sid = _current_windows_sid()
    completed = subprocess.run(
        [
            str(Path(os.environ["SystemRoot"]) / "System32" / "icacls.exe"),
            str(target),
            "/inheritance:r",
            "/grant:r",
            f"*{sid}:(OI)(CI)F",
            "*S-1-5-18:(OI)(CI)F",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if completed.returncode != 0:
        raise OSError("Unable to apply the restricted assessment ACL")


def _current_windows_sid() -> str:
    """Return the current Windows user SID without retaining the account name."""

    completed = subprocess.run(
        [
            str(Path(os.environ["SystemRoot"]) / "System32" / "whoami.exe"),
            "/user",
            "/fo",
            "csv",
            "/nh",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    row = next(csv.reader([completed.stdout.strip()]))
    if len(row) < 2 or not row[1].startswith("S-1-"):
        raise OSError("Unable to determine the current Windows user SID")
    return row[1]
