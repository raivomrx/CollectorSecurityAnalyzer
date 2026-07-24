"""Assessment-scoped storage with canonical paths and atomic writes."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from csa_console.canonical import read_json, write_canonical_json
from csa_console.file_security import restrict_directory

SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class StorageError(ValueError):
    """Report unsafe or invalid assessment storage operations."""


class AssessmentStorage:
    """Manage isolated assessment directories."""

    def __init__(self, root: str | Path = "assessments") -> None:
        """Create an assessment storage manager."""

        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        restrict_directory(self.root)

    def assessment_path(self, assessment_id: str) -> Path:
        """Return a validated assessment directory."""

        return self._contained(assessment_id)

    def ensure_assessment(self, assessment_id: str) -> Path:
        """Create the standard assessment directory structure."""

        root = self.assessment_path(assessment_id)
        for relative in (
            "sessions",
            "submissions/accepted",
            "submissions/rejected",
            "submissions/quarantine",
            "normalized",
            "findings",
            "reports/endpoints",
            "reports/fleet",
            "reports/executive",
            "exports",
            "audit",
            "keys",
            "nonces",
        ):
            directory = root / relative
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o700)
        return root

    def path(self, assessment_id: str, *components: str) -> Path:
        """Return a canonical path below an assessment."""

        root = self.assessment_path(assessment_id)
        current = root
        for component in components:
            if not SAFE_COMPONENT.fullmatch(component):
                raise StorageError(f"Unsafe storage path component: {component!r}")
            current = current / component
        resolved_parent = current.parent.resolve()
        if root != resolved_parent and root not in resolved_parent.parents:
            raise StorageError("Storage path escapes the assessment root")
        return current

    def write_json(
        self,
        assessment_id: str,
        components: tuple[str, ...],
        value: Any,
    ) -> Path:
        """Atomically write canonical JSON within an assessment."""

        output = self.path(assessment_id, *components)
        output.parent.mkdir(parents=True, exist_ok=True)
        return write_canonical_json(output, value)

    def read_json(
        self,
        assessment_id: str,
        *components: str,
    ) -> dict[str, Any]:
        """Read one assessment JSON object."""

        return read_json(self.path(assessment_id, *components))

    def _contained(self, component: str) -> Path:
        """Resolve one safe component below the storage root."""

        if not SAFE_COMPONENT.fullmatch(component):
            raise StorageError(f"Unsafe assessment identifier: {component!r}")
        path = (self.root / component).resolve()
        if self.root not in path.parents:
            raise StorageError("Assessment path escapes storage root")
        return path
