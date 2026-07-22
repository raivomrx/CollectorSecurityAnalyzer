"""Registry for deterministic framework pack discovery and selection."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from frameworks.enums import PackStatus
from frameworks.exceptions import FrameworkPackError
from frameworks.loader import load_json_document, load_pack
from frameworks.models import FrameworkPack

FRAMEWORK_ROOT = Path(__file__).resolve().parent


@dataclass(frozen=True, slots=True)
class RegistryEntry:
    """Describe one pack path and selection status."""

    framework_id: str
    version: str
    path: str
    status: PackStatus
    default: bool


class FrameworkPackRegistry:
    """Discover and resolve versioned framework packs from a local registry."""

    def __init__(self, root: str | Path = FRAMEWORK_ROOT) -> None:
        """Load the registry rooted at a trusted local directory."""

        self.root = Path(root).resolve()
        document = load_json_document(self.root / "registry.json")
        self.entries = tuple(self._entry(item) for item in document.get("packs", []))
        self._validate_registry()

    def list(self, include_archived: bool = False) -> list[RegistryEntry]:
        """Return deterministic registry entries."""

        entries = self.entries if include_archived else tuple(
            item for item in self.entries if item.status != PackStatus.ARCHIVED
        )
        return sorted(entries, key=lambda item: (item.framework_id, _version_key(item.version)))

    def list_framework_ids(self) -> list[str]:
        """Return known framework identifiers."""

        return sorted({entry.framework_id for entry in self.entries})

    def resolve(self, framework_id: str, version: str = "latest") -> FrameworkPack:
        """Load an exact version or the configured active default."""

        candidates = [item for item in self.entries if item.framework_id == framework_id]
        if version == "latest":
            defaults = [
                item for item in candidates
                if item.default and item.status == PackStatus.ACTIVE
            ]
            if len(defaults) != 1:
                raise FrameworkPackError(
                    f"Framework {framework_id} has no unique active default version"
                )
            entry = defaults[0]
        else:
            matches = [item for item in candidates if item.version == version]
            if len(matches) != 1:
                raise FrameworkPackError(f"Unknown framework version: {framework_id}:{version}")
            entry = matches[0]
        pack = load_pack(self._safe_path(entry.path))
        if (
            pack.framework_id != entry.framework_id
            or pack.version != entry.version
            or pack.status != entry.status
        ):
            raise FrameworkPackError(
                f"Registry metadata does not match pack: {entry.framework_id}:{entry.version}"
            )
        return pack

    def load_defaults(self) -> list[FrameworkPack]:
        """Load every active default pack."""

        return [
            self.resolve(framework_id)
            for framework_id in self.list_framework_ids()
            if any(
                entry.framework_id == framework_id
                and entry.default
                and entry.status == PackStatus.ACTIVE
                for entry in self.entries
            )
        ]

    def pack_path(self, framework_id: str, version: str) -> Path:
        """Return the trusted path for one exact registry entry."""

        matches = [
            entry
            for entry in self.entries
            if entry.framework_id == framework_id and entry.version == version
        ]
        if len(matches) != 1:
            raise FrameworkPackError(f"Unknown framework version: {framework_id}:{version}")
        return self._safe_path(matches[0].path)

    def _entry(self, value) -> RegistryEntry:
        """Parse one registry entry."""

        try:
            return RegistryEntry(
                framework_id=str(value["frameworkId"]),
                version=str(value["version"]),
                path=str(value["path"]),
                status=PackStatus(value["status"]),
                default=bool(value.get("default", False)),
            )
        except (KeyError, ValueError, TypeError) as error:
            raise FrameworkPackError(f"Invalid framework registry entry: {error}") from error

    def _safe_path(self, relative: str) -> Path:
        """Resolve a registry path without allowing traversal."""

        path = (self.root / relative).resolve()
        if self.root not in path.parents:
            raise FrameworkPackError(f"Framework path escapes registry root: {relative}")
        return path

    def _validate_registry(self) -> None:
        """Reject duplicate versions and ambiguous defaults."""

        keys = [(entry.framework_id, entry.version) for entry in self.entries]
        if len(keys) != len(set(keys)):
            raise FrameworkPackError("Framework registry contains duplicate versions")
        for entry in self.entries:
            self._safe_path(entry.path)
        for framework_id in self.list_framework_ids():
            defaults = [
                entry for entry in self.entries
                if entry.framework_id == framework_id
                and entry.default
                and entry.status == PackStatus.ACTIVE
            ]
            if len(defaults) > 1:
                raise FrameworkPackError(
                    f"Framework {framework_id} has multiple active default versions"
                )


def _version_key(value: str) -> tuple[tuple[int, object], ...]:
    """Return a deterministic mixed numeric version key."""

    import re

    return tuple(
        (0, int(part)) if part.isdigit() else (1, part.casefold())
        for part in re.split(r"([0-9]+)", value)
        if part
    )
