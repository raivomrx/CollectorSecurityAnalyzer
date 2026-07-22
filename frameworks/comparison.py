"""Compare two versions of the same framework pack."""

from __future__ import annotations

from dataclasses import dataclass

from frameworks.models import FrameworkPack


@dataclass(frozen=True, slots=True)
class FrameworkPackComparison:
    """Describe control and mapping changes between pack versions."""

    framework_id: str
    old_version: str
    new_version: str
    added_controls: tuple[str, ...]
    removed_controls: tuple[str, ...]
    changed_mappings: tuple[str, ...]
    changed_profiles: tuple[str, ...]
    changed_automation: tuple[str, ...]
    changed_status: tuple[str, ...]


def compare_packs(old: FrameworkPack, new: FrameworkPack) -> FrameworkPackComparison:
    """Return deterministic semantic differences between two pack versions."""

    if old.framework_id != new.framework_id:
        raise ValueError("Only versions of the same framework can be compared")
    old_controls = {item.control_id: item for item in old.controls}
    new_controls = {item.control_id: item for item in new.controls}
    shared = sorted(old_controls.keys() & new_controls.keys())
    return FrameworkPackComparison(
        framework_id=old.framework_id,
        old_version=old.version,
        new_version=new.version,
        added_controls=tuple(sorted(new_controls.keys() - old_controls.keys())),
        removed_controls=tuple(sorted(old_controls.keys() - new_controls.keys())),
        changed_mappings=tuple(
            item for item in shared
            if old_controls[item].mappings != new_controls[item].mappings
        ),
        changed_profiles=tuple(
            item for item in shared
            if old_controls[item].profile != new_controls[item].profile
        ),
        changed_automation=tuple(
            item for item in shared
            if old_controls[item].automation != new_controls[item].automation
        ),
        changed_status=("PACK_STATUS",) if old.status != new.status else (),
    )
