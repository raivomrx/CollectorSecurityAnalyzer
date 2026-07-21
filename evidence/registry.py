"""Registry for normalized Windows evidence."""

from __future__ import annotations

from evidence.windows_models import SecuritySettingEvidence


class WindowsEvidenceRegistry:
    """Provide lookup APIs for normalized Windows evidence."""

    def __init__(self, settings: list[SecuritySettingEvidence]) -> None:
        """Create an evidence registry."""

        self._settings_by_id: dict[str, SecuritySettingEvidence] = {}
        self._duplicates: list[str] = []
        for setting in settings:
            if setting.setting_id in self._settings_by_id:
                self._duplicates.append(setting.setting_id)
                continue
            self._settings_by_id[setting.setting_id] = setting

    @property
    def duplicates(self) -> list[str]:
        """Return duplicate setting IDs found during registry construction."""

        return list(self._duplicates)

    def get(self, setting_id: str) -> SecuritySettingEvidence | None:
        """Return evidence by setting ID."""

        return self._settings_by_id.get(setting_id)

    def find_by_category(self, category: str) -> list[SecuritySettingEvidence]:
        """Return evidence items by category."""

        return [
            setting
            for setting in self._settings_by_id.values()
            if setting.category.casefold() == category.casefold()
        ]

    def all(self) -> list[SecuritySettingEvidence]:
        """Return all normalized evidence settings."""

        return list(self._settings_by_id.values())

    def missing_or_problematic(self) -> list[SecuritySettingEvidence]:
        """Return evidence that was not collected successfully."""

        return [
            setting
            for setting in self._settings_by_id.values()
            if setting.collection_status.value != "SUCCESS"
        ]
