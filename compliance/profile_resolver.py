"""Resolve compliance profiles from analysis context."""

from __future__ import annotations

from analysis_context import AnalysisContext
from compliance.models import ComplianceProfile
from compliance.repository import FrameworkRepository


class ComplianceProfileResolver:
    """Resolve applicable compliance profiles."""

    def __init__(self, repository: FrameworkRepository) -> None:
        """Create a resolver."""

        self.repository = repository
        self.warnings: list[str] = []

    def resolve(
        self,
        context: AnalysisContext,
        manual_profile_ids: list[str] | None = None,
        cis_ig: str | None = None,
    ) -> list[ComplianceProfile]:
        """Resolve compliance profiles."""

        if manual_profile_ids:
            profiles = [self.repository.get_profile(profile_id) for profile_id in manual_profile_ids]
        else:
            profile_id = self._detect_profile(context)
            profiles = [self.repository.get_profile(profile_id)] if profile_id else []
        if cis_ig:
            profiles.append(self.repository.get_profile(f"cis_{cis_ig.casefold()}_endpoint"))
        return profiles

    def _detect_profile(self, context: AnalysisContext) -> str | None:
        """Detect a Windows endpoint profile conservatively."""

        data = context.raw_data
        os_value = str(data.get("OS") or data.get("OperatingSystem") or "")
        if "windows 11" not in os_value.casefold() and os_value:
            self.warnings.append(
                "OS is not a supported Windows 11 workstation; no automatic compliance profile selected."
            )
            return None

        current_user = str(data.get("Current_user") or data.get("CurrentUser") or "")
        tenant_id = data.get("TenantID") or data.get("TenantId")
        domain = str(data.get("Domain") or data.get("Workgroup") or "")
        if tenant_id and current_user.casefold().startswith("azuread\\"):
            return "windows_11_entra_joined"
        if domain and domain.casefold() not in {"workgroup", "unknown"}:
            return "windows_11_domain_joined"
        if domain.casefold() == "workgroup" and not tenant_id:
            return "windows_11_standalone"
        self.warnings.append("Join state ambiguous; using Windows workstation fallback.")
        return "windows_11_workstation"
