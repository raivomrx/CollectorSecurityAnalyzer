"""CPE repository placeholder for future CPE mapping."""

from __future__ import annotations

from software.models import SoftwareProduct


class CpeRepository:
    """Resolve normalized software products to CPE names when mappings exist."""

    def get(self, software: SoftwareProduct) -> str | None:
        """Return a CPE URI for a software product when known."""

        return software.cpe
