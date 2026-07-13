"""CVE engine exceptions."""

from __future__ import annotations


class CveEngineError(Exception):
    """Base exception for CVE engine failures."""


class NvdRequestError(CveEngineError):
    """Raised when an NVD request fails after retries."""

    def __init__(
        self,
        message: str,
        retryable: bool = False,
        status_code: int | None = None,
        endpoint_label: str | None = None,
    ) -> None:
        """Create a request error with retry metadata."""

        super().__init__(message)
        self.retryable = retryable
        self.status_code = status_code
        self.endpoint_label = endpoint_label


class CveCacheError(CveEngineError):
    """Raised when the CVE cache cannot be used."""
