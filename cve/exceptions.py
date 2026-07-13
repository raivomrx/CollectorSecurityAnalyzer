"""CVE engine exceptions."""

from __future__ import annotations


class CveEngineError(Exception):
    """Base exception for CVE engine failures."""


class NvdRequestError(CveEngineError):
    """Raised when an NVD request fails after retries."""


class CveCacheError(CveEngineError):
    """Raised when the CVE cache cannot be used."""
