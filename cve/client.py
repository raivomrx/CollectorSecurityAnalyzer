"""NVD API 2.0 client."""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import requests

from cve.cache import NvdCache
from cve.exceptions import NvdRequestError
from cve.rate_limiter import SlidingWindowRateLimiter

LOGGER = logging.getLogger(__name__)
NVD_CVE_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
USER_AGENT = "CollectorSecurityAnalyzer/0.1"


class NvdClient:
    """Client for NVD CVE and CPE API 2.0."""

    def __init__(
        self,
        timeout: int = 30,
        max_retries: int = 3,
        cache_ttl_hours: int = 24,
        api_key_env_var: str = "NVD_API_KEY",
        cache: NvdCache | None = None,
        session: requests.Session | None = None,
        limiter: SlidingWindowRateLimiter | None = None,
    ) -> None:
        """Create a configured NVD client."""

        self.timeout = timeout
        self.max_retries = max_retries
        self.cache_ttl_hours = cache_ttl_hours
        self.api_key = os.getenv(api_key_env_var)
        self.cache = NvdCache() if cache is None else cache
        self.session = requests.Session() if session is None else session
        self.limiter = limiter or SlidingWindowRateLimiter(
            requests=50 if self.api_key else 5,
            window_seconds=30,
        )

    def get_cpes(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        """Return CPE products from NVD."""

        data = self._get_paginated(NVD_CPE_ENDPOINT, params, "products")
        return [item for item in data if isinstance(item, dict)]

    def get_cves(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        """Return CVE vulnerabilities from NVD."""

        data = self._get_paginated(NVD_CVE_ENDPOINT, params, "vulnerabilities")
        return [item for item in data if isinstance(item, dict)]

    def _get_paginated(
        self,
        endpoint: str,
        params: dict[str, Any],
        result_key: str,
    ) -> list[dict[str, Any]]:
        """Fetch all pages for an NVD endpoint."""

        start_index = 0
        results_per_page = int(params.get("resultsPerPage", 2000))
        collected: list[dict[str, Any]] = []
        while True:
            page_params = dict(params)
            page_params["startIndex"] = start_index
            page_params["resultsPerPage"] = results_per_page
            page = self._get_json(endpoint, page_params)
            page_items = page.get(result_key, [])
            if not isinstance(page_items, list):
                raise NvdRequestError(f"Invalid NVD response schema for {endpoint}")
            collected.extend(item for item in page_items if isinstance(item, dict))
            total_results = int(page.get("totalResults", len(collected)))
            start_index += results_per_page
            if start_index >= total_results:
                return collected

    def _get_json(self, endpoint: str, params: dict[str, Any]) -> dict[str, Any]:
        """Fetch one JSON page with cache, retries, and rate limiting."""

        cache_key = NvdCache.make_key(endpoint, params)
        cached = self.cache.get(cache_key)
        if cached is not None:
            LOGGER.info("NVD cache hit: endpoint=%s", _endpoint_label(endpoint))
            return cached

        headers = {"User-Agent": USER_AGENT}
        if self.api_key:
            headers["apiKey"] = self.api_key

        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                self.limiter.acquire()
                response = self.session.get(
                    endpoint,
                    params=params,
                    headers=headers,
                    timeout=self.timeout,
                )
                if response.status_code == 429:
                    self.limiter.retry_after(response.headers.get("Retry-After"))
                    raise NvdRequestError("NVD rate limit exceeded")
                if response.status_code >= 500:
                    raise NvdRequestError(f"NVD server error: {response.status_code}")
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, dict):
                    raise NvdRequestError("Invalid NVD JSON response")
                self.cache.set(cache_key, endpoint, params, data, self.cache_ttl_hours)
                return data
            except (requests.RequestException, ValueError, NvdRequestError) as error:
                last_error = error
                if attempt >= self.max_retries:
                    break
                time.sleep(min(2 ** attempt, 8))

        LOGGER.error("NVD request failed after retries")
        raise NvdRequestError(str(last_error))


def _endpoint_label(endpoint: str) -> str:
    """Return a safe endpoint label for logs."""

    if endpoint == NVD_CVE_ENDPOINT:
        return "CVES"
    if endpoint == NVD_CPE_ENDPOINT:
        return "CPES"
    return "UNKNOWN"
