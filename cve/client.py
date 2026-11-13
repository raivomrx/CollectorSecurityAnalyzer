"""NVD API 2.0 client."""

from __future__ import annotations

import logging
import os
import re
import time
from collections.abc import Callable
from threading import Event, Lock, Thread, BoundedSemaphore
from typing import Any

import requests

from cve.cache import NvdCache
from cve.exceptions import CveScanCancelled, NvdRequestError
from cve.rate_limiter import SlidingWindowRateLimiter
from cve.control import AnalysisControl

LOGGER = logging.getLogger(__name__)
NVD_CVE_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
USER_AGENT = "CollectorSecurityAnalyzer/0.1"
_NETWORK_SLOTS = BoundedSemaphore(4)


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
        api_key: str | None = None,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
        cancel_event: Event | None = None,
        product_deadline_seconds: float = 60,
    ) -> None:
        """Create a configured NVD client."""

        self.timeout = timeout
        self.max_retries = max_retries
        self.cache_ttl_hours = cache_ttl_hours
        self.api_key = api_key if api_key is not None else os.getenv(api_key_env_var)
        self.progress_callback = progress_callback
        self.cancel_event = cancel_event
        self.product_deadline_seconds = max(.05, float(product_deadline_seconds))
        self.product_deadline = None
        self._request_lock = Lock()
        self.metrics = {
            "nvdApiKeyConfigured": bool(self.api_key), "nvdRequests": 0,
            "rateLimitWaitSeconds": 0.0, "cpeCacheHits": 0, "cpeCacheMisses": 0,
            "cveCacheHits": 0, "cveCacheMisses": 0, "nvdCveRetrievalSeconds": 0.0,
            "cpeQueryCount": 0, "cveQueryCount": 0,
            "remoteCpeRequests": 0, "remoteCveRequests": 0,
        }
        self.cache = NvdCache() if cache is None else cache
        self.session = requests.Session() if session is None else session
        self.limiter = limiter or SlidingWindowRateLimiter(
            requests=50 if self.api_key else 5,
            window_seconds=30,
        )

    def get_cpes(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        """Return CPE products from NVD."""

        self.metrics["cpeQueryCount"] += 1
        data = self._get_paginated(NVD_CPE_ENDPOINT, params, "products")
        return [item for item in data if isinstance(item, dict)]

    def get_cves(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        """Return CVE vulnerabilities from NVD."""

        started = time.perf_counter()
        self.metrics["cveQueryCount"] += 1
        try:
            data = self._get_paginated(NVD_CVE_ENDPOINT, params, "vulnerabilities")
        finally:
            self.metrics["nvdCveRetrievalSeconds"] += time.perf_counter() - started
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
            self._check_cancelled()
            page_params = dict(params)
            page_params["startIndex"] = start_index
            page_params["resultsPerPage"] = results_per_page
            page = self._get_json(endpoint, page_params)
            page_items = page.get(result_key, [] if result_key != "vulnerabilities" else None)
            if not isinstance(page_items, list):
                raise NvdRequestError(f"Invalid NVD response schema for {endpoint}")
            if result_key == "vulnerabilities" and (
                type(page.get("totalResults")) is not int or page["totalResults"] < 0
                or any(not isinstance(item, dict) for item in page_items)
            ):
                raise NvdRequestError("Invalid NVD CVE response inventory", endpoint_label="CVES")
            collected.extend(item for item in page_items if isinstance(item, dict))
            total_results = int(page.get("totalResults", len(collected)))
            start_index += results_per_page
            if start_index >= total_results:
                if result_key == "vulnerabilities" and len(collected) != total_results:
                    raise NvdRequestError("Incomplete NVD CVE response inventory", endpoint_label="CVES")
                return collected

    def _get_json(self, endpoint: str, params: dict[str, Any]) -> dict[str, Any]:
        """Fetch one JSON page with cache, retries, and rate limiting."""

        cache_key = NvdCache.make_key(endpoint, params)
        self._check_cancelled()
        cached = self.cache.get(cache_key)
        cache_label = "cpe" if endpoint == NVD_CPE_ENDPOINT else "cve"
        if cached is not None:
            self.metrics[cache_label + "CacheHits"] += 1
            LOGGER.info("NVD cache hit: endpoint=%s", _endpoint_label(endpoint))
            return cached
        self.metrics[cache_label + "CacheMisses"] += 1

        headers = {"User-Agent": USER_AGENT}
        if self.api_key:
            headers["apiKey"] = self.api_key

        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            self._check_cancelled()
            try:
                waiting = time.perf_counter()
                if isinstance(self.limiter, SlidingWindowRateLimiter):
                    self.limiter.acquire(
                        on_wait=lambda remaining: self._progress(
                            endpoint, "RATE_LIMIT_WAIT", remaining, attempt + 1
                        ),
                        cancel_event=self._control(),
                    )
                else:
                    self.limiter.acquire()
                self.metrics["rateLimitWaitSeconds"] += time.perf_counter() - waiting
                self._check_cancelled()
                self._progress(endpoint, "PROVIDER_REQUEST", 0, attempt + 1)
                self.metrics["nvdRequests"] += 1
                self.metrics["remoteCpeRequests" if cache_label == "cpe" else "remoteCveRequests"] += 1
                response, data = self._request(endpoint, params, headers, attempt+1)
                if response.status_code == 429:
                    error = _http_error(endpoint, response, retryable=True, secret=self.api_key)
                    if attempt < self.max_retries:
                        waiting = time.perf_counter()
                        if isinstance(self.limiter, SlidingWindowRateLimiter):
                            self.limiter.retry_after(
                                response.headers.get("Retry-After"),
                                on_wait=lambda remaining: self._progress(
                                    endpoint, "RATE_LIMIT_WAIT", remaining, attempt + 2
                                ),
                                cancel_event=self._control(),
                            )
                        else:
                            self.limiter.retry_after(response.headers.get("Retry-After"))
                        self.metrics["rateLimitWaitSeconds"] += time.perf_counter() - waiting
                    raise error
                if response.status_code >= 500:
                    raise _http_error(endpoint, response, retryable=True, secret=self.api_key)
                if 400 <= response.status_code < 500:
                    raise _http_error(endpoint, response, retryable=False, secret=self.api_key)
                response.raise_for_status()
                self._check_cancelled()
                if not isinstance(data, dict):
                    raise NvdRequestError("Invalid NVD JSON response", retryable=False)
                self.cache.set(cache_key, endpoint, params, data, self.cache_ttl_hours)
                return data
            except NvdRequestError as error:
                last_error = error
                if not error.retryable:
                    break
                if attempt >= self.max_retries:
                    break
                self._backoff(endpoint, attempt)
            except (requests.ConnectionError, requests.Timeout) as error:
                last_error = NvdRequestError(
                    f"NVD request failed: endpoint={_endpoint_label(endpoint)} transient network error",
                    retryable=True,
                    endpoint_label=_endpoint_label(endpoint),
                )
                if attempt >= self.max_retries:
                    break
                self._backoff(endpoint, attempt)
            except requests.RequestException as error:
                last_error = NvdRequestError(
                    f"NVD request failed: endpoint={_endpoint_label(endpoint)} network error",
                    retryable=False,
                    endpoint_label=_endpoint_label(endpoint),
                )
                break
            except ValueError as error:
                last_error = NvdRequestError(
                    f"NVD request failed: endpoint={_endpoint_label(endpoint)} invalid JSON response",
                    retryable=False,
                    endpoint_label=_endpoint_label(endpoint),
                )
                break

        LOGGER.error("NVD request failed after retries")
        if isinstance(last_error, NvdRequestError):
            raise last_error
        raise NvdRequestError(str(last_error))

    def _check_cancelled(self) -> None:
        """Stop a pending scan before another provider request is sent."""

        self._control().check()

    def _control(self):
        return AnalysisControl(self.cancel_event,self.product_deadline)

    def _request(self, endpoint, params, headers, attempt=1):
        # A requests socket timeout is not an overall response/DNS deadline.
        # Keep one bounded in-flight request per client; cancelled requests
        # never publish late results or spawn an unbounded queue of threads.
        if not self._request_lock.acquire(blocking=False):
            raise NvdRequestError("NVD transport still finishing an interrupted request",retryable=False,
                                  endpoint_label=_endpoint_label(endpoint))
        if not _NETWORK_SLOTS.acquire(blocking=False):
            self._request_lock.release()
            raise NvdRequestError("NVD request capacity is busy; retry incomplete products",endpoint_label=_endpoint_label(endpoint))
        done, abandoned = Event(), Event()
        result = {}
        control=self._control()
        def request():
            response=None
            started=time.monotonic()
            try:
                options={'stream':True} if isinstance(self.session,requests.Session) else {}
                response=self.session.get(endpoint,params=params,headers=headers,timeout=min(self.timeout,10),**options)
                if isinstance(response,requests.Response):
                    pieces=[];size=0;maximum=64*1024*1024 if response.status_code<400 else 4096
                    for piece in response.iter_content(chunk_size=65536):
                        control.check();size+=len(piece)
                        if size>maximum:raise NvdRequestError("NVD response exceeds the bounded transfer size",endpoint_label=_endpoint_label(endpoint))
                        pieces.append(piece)
                    response._content=b''.join(pieces);response._content_consumed=True
                data=response.json() if response.status_code<400 else None
                control.check()
                if abandoned.is_set():
                    close=getattr(response,'close',None)
                    if close: close()
                else: result['response']=response;result['data']=data
            except Exception as error: result['error']=error
            finally:
                if response is not None:
                    close=getattr(response,'close',None)
                    if close:close()
                LOGGER.info("NVD transport endpoint=%s attempt=%d status=%s elapsedMs=%d abandoned=%s",
                    _endpoint_label(endpoint),attempt,getattr(response,'status_code',0),
                    int((time.monotonic()-started)*1000),abandoned.is_set())
                self._request_lock.release();_NETWORK_SLOTS.release();done.set()
        try: Thread(target=request,name="CSA-NVD-request",daemon=True).start()
        except RuntimeError:
            self._request_lock.release();_NETWORK_SLOTS.release()
            raise NvdRequestError("NVD request worker could not start",endpoint_label=_endpoint_label(endpoint)) from None
        try:
            request_end=time.monotonic()+max(.05,float(self.timeout))
            heartbeat=time.monotonic()
            while not done.wait(.1):
                self._check_cancelled()
                if time.monotonic()-heartbeat >= .5:
                    self._progress(endpoint,"PROVIDER_REQUEST",0,attempt);heartbeat=time.monotonic()
                if time.monotonic()>=request_end: raise requests.Timeout()
            self._check_cancelled()
            if 'error' in result: raise result['error']
            return result['response'],result['data']
        except BaseException:
            abandoned.set()
            response=result.pop('response',None)
            if response is not None:
                close=getattr(response,'close',None)
                if close: close()
            raise

    def _progress(self, endpoint: str, phase: str, wait: float, attempt: int) -> None:
        """Emit safe provider state without disclosing URL parameters or key."""

        if self.progress_callback is not None:
            self.progress_callback({
                "phase": phase, "provider": f"NVD {_endpoint_label(endpoint)}",
                "wait_seconds": wait, "retry_attempt": attempt,
                "product_remaining_seconds":max(0,self.product_deadline-time.monotonic()) if self.product_deadline else 0,
            })

    def _backoff(self, endpoint: str, attempt: int) -> None:
        """Wait between transient retries with live cancellation."""

        seconds = min(2 ** attempt, 8)
        if isinstance(self.limiter, SlidingWindowRateLimiter):
            self.limiter._wait(
                seconds,
                lambda remaining: self._progress(endpoint, "RETRY_WAIT", remaining, attempt + 2),
                self._control(),
            )
        else:
            time.sleep(seconds)


def _endpoint_label(endpoint: str) -> str:
    """Return a safe endpoint label for logs."""

    if endpoint == NVD_CVE_ENDPOINT:
        return "CVES"
    if endpoint == NVD_CPE_ENDPOINT:
        return "CPES"
    return "UNKNOWN"


def _http_error(endpoint: str, response: requests.Response, retryable: bool, secret: str | None = None) -> NvdRequestError:
    """Build a structured HTTP error without leaking request details."""

    label = _endpoint_label(endpoint)
    status = response.status_code
    summary = _safe_response_summary(response, secret)
    return NvdRequestError(
        f"NVD request failed: endpoint={label} status={status} summary={summary}",
        retryable=retryable,
        status_code=status,
        endpoint_label=label,
    )


def _safe_response_summary(response: requests.Response, secret: str | None = None) -> str:
    """Return a short sanitized response summary."""

    text = getattr(response, "text", "") or getattr(response, "reason", "") or ""
    if secret:
        text = str(text).replace(secret, "[REDACTED]")
    summary = re.sub(r"\s+", " ", str(text)).strip()
    if not summary:
        summary = "no response summary"
    return summary[:160]
