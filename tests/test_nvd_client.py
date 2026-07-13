"""Tests for the NVD API client."""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from cve.cache import NvdCache
from cve.client import NVD_CVE_ENDPOINT, NvdClient
from cve.exceptions import NvdRequestError
from cve.rate_limiter import SlidingWindowRateLimiter


class NvdClientTests(unittest.TestCase):
    """Validate NVD client behavior without internet access."""

    def test_api_key_header_and_no_key(self) -> None:
        """Client should include API key only when environment variable exists."""

        session = _Session([_Response({"totalResults": 0, "vulnerabilities": []})])
        with patch.dict(os.environ, {"NVD_API_KEY": "secret"}, clear=False):
            client = _client(session)
            client.get_cves({})
        self.assertEqual(session.calls[0]["headers"]["apiKey"], "secret")

        session = _Session([_Response({"totalResults": 0, "vulnerabilities": []})])
        with patch.dict(os.environ, {}, clear=True):
            client = _client(session)
            client.get_cves({})
        self.assertNotIn("apiKey", session.calls[0]["headers"])

    def test_pagination(self) -> None:
        """Client should follow NVD pagination fields."""

        responses = [
            _Response({"totalResults": 2, "vulnerabilities": [{"cve": {"id": "CVE-1"}}]}),
            _Response({"totalResults": 2, "vulnerabilities": [{"cve": {"id": "CVE-2"}}]}),
        ]
        client = _client(_Session(responses))
        items = client.get_cves({"resultsPerPage": 1})

        self.assertEqual(len(items), 2)

    def test_cache_hit_avoids_request(self) -> None:
        """Cached responses should avoid HTTP requests."""

        cache = _MemoryCache()
        params = {"startIndex": 0, "resultsPerPage": 2000}
        key = NvdCache.make_key(NVD_CVE_ENDPOINT, params)
        cache.set(key, NVD_CVE_ENDPOINT, params, {"totalResults": 0, "vulnerabilities": []}, 1)
        session = _Session([])
        client = NvdClient(cache=cache, session=session, limiter=_limiter(), max_retries=0)
        self.assertEqual(client.get_cves({}), [])
        self.assertEqual(session.calls, [])

    def test_429_and_500_exhaust_retries(self) -> None:
        """Retryable server responses should raise after retries are exhausted."""

        client = _client(_Session([_Response({}, status_code=429, headers={"Retry-After": "0"})]))
        with self.assertRaises(NvdRequestError):
            client.get_cves({})

        client = _client(_Session([_Response({}, status_code=500)]))
        with self.assertRaises(NvdRequestError):
            client.get_cves({})

    def test_invalid_response_schema(self) -> None:
        """Invalid NVD schemas should raise a request error."""

        client = _client(_Session([_Response({"totalResults": 1, "vulnerabilities": {}})]))
        with self.assertRaises(NvdRequestError):
            client.get_cves({})


def _client(session: "_Session") -> NvdClient:
    """Create a test client."""

    return NvdClient(
        cache=_MemoryCache(),
        session=session,
        limiter=_limiter(),
        max_retries=0,
        timeout=1,
    )


def _limiter() -> SlidingWindowRateLimiter:
    """Create a no-wait limiter."""

    return SlidingWindowRateLimiter(requests=999, window_seconds=1, sleep=lambda _: None)


class _Session:
    """Fake requests session."""

    def __init__(self, responses: list["_Response"]) -> None:
        self.responses = responses
        self.calls: list[dict[str, object]] = []

    def get(self, endpoint, params, headers, timeout):
        self.calls.append(
            {
                "endpoint": endpoint,
                "params": dict(params),
                "headers": dict(headers),
                "timeout": timeout,
            }
        )
        return self.responses.pop(0)


class _Response:
    """Fake requests response."""

    def __init__(self, payload, status_code: int = 200, headers: dict[str, str] | None = None) -> None:
        self.payload = payload
        self.status_code = status_code
        self.headers = {} if headers is None else headers

    def json(self):
        return self.payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise NvdRequestError(str(self.status_code))


class _MemoryCache:
    """In-memory cache fake for client tests."""

    def __init__(self) -> None:
        self.values = {}

    @staticmethod
    def make_key(endpoint, params):
        return f"{endpoint}|{sorted(params.items())}"

    def get(self, key):
        return self.values.get(key)

    def set(self, key, endpoint, params, value, ttl_hours):
        self.values[key] = value


if __name__ == "__main__":
    unittest.main()
