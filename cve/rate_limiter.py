"""Rate limiting helpers for NVD API calls."""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable


class SlidingWindowRateLimiter:
    """Limit calls using a sliding time window."""

    def __init__(
        self,
        requests: int,
        window_seconds: int,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        """Create a sliding-window limiter."""

        self.requests = max(1, requests)
        self.window_seconds = max(1, window_seconds)
        self._sleep = sleep
        self._now = now
        self._timestamps: deque[float] = deque()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Wait until a new request is allowed."""

        while True:
            with self._lock:
                now = self._now()
                self._drop_expired(now)
                if len(self._timestamps) < self.requests:
                    self._timestamps.append(now)
                    return
                wait_seconds = self.window_seconds - (now - self._timestamps[0])
            self._sleep(max(0.0, wait_seconds))

    def retry_after(self, seconds: float | int | str | None) -> None:
        """Respect a server-provided retry delay."""

        try:
            wait_seconds = float(seconds) if seconds is not None else 0.0
        except (TypeError, ValueError):
            wait_seconds = 0.0
        if wait_seconds > 0:
            self._sleep(wait_seconds)

    def _drop_expired(self, now: float) -> None:
        """Remove timestamps outside the active window."""

        while self._timestamps and now - self._timestamps[0] >= self.window_seconds:
            self._timestamps.popleft()
