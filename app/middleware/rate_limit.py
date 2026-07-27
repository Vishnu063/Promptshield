"""
Token bucket rate limiter, per client key (API key / tenant id).

Deliberately uses time.monotonic(), not time.time(): wall-clock time
can jump backward (NTP adjustment, DST, VM migration) and a naive
implementation using time.time() can compute a negative elapsed
interval, which either grants free tokens or drains the bucket
incorrectly. monotonic() never goes backward within a process.

Thread-safe with a per-bucket lock so concurrent requests from the
same client don't race on refill math.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class RateLimitResult:
    allowed: bool
    remaining: float
    retry_after: float = 0.0


class _Bucket:
    __slots__ = ("tokens", "last_refill", "lock")

    def __init__(self, capacity: float):
        self.tokens = capacity
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()


class TokenBucketRateLimiter:
    def __init__(self, capacity: int = 20, refill_rate_per_sec: float = 0.5):
        """
        capacity: max burst size (tokens in a full bucket)
        refill_rate_per_sec: steady-state tokens/sec (e.g. 0.5 = 30/min)
        """
        if capacity <= 0 or refill_rate_per_sec <= 0:
            raise ValueError("capacity and refill_rate_per_sec must be positive")
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate_per_sec)
        self._buckets: dict[str, _Bucket] = {}
        self._buckets_lock = threading.Lock()

    def _get_bucket(self, key: str) -> _Bucket:
        with self._buckets_lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(self.capacity)
                self._buckets[key] = bucket
            return bucket

    def check(self, key: str, cost: float = 1.0) -> RateLimitResult:
        bucket = self._get_bucket(key)
        with bucket.lock:
            now = time.monotonic()
            elapsed = now - bucket.last_refill
            # elapsed should never be negative with monotonic(), but
            # clamp defensively — cheap insurance against a bad clock
            # source on an unusual platform.
            elapsed = max(elapsed, 0.0)

            bucket.tokens = min(self.capacity, bucket.tokens + elapsed * self.refill_rate)
            bucket.last_refill = now

            if bucket.tokens >= cost:
                bucket.tokens -= cost
                return RateLimitResult(allowed=True, remaining=bucket.tokens)

            deficit = cost - bucket.tokens
            retry_after = deficit / self.refill_rate
            return RateLimitResult(allowed=False, remaining=bucket.tokens, retry_after=retry_after)

    def reset(self, key: str) -> None:
        with self._buckets_lock:
            self._buckets.pop(key, None)
