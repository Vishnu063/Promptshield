import sys
import os
import time
import threading
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.middleware.rate_limit import TokenBucketRateLimiter


class TestTokenBucketRateLimiter(unittest.TestCase):
    def test_allows_within_capacity(self):
        limiter = TokenBucketRateLimiter(capacity=5, refill_rate_per_sec=1)
        for _ in range(5):
            result = limiter.check("client-a")
            self.assertTrue(result.allowed)

    def test_blocks_over_capacity(self):
        limiter = TokenBucketRateLimiter(capacity=3, refill_rate_per_sec=0.1)
        for _ in range(3):
            self.assertTrue(limiter.check("client-b").allowed)
        result = limiter.check("client-b")
        self.assertFalse(result.allowed)
        self.assertGreater(result.retry_after, 0)

    def test_refills_over_time(self):
        limiter = TokenBucketRateLimiter(capacity=1, refill_rate_per_sec=20)
        self.assertTrue(limiter.check("client-c").allowed)
        self.assertFalse(limiter.check("client-c").allowed)
        time.sleep(0.15)  # should refill ~3 tokens worth (capped at capacity=1)
        self.assertTrue(limiter.check("client-c").allowed)

    def test_separate_clients_have_separate_buckets(self):
        limiter = TokenBucketRateLimiter(capacity=1, refill_rate_per_sec=0.1)
        self.assertTrue(limiter.check("tenant-1").allowed)
        self.assertFalse(limiter.check("tenant-1").allowed)
        # tenant-2 must be unaffected by tenant-1 exhausting its bucket
        self.assertTrue(limiter.check("tenant-2").allowed)

    def test_reset_clears_bucket(self):
        limiter = TokenBucketRateLimiter(capacity=1, refill_rate_per_sec=0.01)
        self.assertTrue(limiter.check("client-d").allowed)
        self.assertFalse(limiter.check("client-d").allowed)
        limiter.reset("client-d")
        self.assertTrue(limiter.check("client-d").allowed)

    def test_invalid_config_raises(self):
        with self.assertRaises(ValueError):
            TokenBucketRateLimiter(capacity=0, refill_rate_per_sec=1)
        with self.assertRaises(ValueError):
            TokenBucketRateLimiter(capacity=5, refill_rate_per_sec=0)

    def test_concurrent_requests_do_not_overdraw_bucket(self):
        """Regression test: fire many threads at a small bucket and make
        sure the total number of *allowed* requests never exceeds capacity
        plus whatever legitimately refilled during the run. This is the
        kind of race a non-locked implementation would fail."""
        limiter = TokenBucketRateLimiter(capacity=10, refill_rate_per_sec=0.001)
        allowed_count = 0
        lock = threading.Lock()

        def worker():
            nonlocal allowed_count
            result = limiter.check("client-e")
            if result.allowed:
                with lock:
                    allowed_count += 1

        threads = [threading.Thread(target=worker) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertLessEqual(allowed_count, 10)

    def test_cost_greater_than_one(self):
        limiter = TokenBucketRateLimiter(capacity=10, refill_rate_per_sec=1)
        result = limiter.check("client-f", cost=7)
        self.assertTrue(result.allowed)
        result2 = limiter.check("client-f", cost=5)
        self.assertFalse(result2.allowed)


if __name__ == "__main__":
    unittest.main()
