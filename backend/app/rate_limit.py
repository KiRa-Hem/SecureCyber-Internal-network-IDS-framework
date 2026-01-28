import time
from typing import Tuple

from app.cache import cache_manager


class RateLimiter:
    """Simple fixed-window rate limiter using the shared cache."""

    def check(self, key: str, limit: int, window_seconds: int) -> Tuple[bool, int, int]:
        now = int(time.time())
        bucket_key = f"rl:{key}:{now // window_seconds}"
        entry = cache_manager.get(bucket_key)
        if entry is None:
            cache_manager.set(bucket_key, 1, window_seconds + 1)
            return True, now + window_seconds, limit - 1
        count = int(entry) + 1
        cache_manager.set(bucket_key, count, window_seconds + 1)
        allowed = count <= limit
        remaining = max(0, limit - count)
        return allowed, now + window_seconds, remaining


rate_limiter = RateLimiter()
