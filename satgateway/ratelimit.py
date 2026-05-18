"""Rate limiting with Redis priority, in-memory fallback.

Solves: in-memory rate limiter resets on restart and doesn't
share state across workers.
"""

import os
import time
import hashlib
import threading
from typing import Optional, Tuple


class RateLimiter:
    """Token-bucket / sliding-window rate limiter.

    Redis is used when SATGATEWAY_REDIS_URL or REDIS_HOST is set.
    Otherwise falls back to a thread-safe in-memory store.
    """

    def __init__(
        self,
        redis_url: Optional[str] = None,
        default_limit: int = 30,
        default_window: int = 60,
    ):
        self.default_limit = int(os.getenv("SATGATEWAY_RATE_LIMIT", default_limit))
        self.default_window = default_window
        self._memory: dict = {}
        self._lock = threading.Lock()
        self._redis = None

        redis_url = redis_url or os.getenv("SATGATEWAY_REDIS_URL") or os.getenv("REDIS_HOST")
        if redis_url:
            try:
                import redis as redis_lib
                if redis_url.startswith("redis://"):
                    self._redis = redis_lib.from_url(redis_url, decode_responses=True)
                else:
                    self._redis = redis_lib.Redis(host=redis_url, port=6379, decode_responses=True)
                self._redis.ping()
            except Exception:
                self._redis = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_allowed(self, key: str, limit: Optional[int] = None, window: Optional[int] = None) -> Tuple[bool, dict]:
        """Returns (allowed: bool, headers: dict with Retry-After, X-RateLimit-*)."""
        limit = limit or self.default_limit
        window = window or self.default_window

        if self._redis:
            return self._is_allowed_redis(key, limit, window)
        return self._is_allowed_memory(key, limit, window)

    def is_allowed_request(self, request) -> Tuple[bool, dict]:
        """Extract a stable key from the request and check limit."""
        key = self._key_for_request(request)
        return self.is_allowed(key)

    # ------------------------------------------------------------------
    # Key extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _key_for_request(request) -> str:
        """Hash the client IP + User-Agent for a stable per-client key."""
        client = request.client.host if request.client else "unknown"
        ua = request.headers.get("user-agent", "")
        forwarded = request.headers.get("x-forwarded-for", "")
        # Prefer X-Forwarded-For when behind a proxy
        if forwarded:
            client = forwarded.split(",")[0].strip()
        raw = f"{client}|{ua}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    # ------------------------------------------------------------------
    # Redis backend (sliding window)
    # ------------------------------------------------------------------

    def _is_allowed_redis(self, key: str, limit: int, window: int) -> Tuple[bool, dict]:
        import time
        now = time.time()
        bucket_key = f"ratelimit:{key}"
        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(bucket_key, 0, now - window)
        pipe.zcard(bucket_key)
        pipe.zadd(bucket_key, {str(now): now})
        pipe.expire(bucket_key, window)
        _, current_count, _, _ = pipe.execute()

        # current_count is count BEFORE this request, so we compare
        allowed = current_count < limit
        if not allowed:
            # Remove the just-added entry since request is blocked
            self._redis.zrem(bucket_key, str(now))

        reset_at = int(now + window)
        remaining = max(0, limit - current_count - (1 if allowed else 0))
        headers = {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(reset_at),
        }
        if not allowed:
            headers["Retry-After"] = str(window)
        return allowed, headers

    # ------------------------------------------------------------------
    # In-memory backend (sliding window)
    # ------------------------------------------------------------------

    def _is_allowed_memory(self, key: str, limit: int, window: int) -> Tuple[bool, dict]:
        now = time.time()
        with self._lock:
            bucket = self._memory.setdefault(key, [])
            # Prune old entries
            cutoff = now - window
            self._memory[key] = [t for t in bucket if t > cutoff]
            current_count = len(self._memory[key])
            allowed = current_count < limit
            if allowed:
                self._memory[key].append(now)
            reset_at = int(now + window)
            remaining = max(0, limit - len(self._memory[key]))

        headers = {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(reset_at),
        }
        if not allowed:
            headers["Retry-After"] = str(window)
        return allowed, headers
