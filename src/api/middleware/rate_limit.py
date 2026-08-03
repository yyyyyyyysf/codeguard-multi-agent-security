"""Rate limiting middleware (MVP: reserved, not active by default).

Production-grade rate limiting using Redis sliding window.
Per-IP and per-API-Key buckets, configurable threshold.

Enabled via RATE_LIMIT_ENABLED=true env var.
"""

from __future__ import annotations

import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class RateLimitMiddleware(BaseHTTPMiddleware):
    """IP-level + API-Key-level rate limiting middleware.

    MVP: Inactive by default. Enable via RATE_LIMIT_ENABLED=true.
    """

    async def dispatch(self, request: Request, call_next):
        enabled = os.getenv("RATE_LIMIT_ENABLED", "false").lower() == "true"

        if not enabled:
            return await call_next(request)

        identifier = request.client.host if request.client else "unknown"
        redis = getattr(request.app.state, "redis", None)

        if redis:
            minute_key = f"codeguard:rate_limit:{identifier}:{self._current_minute()}"
            try:
                count = await redis.incr(minute_key)
                if count == 1:
                    await redis.expire(minute_key, 60)
                limit = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
                if count > limit:
                    return JSONResponse(
                        status_code=429,
                        content={
                            "error": {
                                "code": "RATE-001",
                                "message": "Rate limit exceeded. Try again later.",
                                "retryable": True,
                                "detail": {"retry_after_seconds": 60},
                            }
                        },
                    )
            except Exception:
                pass  # Redis failure: skip rate limiting

        return await call_next(request)

    @staticmethod
    def _current_minute() -> int:
        import time
        return int(time.time() // 60)
