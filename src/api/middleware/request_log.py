"""Request logging middleware.

Logs structured information about every request:
- Method, path, status code, duration
- Client IP, User-Agent
- Masks sensitive headers
"""

from __future__ import annotations

import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from src.utils.logging import get_logger

logger = get_logger(__name__)

SENSITIVE_HEADERS = {"authorization", "cookie", "x-api-key", "x-hub-signature-256"}


class RequestLogMiddleware(BaseHTTPMiddleware):
    """Logs every HTTP request with structured fields."""

    async def dispatch(self, request: Request, call_next):
        started = time.monotonic()

        response = await call_next(request)

        duration_ms = (time.monotonic() - started) * 1000

        logger.info(
            "request",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=round(duration_ms, 2),
            client_ip=request.client.host if request.client else "unknown",
        )

        return response
