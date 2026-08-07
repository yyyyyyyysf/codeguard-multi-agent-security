"""FastAPI application factory.

Creates and configures the FastAPI application with all routers,
middleware, and exception handlers registered.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.middleware.error_handler import register_exception_handlers
from src.api.middleware.rate_limit import RateLimitMiddleware
from src.api.middleware.request_log import RequestLogMiddleware
from src.api.routers import analyze, appeal, health, rules
from src.utils.logging import get_logger

logger = get_logger(__name__)


@asynccontextmanager
async def _redis_lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialize and tear down Redis on app start/stop.

    Fails gracefully: if Redis is unavailable, app.state.redis stays None
    and all Redis-dependent paths (task status, idempotency, rate limit)
    degrade gracefully with the existing getattr(..., None) pattern.
    """
    try:
        import redis.asyncio as aioredis

        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        app.state.redis = aioredis.from_url(
            redis_url,
            socket_connect_timeout=3,
            socket_timeout=5,
        )
        await app.state.redis.ping()
        logger.info("redis_connected", url=redis_url)
    except Exception as exc:
        logger.warning("redis_unavailable", error=str(exc)[:200])
        app.state.redis = None

    yield

    redis = getattr(app.state, "redis", None)
    if redis is not None:
        try:
            await redis.close()
        except Exception:
            pass


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns:
        Configured FastAPI app instance ready for uvicorn.
    """
    app = FastAPI(
        title="CodeGuard",
        description="Multi-Agent Code Repository Security Analysis Platform",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=_redis_lifespan,
    )

    # CORS (allow all for MVP)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Request logging middleware
    app.add_middleware(RequestLogMiddleware)

    # Rate limiting (enabled via RATE_LIMIT_ENABLED=true)
    app.add_middleware(RateLimitMiddleware)

    # Register exception handlers
    register_exception_handlers(app)

    # Register routers
    app.include_router(health.router, tags=["health"])
    app.include_router(analyze.router, prefix="/api/v1", tags=["analysis"])
    app.include_router(appeal.router, prefix="/api/v1", tags=["appeal"])
    app.include_router(rules.router, prefix="/api/v1", tags=["rules"])

    return app
