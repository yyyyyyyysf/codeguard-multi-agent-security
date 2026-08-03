"""FastAPI application factory.

Creates and configures the FastAPI application with all routers,
middleware, and exception handlers registered.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.middleware.error_handler import register_exception_handlers
from src.api.middleware.request_log import RequestLogMiddleware
from src.api.routers import analyze, appeal, health, rules


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

    # Register exception handlers
    register_exception_handlers(app)

    # Register routers
    app.include_router(health.router, tags=["health"])
    app.include_router(analyze.router, prefix="/api/v1", tags=["analysis"])
    app.include_router(appeal.router, prefix="/api/v1", tags=["appeal"])
    app.include_router(rules.router, prefix="/api/v1", tags=["rules"])

    return app
