"""Health check endpoint.

GET /health - Returns service status and dependency connectivity.
"""

from __future__ import annotations

from fastapi import APIRouter, Request

from src.api.schemas.response import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health_check(request: Request) -> dict:
    """Service health check with dependency status."""
    deps: dict[str, str] = {}

    # Check Redis
    redis = getattr(request.app.state, "redis", None)
    if redis:
        try:
            await redis.ping()
            deps["redis"] = "ok"
        except Exception:
            deps["redis"] = "unavailable"
    else:
        deps["redis"] = "not_configured"

    return {
        "status": "ok",
        "version": "0.1.0",
        "dependencies": deps,
    }
