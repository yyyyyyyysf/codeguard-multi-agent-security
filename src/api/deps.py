"""Dependency injection for FastAPI routes.

Provides reusable dependencies for:
- Configuration
- Redis connection
- API Key authentication (MVP: static key)
- Task state lookup
"""

from __future__ import annotations

import os

from fastapi import Header, HTTPException, Request

from src.core.errors import TaskNotFoundError, UnauthorizedActionError


# ------------------------------------------------------------------
# API Key auth
# ------------------------------------------------------------------

async def verify_api_key(
    request: Request,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
) -> str:
    """Verify the X-API-Key header against the configured key.

    MVP: Single static key from environment.
    v1.0+: OAuth2 / JWT token validation.
    """
    configured_key = os.getenv("CODEGUARD_API_KEY", "")

    # If no key is configured, allow all requests (dev mode)
    if not configured_key:
        return "anonymous"

    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail={"error": {"code": "SEC-003", "message": "Missing X-API-Key header"}},
        )

    if x_api_key != configured_key:
        raise HTTPException(
            status_code=401,
            detail={"error": {"code": "SEC-003", "message": "Invalid API key"}},
        )

    return "authenticated"


# ------------------------------------------------------------------
# Task state
# ------------------------------------------------------------------

async def get_task_state(task_id: str, request: Request) -> dict:
    """Fetch task state from Redis. Returns 404 if task not found.

    The Redis client is stored in app.state.redis (set in create_app).
    """
    redis = getattr(request.app.state, "redis", None)
    if not redis:
        raise HTTPException(status_code=503, detail="Redis unavailable")

    import json
    key = f"codeguard:task:{task_id}:result"
    try:
        raw = await redis.get(key)
        if not raw:
            raise HTTPException(status_code=404, detail={"error": {"code": "TASK-001", "message": "Task not found"}})
        return json.loads(raw)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=404, detail={"error": {"code": "TASK-001", "message": "Task not found"}})
