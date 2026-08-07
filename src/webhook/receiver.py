"""Webhook receiver — entry point for inbound webhook events.

POST /webhook/github - GitHub webhook endpoint (MVP).
POST /webhook/gitlab - GitLab webhook endpoint (reserved).

Flow:
1. Verify HMAC-SHA256 signature (401 on failure).
2. Return 200 immediately (<200ms target).
3. Parse event type from X-GitHub-Event header.
4. Dispatch to handler for async processing.
"""

from __future__ import annotations

import hashlib
import hmac
import os

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from src.utils.hashing import verify_signature
from src.utils.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/webhook", tags=["webhook"])


@router.post("/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(None, alias="X-Hub-Signature-256"),
    x_github_event: str | None = Header(None, alias="X-GitHub-Event"),
) -> JSONResponse:
    """Receive and validate GitHub webhook events.

    Steps:
    1. Read raw body
    2. Verify HMAC-SHA256 signature
    3. Return 200
    4. Dispatch event to handler
    """
    body_bytes = await request.body()

    # Step 1: Verify signature
    secret = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    if not secret:
        logger.error("webhook_secret_not_configured")
        raise HTTPException(
            status_code=503,
            detail="Webhook secret not configured. Set GITHUB_WEBHOOK_SECRET.",
        )

    if not x_hub_signature_256:
        logger.warning("webhook_missing_signature", ip=request.client.host if request.client else "unknown")
        raise HTTPException(status_code=401, detail="Missing X-Hub-Signature-256 header")

    if not verify_signature(body_bytes, secret, x_hub_signature_256):
        logger.warning("webhook_invalid_signature", ip=request.client.host if request.client else "unknown")
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Step 2: Return 200 immediately
    logger.info("webhook_received", event_type=x_github_event or "unknown")

    # Step 3: Dispatch asynchronously (background task)
    event_type = x_github_event or "ping"
    body_str = body_bytes.decode("utf-8", errors="replace")

    if event_type == "ping":
        return JSONResponse(content={"message": "pong"})

    # Dispatch to GitHub handler
    from src.webhook.handlers.github import handle_github_event
    import asyncio
    asyncio.create_task(handle_github_event(event_type, body_str, request))

    return JSONResponse(content={"message": "accepted"})


@router.post("/gitlab")
async def gitlab_webhook(
    request: Request,
    x_gitlab_token: str | None = Header(None, alias="X-Gitlab-Token"),
) -> JSONResponse:
    """GitLab webhook endpoint (reserved for v0.2)."""
    return JSONResponse(
        status_code=501,
        content={"message": "GitLab webhook not yet implemented"},
    )
