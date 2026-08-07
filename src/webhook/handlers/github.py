"""GitHub webhook event handler.

Handles pull_request and push events from GitHub webhooks.
Extracts repo info, PR context, commit SHAs for task creation.
Implements idempotency via Redis — same commit won't be scanned twice.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from fastapi import Request

from src.utils.id_gen import generate_task_id
from src.utils.logging import get_logger

logger = get_logger(__name__)


async def handle_github_event(
    event_type: str,
    body: str | bytes,
    request: Request | None = None,
) -> dict[str, Any]:
    """Handle an incoming GitHub webhook event.

    Args:
        event_type: GitHub event type from X-GitHub-Event header.
        body: Raw JSON body string.
        request: FastAPI Request for app state access.

    Returns:
        Dict with task_id if scan was triggered, empty dict otherwise.
    """
    try:
        data = json.loads(body) if isinstance(body, str) else json.loads(body.decode("utf-8"))
    except json.JSONDecodeError:
        logger.error("webhook_invalid_json", event_type=event_type)
        return {}

    if event_type == "pull_request":
        return await _handle_pr_event(data, request)
    elif event_type == "push":
        return await _handle_push_event(data, request)
    else:
        logger.info("webhook_ignored_event", event_type=event_type)
        return {}


# ------------------------------------------------------------------
# PR events
# ------------------------------------------------------------------

async def _handle_pr_event(
    data: dict[str, Any],
    request: Request | None = None,
) -> dict[str, Any]:
    """Handle a pull_request webhook event."""
    action = data.get("action", "")
    pr = data.get("pull_request", {})
    repo = data.get("repository", {})

    if not pr or not repo:
        return {}

    is_draft = pr.get("draft", False)
    scan_drafts = os.getenv("CODEGUARD_SCAN_DRAFTS", "false").lower() == "true"

    # Skip non-scannable actions
    if action not in ("opened", "synchronize", "reopened"):
        logger.info("webhook_pr_skipped", action=action)
        return {}

    # Skip draft PRs (configurable)
    if is_draft and not scan_drafts:
        logger.info("webhook_draft_skipped", pr_number=pr.get("number"))
        return {}

    return await _trigger_scan(data, request, is_pr=True)


# ------------------------------------------------------------------
# Push events
# ------------------------------------------------------------------

async def _handle_push_event(
    data: dict[str, Any],
    request: Request | None = None,
) -> dict[str, Any]:
    """Handle a push webhook event (only main/master by default)."""
    ref = data.get("ref", "")
    default_branch = data.get("repository", {}).get("default_branch", "main")

    # Only scan pushes to the default branch
    if not ref.endswith(f"/{default_branch}"):
        logger.info("webhook_push_skipped", ref=ref)
        return {}

    return await _trigger_scan(data, request, is_pr=False)


# ------------------------------------------------------------------
# Scan trigger
# ------------------------------------------------------------------

async def _trigger_scan(
    data: dict[str, Any],
    request: Request | None = None,
    is_pr: bool = True,
) -> dict[str, Any]:
    """Extract scan parameters and dispatch to Celery.

    Implements idempotency: same (repo, pr_number, head_sha) won't
    create a new task.
    """
    repo = data.get("repository", {})
    repo_full_name = repo.get("full_name", "")
    repo_url = repo.get("clone_url") or repo.get("html_url", "")

    if is_pr:
        pr_data = data.get("pull_request", {})
        pr_number = pr_data.get("number", 0)
        head_sha = pr_data.get("head", {}).get("sha", "")
        base_sha = pr_data.get("base", {}).get("sha", "")
        base_branch = pr_data.get("base", {}).get("ref", "main")
        head_branch = pr_data.get("head", {}).get("ref", "")
    else:
        pr_number = 0
        head_sha = data.get("after", "")
        base_sha = data.get("before", "")
        base_branch = repo.get("default_branch", "main")
        head_branch = base_branch

    if not repo_url or not head_sha:
        return {}

    if not _repo_url_is_safe(repo_url):
        logger.error("webhook_ssrf_blocked", repo_url=repo_url)
        return {}

    # Idempotency check via Redis
    task_id = None
    if request:
        redis = getattr(request.app.state, "redis", None)
        if redis:
            dedup_key = _idempotency_key(repo_full_name, pr_number, head_sha)
            existing = await redis.get(f"codeguard:task:dedup:{dedup_key}")
            if existing:
                logger.info("webhook_idempotent_skip", repo=repo_full_name, sha=head_sha[:8])
                return {"task_id": existing.decode() if isinstance(existing, bytes) else existing, "cached": True}

    # Generate task_id
    task_id = generate_task_id()

    # Dispatch to Celery for async execution
    dispatched = False
    try:
        from src.tasks.analysis import analysis_main_task
        analysis_main_task.apply_async(
            kwargs={
                "task_id": task_id,
                "repo_url": repo_url,
                "branch": base_branch,
                "scan_type": "diff" if is_pr else "full",
                "pr_info": {
                    "pr_number": pr_number,
                    "base_branch": base_branch,
                    "head_branch": head_branch,
                    "base_sha": base_sha,
                    "head_sha": head_sha,
                } if is_pr else None,
            },
            queue="codeguard",
        )
        dispatched = True
        logger.info(
            "webhook_scan_dispatched",
            repo=repo_full_name,
            pr=pr_number if is_pr else None,
            head_sha=head_sha[:8],
            task_id=task_id,
        )
    except Exception as e:
        logger.error("webhook_celery_dispatch_failed", repo=repo_full_name, error=str(e)[:200])

    # Only write idempotency / status if the task was actually dispatched.
    # Writing them on failure would block re-delivery for 72 hours.
    if dispatched and request:
        redis = getattr(request.app.state, "redis", None)
        if redis:
            dedup_key = _idempotency_key(repo_full_name, pr_number, head_sha)
            await redis.setex(
                f"codeguard:task:dedup:{dedup_key}",
                259200,  # 72 hours
                task_id,
            )
            await redis.setex(
                f"codeguard:task:{task_id}:status",
                3600,
                "pending",
            )

    return {"task_id": task_id}


def _idempotency_key(repo: str, pr_number: int, head_sha: str) -> str:
    """Generate a deterministic idempotency key."""
    raw = f"{repo}:{pr_number}:{head_sha}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _repo_url_is_safe(url: str) -> bool:
    """Delegate to shared SSRF validator (src.utils.repo_url)."""
    from src.utils.repo_url import repo_url_is_safe
    return repo_url_is_safe(url)
