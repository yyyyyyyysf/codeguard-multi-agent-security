"""Outbound webhook callback task — standalone, best-effort with retry.

Separated from analysis tasks to allow independent queue routing
(celery:callback queue) so callback failures never block analysis.
"""

from __future__ import annotations

import json
import os
from typing import Any

from celery.utils.log import get_task_logger

from src.tasks.celery_app import BaseCodeGuardTask, app

logger = get_task_logger(__name__)


@app.task(
    base=BaseCodeGuardTask,
    bind=True,
    max_retries=5,
    default_retry_delay=5,
    soft_time_limit=30,
    queue="codeguard",
)
def send_callback_task(
    self: BaseCodeGuardTask,
    task_id: str = "",
    callback_url: str = "",
    event: str = "analysis.complete",
    repo: str = "",
    pr_number: int = 0,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Send an outbound webhook callback with retry.

    This task is idempotent: repeated calls with the same task_id
    for the same event type are safe.

    Args:
        task_id: Analysis task ID.
        callback_url: Target webhook URL.
        event: Event type (analysis.complete by default).
        repo: Repository name.
        pr_number: PR number.
        payload: Event data.
    """
    if not callback_url:
        return {"task_id": task_id, "status": "skipped", "reason": "no callback_url"}

    # Load result data
    import redis
    r = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    raw = r.get(f"codeguard:task:{task_id}:result")
    result_data = json.loads(raw) if raw else {}

    try:
        from src.integrations.webhook_sender import WebhookSender

        sender = WebhookSender()
        ok = _run_async(sender.send_event(
            callback_url=callback_url,
            event=event,
            task_id=task_id,
            scan_id=task_id,
            repo=repo,
            pr_number=pr_number if pr_number > 0 else None,
            payload=payload or result_data.get("summary", {}),
            report_url=f"/api/v1/tasks/{task_id}/report",
        ))

        if not ok and self.request.retries < self.max_retries:
            raise self.retry(countdown=min(5 * (2 ** self.request.retries), 60))

        return {"task_id": task_id, "status": "sent" if ok else "failed"}

    except self.MaxRetriesExceededError:
        logger.error("callback_retries_exhausted", task_id=task_id, url=callback_url[:80])
        return {"task_id": task_id, "status": "exhausted"}
    except Exception as exc:
        logger.error("callback_error", task_id=task_id, error=str(exc)[:200])
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc, countdown=5)
        return {"task_id": task_id, "status": "failed", "error": str(exc)[:200]}


def _run_async(coro):
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import nest_asyncio
            nest_asyncio.apply()
            return loop.run_until_complete(coro)
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)
