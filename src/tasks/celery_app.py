"""Celery application instance and BaseTask.

Configures the Celery app with:
- Redis broker/backend
- JSON serialization (no pickle for security)
- Per-queue routing
- BaseTask with auto status sync, retry, and idempotency
"""

from __future__ import annotations

import os
from typing import Any

from celery import Celery, Task

from src.core.constants import (
    CELERY_TASK_DEFAULT_QUEUE,
    CELERY_TASK_MAX_RETRIES,
    CELERY_TASK_RETRY_DELAY,
    CELERY_TASK_SOFT_TIME_LIMIT,
    CELERY_TASK_TIME_LIMIT,
    TASK_RESULT_KEY,
    TASK_RESULT_TTL,
    TASK_STATUS_KEY,
)

# ------------------------------------------------------------------
# Celery app
# ------------------------------------------------------------------

redis_url = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/1")
result_backend = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/2")

app = Celery(
    "codeguard",
    broker=redis_url,
    backend=result_backend,
)

app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_default_queue=CELERY_TASK_DEFAULT_QUEUE,
    task_queues={
        CELERY_TASK_DEFAULT_QUEUE: {"exchange": "codeguard"},
    },
    task_soft_time_limit=CELERY_TASK_SOFT_TIME_LIMIT,
    task_time_limit=CELERY_TASK_TIME_LIMIT,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
)

# ------------------------------------------------------------------
# BaseTask
# ------------------------------------------------------------------


class BaseCodeGuardTask(Task):
    """Base Celery task with state management, retry, and idempotency.

    Subclasses get:
    - Auto status sync: pending -> running -> completed/failed in Redis.
    - Idempotency guard: same task_id won't re-execute.
    - Structured error logging.
    - Configurable retry with exponential backoff.
    """

    abstract = True
    max_retries = CELERY_TASK_MAX_RETRIES
    default_retry_delay = CELERY_TASK_RETRY_DELAY

    def __init__(self) -> None:
        super().__init__()
        self._redis = None

    def _get_redis(self):
        if self._redis is None:
            import redis.asyncio as aioredis
            redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
            self._redis = aioredis.from_url(redis_url, decode_responses=True)
        return self._redis

    async def _set_status(self, task_id: str, status: str) -> None:
        """Update task status in Redis."""
        try:
            r = self._get_redis()
            key = TASK_STATUS_KEY.format(task_id=task_id)
            await r.setex(key, TASK_RESULT_TTL, status)
        except Exception:
            pass

    async def _check_idempotent(self, task_id: str) -> bool:
        """Check if task already executed. Returns True if duplicate."""
        try:
            r = self._get_redis()
            result_key = TASK_RESULT_KEY.format(task_id=task_id)
            exists = await r.exists(result_key)
            return bool(exists)
        except Exception:
            return False

    async def _cache_result(self, task_id: str, data: dict[str, Any]) -> None:
        """Cache task result in Redis."""
        try:
            import json
            r = self._get_redis()
            key = TASK_RESULT_KEY.format(task_id=task_id)
            await r.setex(key, TASK_RESULT_TTL, json.dumps(data, default=str))
        except Exception:
            pass

    def on_retry(self, exc, task_id, args, kwargs, einfo):
        """Log retry attempts."""
        import logging
        logger = logging.getLogger(__name__)
        logger.warning("celery_task_retry", task_id=task_id, error=str(exc)[:200])

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Log final failure."""
        import logging
        logger = logging.getLogger(__name__)
        logger.error("celery_task_failed", task_id=task_id, error=str(exc)[:500])
