"""Appeal endpoints.

POST /api/v1/tasks/{task_id}/appeal - Submit exemption appeal.
GET  /api/v1/tasks/{task_id}/appeals - Query appeal status.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Request

from src.api.deps import verify_api_key
from src.api.schemas.request import AppealRequest
from src.api.schemas.response import AppealResponse
from src.utils.id_gen import generate_id
from src.utils.logging import get_logger

logger = get_logger(__name__)

router = APIRouter()


@router.post("/tasks/{task_id}/appeal", status_code=200, response_model=AppealResponse)
async def submit_appeal(
    task_id: str,
    body: AppealRequest,
    request: Request,
    _api_key: str = Depends(verify_api_key),
) -> dict:
    """Submit an exemption appeal for a blocked finding.

    This triggers the human-in-the-loop flow in the Conflict Agent.
    """
    appeal_id = generate_id()

    redis = getattr(request.app.state, "redis", None)
    appeal_data = {
        "appeal_id": appeal_id,
        "task_id": task_id,
        "finding_id": body.finding_id,
        "reason": body.reason,
        "evidence_url": body.evidence_url,
        "status": "pending_review",
    }

    if redis:
        await redis.setex(
            f"codeguard:appeal:{appeal_id}",
            86400 * 7,  # 7 days
            json.dumps(appeal_data),
        )
        await redis.rpush(f"codeguard:task:{task_id}:appeals", appeal_id)
        await redis.expire(f"codeguard:task:{task_id}:appeals", 86400 * 7)

    # Dispatch to the Celery worker to resume the paused Conflict graph.
    # Best-effort: if dispatch fails the appeal stays pending_review and
    # the original blocking verdict stands.
    dispatch_ok = _dispatch_appeal_resume(
        appeal_id=appeal_id,
        task_id=task_id,
        finding_id=body.finding_id,
        decision="waive",
        reason=body.reason,
    )
    if not dispatch_ok:
        logger.warning(
            "appeal_dispatch_failed",
            appeal_id=appeal_id,
            task_id=task_id,
        )

    return {
        "appeal_id": appeal_id,
        "status": "pending_review",
        "estimated_hours": 24,
    }


@router.get("/tasks/{task_id}/appeals")
async def get_appeals(
    task_id: str,
    request: Request,
    _api_key: str = Depends(verify_api_key),
) -> dict:
    """Query appeal statuses for a task."""
    redis = getattr(request.app.state, "redis", None)
    appeals: list[dict] = []

    if redis:
        appeal_ids = await redis.lrange(f"codeguard:task:{task_id}:appeals", 0, -1)
        for appeal_id in appeal_ids:
            raw = await redis.get(f"codeguard:appeal:{appeal_id}")
            if raw:
                try:
                    appeals.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue

    return {"task_id": task_id, "appeals": appeals}


def _dispatch_appeal_resume(
    *,
    appeal_id: str,
    task_id: str,
    finding_id: str,
    decision: str,
    reason: str,
) -> bool:
    """Enqueue appeal_resume_task on the Celery 'codeguard' queue.

    Returns True if the task was accepted by Celery, False otherwise
    (e.g. broker unavailable). Import is lazy so the API stays responsive
    when Celery is not deployed.
    """
    try:
        from src.tasks.appeal import appeal_resume_task

        appeal_resume_task.apply_async(
            kwargs={
                "appeal_id": appeal_id,
                "task_id": task_id,
                "finding_id": finding_id,
                "decision": decision,
                "reason": reason,
            },
            queue="codeguard",
        )
        return True
    except Exception as exc:
        logger.warning(
            "appeal_celery_enqueue_failed",
            appeal_id=appeal_id,
            error=str(exc)[:200],
        )
        return False
