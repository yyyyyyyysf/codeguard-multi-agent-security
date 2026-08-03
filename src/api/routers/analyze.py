"""Analysis task endpoints.

POST /api/v1/analyze - Submit a new analysis task (async).
GET  /api/v1/tasks/{task_id} - Query task status.
GET  /api/v1/tasks/{task_id}/report - Get full report.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from src.api.deps import get_task_state, verify_api_key
from src.api.schemas.request import AnalyzeRequest
from src.api.schemas.response import AnalyzeResponse, TaskStatusResponse
from src.utils.id_gen import generate_task_id

router = APIRouter()


@router.post("/analyze", status_code=202, response_model=AnalyzeResponse)
async def submit_analysis(
    body: AnalyzeRequest,
    request: Request,
    _api_key: str = Depends(verify_api_key),
) -> dict:
    """Submit a new code analysis task.

    The task is enqueued to Celery for async execution.
    Returns immediately with a task_id for polling.
    """
    task_id = generate_task_id()

    # TODO: Dispatch to Celery when task layer is ready (Module 13)
    # For now, store initial state in Redis
    redis = getattr(request.app.state, "redis", None)
    if redis:
        import json
        await redis.setex(
            f"codeguard:task:{task_id}:status",
            3600,
            "pending",
        )

    return {"task_id": task_id, "status": "pending"}


@router.get("/tasks/{task_id}", response_model=TaskStatusResponse)
async def get_task(
    task_id: str,
    request: Request,
    _api_key: str = Depends(verify_api_key),
) -> dict:
    """Query the status and results of an analysis task."""
    try:
        state = await get_task_state(task_id, request)
        return state
    except HTTPException:
        # Task not yet completed or not found — return pending status
        redis = getattr(request.app.state, "redis", None)
        status = "pending"
        progress = 0
        if redis:
            s = await redis.get(f"codeguard:task:{task_id}:status")
            if s:
                status = s.decode() if isinstance(s, bytes) else s
            p = await redis.get(f"codeguard:task:{task_id}:progress")
            if p:
                stage = p.decode() if isinstance(p, bytes) else p
                stage_map = {"preprocess": 20, "security": 50, "conflict": 70, "migration": 85, "report": 95}
                progress = stage_map.get(stage, 10)

        return {
            "task_id": task_id,
            "status": status,
            "progress": progress,
            "current_stage": "",
            "created_at": None,
            "started_at": None,
            "finished_at": None,
            "security_result": None,
            "migration_result": None,
            "full_report_url": None,
        }


@router.get("/tasks/{task_id}/report")
async def get_report(
    task_id: str,
    request: Request,
    format: str = "json",
    _api_key: str = Depends(verify_api_key),
) -> dict:
    """Get the full analysis report for a completed task.

    Args:
        format: "json" (default) or "html".
    """
    state = await get_task_state(task_id, request)
    return {
        "task_id": task_id,
        "format": format,
        "report": state.get("aggregated", state),
    }
