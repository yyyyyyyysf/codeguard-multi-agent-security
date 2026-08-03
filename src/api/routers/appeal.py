"""Appeal endpoints.

POST /api/v1/tasks/{task_id}/appeal - Submit exemption appeal.
GET  /api/v1/tasks/{task_id}/appeals - Query appeal status.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from src.api.deps import verify_api_key
from src.api.schemas.request import AppealRequest
from src.api.schemas.response import AppealResponse
from src.utils.id_gen import generate_id

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

    # TODO: Dispatch to human loop when task layer is ready (Module 13)
    # For now, store appeal state in Redis
    redis = getattr(request.app.state, "redis", None)
    if redis:
        import json
        appeal_data = {
            "appeal_id": appeal_id,
            "finding_id": body.finding_id,
            "reason": body.reason,
            "evidence_url": body.evidence_url,
            "status": "pending_review",
        }
        await redis.setex(
            f"codeguard:appeal:{appeal_id}",
            86400 * 7,  # 7 days
            json.dumps(appeal_data),
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
    return {"task_id": task_id, "appeals": []}
