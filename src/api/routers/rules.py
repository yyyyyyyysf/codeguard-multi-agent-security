"""Rule management endpoints.

GET  /api/v1/rules - List active exemption rules.
PUT  /api/v1/rules/{rule_id} - Update rule (MVP: read-only, reserved).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from src.api.deps import verify_api_key
from src.api.schemas.request import RuleUpdateRequest
from src.api.schemas.response import RuleListResponse

router = APIRouter()


@router.get("/rules", response_model=RuleListResponse)
async def list_rules(
    request: Request,
    _api_key: str = Depends(verify_api_key),
) -> dict:
    """List all currently active exemption rules."""
    # TODO: Read from RuleStore when storage integration is ready
    return {"rules": [], "count": 0}


@router.put("/rules/{rule_id}")
async def update_rule(
    rule_id: str,
    body: RuleUpdateRequest,
    request: Request,
    _api_key: str = Depends(verify_api_key),
) -> dict:
    """Update an exemption rule (MVP: reserved)."""
    raise HTTPException(
        status_code=501,
        detail={"error": {"code": "NOT-IMPL", "message": "Rule update not yet implemented"}},
    )
