"""Rule management endpoints.

GET  /api/v1/rules - List active exemption rules.
PUT  /api/v1/rules/{rule_id} - Update an exemption rule.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from src.api.deps import verify_api_key
from src.api.schemas.request import RuleUpdateRequest
from src.api.schemas.response import RuleListResponse
from src.utils.logging import get_logger

logger = get_logger(__name__)

router = APIRouter()


@router.get("/rules", response_model=RuleListResponse)
async def list_rules(
    request: Request,
    _api_key: str = Depends(verify_api_key),
) -> dict:
    """List all currently active exemption rules."""
    from src.storage.rule_store import RuleStore

    store = RuleStore(redis_client=getattr(request.app.state, "redis", None))
    rules = store.get_active_rules()
    return {"rules": rules, "count": len(rules)}


@router.put("/rules/{rule_id}")
async def update_rule(
    rule_id: str,
    body: RuleUpdateRequest,
    request: Request,
    _api_key: str = Depends(verify_api_key),
) -> dict:
    """Update an exemption rule. Returns 404 if the rule does not exist."""
    from src.storage.rule_store import RuleStore

    store = RuleStore(redis_client=getattr(request.app.state, "redis", None))

    updated = store.update_rule(
        rule_id,
        enabled=body.enabled,
        pattern=body.pattern,
        reason=body.reason,
    )
    if not updated:
        raise HTTPException(
            status_code=404,
            detail={
                "error": {
                    "code": "RULE-001",
                    "message": f"Rule not found: {rule_id}",
                }
            },
        )

    rule = store.get_rule(rule_id)
    logger.info("rule_updated", rule_id=rule_id)
    return {"rule_id": rule_id, "updated": True, "rule": rule}
