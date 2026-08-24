"""Appeal resume task — human-in-the-loop continuation.

``POST /api/v1/tasks/{task_id}/appeal`` stores the appeal request in
Redis and dispatches this task. The task loads the paused Conflict
Agent graph (via the LangGraph checkpointer), applies the human
decision, refreshes the cached security result and writes an audit
trail entry.

Fail-safe: if the graph is not paused at the human-review interrupt
(e.g. checkpointer lost), the appeal is marked ``failed`` and the
original blocking verdict stands.
"""

from __future__ import annotations

import json
import os
from typing import Any

from src.tasks.celery_app import BaseCodeGuardTask, app
from src.utils.logging import get_logger

logger = get_logger(__name__)

# Module-level redis import (mocked in tests)
try:
    import redis as _redis_module
except ImportError:
    _redis_module = None  # type: ignore[assignment]


@app.task(
    base=BaseCodeGuardTask,
    bind=True,
    max_retries=1,
    soft_time_limit=30,
)
def appeal_resume_task(
    self: BaseCodeGuardTask,
    appeal_id: str = "",
    task_id: str = "",
    finding_id: str = "",
    decision: str = "waive",
    reason: str = "",
    scan_id: str | None = None,
) -> dict[str, Any]:
    """Apply a human decision to a paused conflict graph."""
    scan_id = scan_id or task_id

    from src.agents.conflict.agent import ConflictResolutionAgent
    from src.storage.audit_log import AuditLogger
    from src.storage.rule_store import RuleStore

    audit_logger = AuditLogger()
    agent = ConflictResolutionAgent(
        rule_store=RuleStore(),
        audit_logger=audit_logger,
    )

    # 1. Verify the graph is actually paused at the human-review node.
    # get_pending_human_items is async (may read an AsyncSqliteSaver checkpoint).
    pending = _run_async(agent.get_pending_human_items(task_id, scan_id))
    if not pending:
        _mark_appeal_status(
            appeal_id,
            "failed",
            error="no_pending_human_state",
        )
        logger.error(
            "appeal_no_pending_state",
            appeal_id=appeal_id,
            task_id=task_id,
            finding_id=finding_id,
        )
        audit_logger.log(
            action="appeal_failed",
            operator="system",
            detail={
                "appeal_id": appeal_id,
                "finding_id": finding_id,
                "reason": "no_pending_human_state",
            },
            task_id=task_id,
            scan_id=scan_id,
        )
        return {
            "appeal_id": appeal_id,
            "task_id": task_id,
            "status": "failed",
            "error": "no_pending_human_state",
        }

    if finding_id not in pending:
        _mark_appeal_status(
            appeal_id,
            "failed",
            error="finding_not_pending",
        )
        logger.error(
            "appeal_finding_not_pending",
            appeal_id=appeal_id,
            finding_id=finding_id,
            pending=pending,
        )
        return {
            "appeal_id": appeal_id,
            "task_id": task_id,
            "status": "failed",
            "error": "finding_not_pending",
        }

    # 2. Resume the graph with the human decision.
    try:
        final_decision = _run_async(
            agent.resume_with_human_input(
                task_id=task_id,
                scan_id=scan_id,
                human_decisions={finding_id: decision},
            )
        )
    except Exception as exc:
        _mark_appeal_status(
            appeal_id,
            "failed",
            error=str(exc)[:200],
        )
        logger.error(
            "appeal_resume_failed",
            appeal_id=appeal_id,
            task_id=task_id,
            error=str(exc)[:200],
        )
        raise

    # 3. Refresh the cached security result with the new decision.
    _update_security_cache(task_id, final_decision)

    # 4. Audit trail.
    audit_logger.log(
        action="appeal_approved",
        operator="human:api",
        detail={
            "appeal_id": appeal_id,
            "finding_id": finding_id,
            "decision": decision,
            "reason": reason,
        },
        task_id=task_id,
        scan_id=scan_id,
    )

    # 5. Mark the appeal resolved.
    _mark_appeal_status(appeal_id, "resolved")
    logger.info(
        "appeal_resolved",
        appeal_id=appeal_id,
        task_id=task_id,
        finding_id=finding_id,
        decision=decision,
    )

    return {
        "appeal_id": appeal_id,
        "task_id": task_id,
        "status": "resolved",
        "decision": decision,
    }


# ==================================================================
# Redis helpers (synchronous, used within the Celery task)
# ==================================================================

def _mark_appeal_status(
    appeal_id: str,
    status: str,
    *,
    error: str = "",
) -> None:
    """Update the stored appeal record status."""
    try:
        if _redis_module is None:
            return
        r = _redis_module.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        raw = r.get(f"codeguard:appeal:{appeal_id}")
        try:
            data = json.loads(raw) if raw else {"appeal_id": appeal_id}
        except (TypeError, ValueError):
            data = {"appeal_id": appeal_id}
        data["status"] = status
        if error:
            data["error"] = error
        r.setex(f"codeguard:appeal:{appeal_id}", 86400 * 7, json.dumps(data, default=str))
    except Exception as exc:
        logger.warning(
            "appeal_status_sync_failed",
            appeal_id=appeal_id,
            error=str(exc)[:100],
        )


def _update_security_cache(
    task_id: str,
    final_decision: dict[str, Any],
) -> None:
    """Replace the conflict decision inside the cached security result."""
    try:
        if _redis_module is None:
            return
        r = _redis_module.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        key = f"codeguard:task:{task_id}:security"
        raw = r.get(key)
        try:
            data = json.loads(raw) if raw else {}
        except (TypeError, ValueError):
            data = {}
        conflict = data.get("conflict", {})
        conflict["final_decision"] = final_decision
        conflict["overall_blocking"] = bool(
            final_decision.get("overall_blocking", False)
        )
        data["conflict"] = conflict
        r.setex(key, 86400, json.dumps(data, default=str))
    except Exception as exc:
        logger.warning(
            "appeal_security_cache_update_failed",
            task_id=task_id,
            error=str(exc)[:100],
        )


def _run_async(coro):
    """Run an async coroutine from a sync Celery task context."""
    import asyncio

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None:
        import nest_asyncio

        nest_asyncio.apply()
        return loop.run_until_complete(coro)
    return asyncio.run(coro)
