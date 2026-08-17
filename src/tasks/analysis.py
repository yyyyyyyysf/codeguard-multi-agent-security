"""Core analysis tasks — pure orchestration, zero business logic.

6 task types:
1. analysis_main_task     - Entry point, orchestrates full pipeline.
2. preprocess_task        - Clone repo, parse deps, build CodeMetadata.
3. security_chain_task    - Security Audit -> Conflict -> GitHub block.
4. migration_task         - Migration assessment (parallel, optional).
5. report_aggregation_task- Merge results, generate reports.
6. webhook_callback_task  - Outbound webhook notification.
"""

from __future__ import annotations

import json
import os
from typing import Any

from celery import chain, group

from src.core.models import ScanScope
from src.tasks.celery_app import BaseCodeGuardTask, app
from src.utils.id_gen import generate_task_id
from src.utils.logging import get_logger

logger = get_logger(__name__)

# Module-level redis import (mocked in tests)
try:
    import redis as _redis_module
except ImportError:
    _redis_module = None  # type: ignore[assignment]


# ==================================================================
# 1. Main entry task
# ==================================================================

@app.task(
    base=BaseCodeGuardTask,
    bind=True,
    max_retries=1,
    soft_time_limit=300,
)
def analysis_main_task(
    self: BaseCodeGuardTask,
    task_id: str = "",
    repo_url: str = "",
    branch: str = "main",
    scan_type: str = "full",
    target: dict[str, str] | None = None,
    pr_info: dict[str, Any] | None = None,
    callback_url: str = "",
) -> dict[str, Any]:
    """Entry point for a full analysis pipeline.

    Flow: preprocess -> (security_chain || migration) -> report -> callback
    """
    task_id = task_id or generate_task_id()

    if _sync_check_idempotent(task_id):
        return {"task_id": task_id, "status": "already_completed", "cached": True}

    _sync_set_status(task_id, "running")

    scan_scope = ScanScope.FULL if scan_type == "full" else ScanScope.DIFF

    try:
        workflow = chain(
            preprocess_task.s(
                task_id=task_id,
                repo_url=repo_url,
                branch=branch,
                scan_scope=scan_scope.value,
                pr_info=pr_info,
            ),
            _dispatch_parallel.s(
                task_id=task_id,
                target=target,
            ),
            report_aggregation_task.s(task_id=task_id),
            webhook_callback_task.s(
                task_id=task_id,
                callback_url=callback_url,
            ),
        )

        result = workflow.apply_async()
        return {"task_id": task_id, "status": "running", "celery_group_id": result.id}
    except Exception:
        _cleanup_task_dir(task_id)
        raise


# ==================================================================
# 2. Preprocess task
# ==================================================================

@app.task(
    base=BaseCodeGuardTask,
    bind=True,
    max_retries=2,
    default_retry_delay=10,
    soft_time_limit=60,
)
def preprocess_task(
    self: BaseCodeGuardTask,
    task_id: str = "",
    repo_url: str = "",
    branch: str = "main",
    scan_scope: str = "full",
    pr_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Clone repo, parse dependencies, generate CodeMetadata.

    On failure: marks task as degraded, returns minimal metadata.
    """
    _sync_set_status(task_id, "running:preprocess")

    try:
        from src.preprocess.metadata import run_preprocessing

        work_dir = f"/tmp/codeguard_repos/{task_id}"

        # Extract diff parameters from pr_info
        base_sha = None
        head_sha = None
        head_branch = None
        if pr_info:
            base_sha = pr_info.get("base_sha")
            head_sha = pr_info.get("head_sha")
            head_branch = pr_info.get("head_branch")

        metadata = run_preprocessing(
            repo_url=repo_url,
            work_dir=work_dir,
            task_id=task_id,
            scan_id=task_id,
            scan_scope=ScanScope(scan_scope),
            base_sha=base_sha,
            head_sha=head_sha,
            head_branch=head_branch,
            branch=branch,
        )

        # Cache metadata in Redis
        _sync_cache_json(f"codeguard:task:{task_id}:metadata", metadata, ttl=86400)
        _sync_publish(
            "code_metadata.ready",
            task_id=task_id,
            payload={"language": metadata.get("language", "unknown")},
        )

        return {
            "task_id": task_id,
            "status": "preprocess_done",
            "metadata": metadata,
        }

    except Exception as exc:
        logger.warning("preprocess_failed_degraded", task_id=task_id, error=str(exc)[:200])
        degraded_meta = {
            "task_id": task_id,
            "repo_url": repo_url,
            "scan_scope": scan_scope,
            "language": "unknown",
            "dependencies": [],
            "transitive_deps": [],
            "changed_files": [],
            "degraded": True,
            "degraded_reasons": [f"Preprocess failed: {str(exc)[:200]}"],
        }
        _sync_cache_json(f"codeguard:task:{task_id}:metadata", degraded_meta, ttl=3600)
        return {"task_id": task_id, "status": "preprocess_degraded", "metadata": degraded_meta}


# ==================================================================
# 3. Security chain task
# ==================================================================

@app.task(
    base=BaseCodeGuardTask,
    bind=True,
    max_retries=1,
    soft_time_limit=30,
)
def security_chain_task(
    self: BaseCodeGuardTask,
    task_id: str = "",
    code_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run Security Audit -> Conflict Resolution -> GitHub block.

    This is the critical path. Must complete within 30s.
    """
    _sync_set_status(task_id, "running:security")

    metadata = code_metadata or _sync_load_json(f"codeguard:task:{task_id}:metadata") or {}

    try:
        # Security Audit Agent
        from src.agents.security.agent import SecurityAuditAgent

        security_agent = SecurityAuditAgent()
        security_result = _sync_run_async(security_agent.execute(
            code_metadata=metadata,
            scan_scope=metadata.get("scan_scope", "full"),
            scan_id=task_id,
        ))

        # Conflict Resolution Agent
        from src.agents.conflict.agent import ConflictResolutionAgent

        conflict_agent = ConflictResolutionAgent()
        conflict_result = _sync_run_async(conflict_agent.execute(
            security_report=security_result.get("data", {}),
            code_metadata=metadata,
            task_id=task_id,
            scan_id=task_id,
        ))

        # Cache security result immediately (before migration completes)
        security_data = {
            "security": security_result.get("data", {}),
            "conflict": conflict_result.get("data", {}),
        }
        _sync_cache_json(f"codeguard:task:{task_id}:security", security_data, ttl=86400)
        conflict_data = conflict_result.get("data", {})
        # Fail-safe: if the conflict graph paused for human review, surface that
        # distinct state instead of claiming security is fully done.
        if conflict_data.get("paused_for_human_review"):
            _sync_set_status(task_id, "paused:human_review")
        else:
            _sync_set_status(task_id, "running:security_done")
        _sync_publish(
            "security.complete",
            task_id=task_id,
            payload={
                "overall_blocking": conflict_result.get("data", {}).get(
                    "overall_blocking", False
                )
            },
        )

        return {
            "task_id": task_id,
            "status": "security_done",
            "overall_blocking": conflict_result.get("data", {}).get("overall_blocking", False),
        }

    except Exception as exc:
        logger.error("security_chain_failed", task_id=task_id, error=str(exc)[:200])
        # Degrade: mark as blocking by default (fail-safe)
        degraded = {
            "security": {},
            "conflict": {
                "overall_blocking": True,
                "decisions": [],
                "human_intervention_required": False,
            },
            "degraded": True,
            "degraded_reasons": [f"Security chain failed: {str(exc)[:200]}"],
        }
        _sync_cache_json(f"codeguard:task:{task_id}:security", degraded, ttl=3600)
        return {"task_id": task_id, "status": "security_degraded", "overall_blocking": True}


# ==================================================================
# 4. Migration task
# ==================================================================

@app.task(
    base=BaseCodeGuardTask,
    bind=True,
    max_retries=1,
    soft_time_limit=60,
)
def migration_task(
    self: BaseCodeGuardTask,
    task_id: str = "",
    target: dict[str, str] | None = None,
    code_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run migration assessment (parallel to security chain).

    Only triggered when target framework/version is specified.
    Failure does not affect security results.
    """
    if not target:
        return {"task_id": task_id, "status": "migration_skipped"}

    _sync_set_status(task_id, "running:migration")

    metadata = code_metadata or _sync_load_json(f"codeguard:task:{task_id}:metadata") or {}

    try:
        from src.agents.migration.agent import MigrationAssessmentAgent

        agent = MigrationAssessmentAgent()
        result = _sync_run_async(agent.execute(
            code_metadata=metadata,
            target_version=target,
            scan_id=task_id,
        ))

        migration_data = result.get("data", {})
        _sync_cache_json(f"codeguard:task:{task_id}:migration", migration_data, ttl=86400)
        _sync_set_status(task_id, "running:migration_done")
        _sync_publish(
            "migration.complete",
            task_id=task_id,
            payload={"framework": migration_data.get("framework", "")},
        )

        return {"task_id": task_id, "status": "migration_done"}

    except Exception as exc:
        logger.warning("migration_degraded", task_id=task_id, error=str(exc)[:200])
        degraded = {"degraded": True, "degraded_reasons": [f"Migration failed: {str(exc)[:200]}"]}
        _sync_cache_json(f"codeguard:task:{task_id}:migration", degraded, ttl=3600)
        return {"task_id": task_id, "status": "migration_degraded"}


# ==================================================================
# 5. Report aggregation task
# ==================================================================

@app.task(
    base=BaseCodeGuardTask,
    bind=True,
    max_retries=1,
    soft_time_limit=30,
)
def report_aggregation_task(
    self: BaseCodeGuardTask,
    prev_results: list[dict[str, Any]] | None = None,
    task_id: str = "",
) -> dict[str, Any]:
    """Aggregate security + migration results into final report."""
    _sync_set_status(task_id, "running:report")

    security_data = _sync_load_json(f"codeguard:task:{task_id}:security") or {}
    migration_data = _sync_load_json(f"codeguard:task:{task_id}:migration") or {}
    metadata = _sync_load_json(f"codeguard:task:{task_id}:metadata") or {}

    try:
        from src.agents.reporter.agent import ReportAggregationAgent
        from src.storage.report_store import LocalFileReportStorage

        agent = ReportAggregationAgent(report_store=LocalFileReportStorage())
        result = _sync_run_async(agent.execute(
            security_data=security_data,
            migration_data=migration_data,
            repo_url=metadata.get("repo_url", ""),
            code_metadata=metadata,
            scan_id=task_id,
            task_id=task_id,
        ))

        report = result.get("data", {})
        _sync_cache_json(f"codeguard:task:{task_id}:result", report, ttl=86400)
        _sync_set_status(task_id, "completed")
        _sync_publish(
            "analysis.complete",
            task_id=task_id,
            payload={
                "blocking_count": report.get("summary", {}).get("blocking_count", 0)
            },
        )

        # Cleanup working directory
        _cleanup_task_dir(task_id)

        return {"task_id": task_id, "status": "completed"}

    except Exception as exc:
        logger.error("report_failed", task_id=task_id, error=str(exc)[:200])
        _cleanup_task_dir(task_id)
        return {"task_id": task_id, "status": "report_failed", "error": str(exc)[:200]}


# ==================================================================
# 6. Webhook callback task
# ==================================================================

@app.task(
    base=BaseCodeGuardTask,
    bind=True,
    max_retries=5,
    default_retry_delay=5,
    soft_time_limit=30,
)
def webhook_callback_task(
    self: BaseCodeGuardTask,
    prev_result: dict[str, Any] | None = None,
    task_id: str = "",
    callback_url: str = "",
) -> dict[str, Any]:
    """Send outbound webhook callback (best-effort, with retry)."""
    if not callback_url:
        return {"task_id": task_id, "status": "callback_skipped"}

    result_data = _sync_load_json(f"codeguard:task:{task_id}:result") or {}

    try:
        from src.integrations.webhook_sender import WebhookSender

        sender = WebhookSender()
        metadata = _sync_load_json(f"codeguard:task:{task_id}:metadata") or {}

        ok = _sync_run_async(sender.send_analysis_complete(
            callback_url=callback_url,
            task_id=task_id,
            scan_id=task_id,
            repo=metadata.get("repo_url", ""),
            payload=result_data.get("summary", {}),
            report_url=f"/api/v1/tasks/{task_id}/report",
        ))

        if not ok and self.request.retries < self.max_retries:
            raise self.retry(countdown=5 * (2 ** self.request.retries))

        return {"task_id": task_id, "status": "callback_sent" if ok else "callback_failed"}

    except Exception as exc:
        logger.error("callback_failed", task_id=task_id, error=str(exc)[:200])
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc) from None
        return {"task_id": task_id, "status": "callback_exhausted"}


# ==================================================================
# Helper: dispatch parallel security + migration
# ==================================================================

@app.task(
    base=BaseCodeGuardTask,
    bind=True,
    soft_time_limit=120,
)
def _dispatch_parallel(
    self: BaseCodeGuardTask,
    preprocess_result: dict[str, Any],
    task_id: str = "",
    target: dict[str, str] | None = None,
) -> list[Any]:
    """Internal: run security_chain_task and migration_task in parallel."""
    metadata = preprocess_result.get("metadata", {})

    parallel_group = group(
        security_chain_task.s(task_id=task_id, code_metadata=metadata),
        migration_task.s(task_id=task_id, target=target, code_metadata=metadata),
    )
    result = parallel_group.apply_async()
    return result.get(timeout=120)


# ==================================================================
# Synchronous Redis helpers (for use within Celery tasks)
# ==================================================================

def _sync_set_status(task_id: str, status: str) -> None:
    try:
        if _redis_module is None:
            return
        r = _redis_module.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        r.setex(f"codeguard:task:{task_id}:status", 3600, status)
    except Exception:
        pass


def _sync_cache_json(key: str, data: dict[str, Any], ttl: int = 3600) -> None:
    try:
        if _redis_module is None:
            return
        r = _redis_module.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        r.setex(key, ttl, json.dumps(data, default=str))
    except Exception:
        pass


def _sync_load_json(key: str) -> dict[str, Any] | None:
    try:
        if _redis_module is None:
            return None
        r = _redis_module.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        raw = r.get(key)
        return json.loads(raw) if raw else None
    except Exception:
        return None


def _sync_publish(
    channel: str,
    *,
    task_id: str,
    scan_id: str = "",
    payload: dict[str, Any] | None = None,
) -> None:
    """Publish a lifecycle event via the EventBus (best-effort).

    Uses the in-process subscriber list; when Redis is reachable the
    EventBus also publishes to the Redis Pub/Sub channel.
    """
    from src.engine.event_bus import EventBus

    try:
        redis_client = None
        try:
            import redis.asyncio as aioredis

            redis_client = aioredis.from_url(
                os.getenv("REDIS_URL", "redis://localhost:6379/0"),
                decode_responses=True,
            )
        except Exception:
            redis_client = None
        bus = EventBus(redis_client)
        _sync_run_async(
            bus.publish(
                channel,
                task_id=task_id,
                scan_id=scan_id or task_id,
                payload=payload or {},
            )
        )
    except Exception as exc:
        logger.warning(
            "event_publish_failed",
            channel=channel,
            task_id=task_id,
            error=str(exc)[:100],
        )


def _sync_check_idempotent(task_id: str) -> bool:
    try:
        if _redis_module is None:
            return False
        r = _redis_module.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        return bool(r.exists(f"codeguard:task:{task_id}:result"))
    except Exception:
        return False


def _sync_run_async(coro):
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


def _cleanup_task_dir(task_id: str) -> None:
    """Remove the cloned repo working directory for this task."""
    import shutil
    from pathlib import Path

    work_dir = Path(f"/tmp/codeguard_repos/{task_id}")
    try:
        if work_dir.exists():
            shutil.rmtree(str(work_dir), ignore_errors=True)
            logger.info("task_dir_cleaned", task_id=task_id, path=str(work_dir))
    except Exception:
        logger.warning("task_dir_cleanup_failed", task_id=task_id, path=str(work_dir))
