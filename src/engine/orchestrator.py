"""Orchestration engine: coordinates DAG + event-driven execution.

The orchestrator is responsible for:
1. Receiving analysis tasks from Celery workers.
2. Running preprocess -> dispatch to Agents via the correct topology.
3. Security main chain: DAG (Security -> Conflict) via LangGraph StateGraph.
4. Auxiliary chain: Event-driven (Migration subscribed to code_metadata.ready).
5. Final aggregation: Report Agent collects results from both chains.

Architecture constraint:
    Engine depends only on BaseAgent (not concrete Agent classes).
    Concrete Agents register themselves with the engine at startup.
    Engine NEVER imports from src/agents/*.
"""

from __future__ import annotations

from typing import Any

from src.core.constants import (
    TASK_PROGRESS_KEY,
    TASK_RESULT_KEY,
    TASK_RESULT_TTL,
    TASK_STATUS_KEY,
)
from src.core.models import ScanScope, ScanStatus
from src.engine.base_agent import BaseAgent
from src.engine.event_bus import EventBus
from src.utils.logging import get_logger

logger = get_logger(__name__)


class Orchestrator:
    """Central orchestrator for CodeGuard analysis tasks.

    Usage:
        orch = Orchestrator(redis_client, event_bus)
        orch.register_agent("security", security_agent)
        orch.register_agent("conflict", conflict_agent)
        orch.register_agent("migration", migration_agent)
        orch.register_agent("reporter", reporter_agent)

        result = await orch.run_analysis(
            task_id="...",
            scan_id="...",
            repo_url="...",
            ...
        )
    """

    def __init__(
        self,
        redis_client: Any = None,
        event_bus: EventBus | None = None,
    ) -> None:
        self._redis = redis_client
        self._event_bus = event_bus or EventBus(redis_client)
        self._agents: dict[str, BaseAgent] = {}

    # ------------------------------------------------------------------
    # Agent registry
    # ------------------------------------------------------------------

    def register_agent(self, name: str, agent: BaseAgent) -> None:
        """Register an Agent with the orchestrator.

        Args:
            name: Logical name ('security', 'conflict', 'migration', 'reporter').
            agent: Agent instance (must extend BaseAgent).
        """
        self._agents[name] = agent

    def get_agent(self, name: str) -> BaseAgent | None:
        """Get a registered agent by name."""
        return self._agents.get(name)

    # ------------------------------------------------------------------
    # Task lifecycle
    # ------------------------------------------------------------------

    async def run_analysis(
        self,
        *,
        task_id: str,
        scan_id: str,
        repo_url: str,
        code_metadata: dict[str, Any],
        scan_scope: ScanScope = ScanScope.FULL,
        target_version: dict[str, str] | None = None,
        scan_config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run the full analysis pipeline.

        1. Publish code_metadata.ready -> triggers Migration Agent (async)
        2. Run Security DAG: Security -> Conflict (synchronous within this worker)
        3. Run Report aggregation

        Note: Migration Agent runs in parallel via event subscription.
        The orchestrator does NOT await migration; it starts the DAG immediately.

        Args:
            task_id: Celery task ID.
            scan_id: Unique scan ID.
            repo_url: Repository URL.
            code_metadata: Preprocessed CodeMetadata dict.
            scan_scope: FULL or DIFF.
            target_version: Optional migration target {framework, from_version, to_version}.
            scan_config: Optional SecurityScanConfig overrides.

        Returns:
            Aggregated report dict.
        """
        scan_config = scan_config or {}
        await self._update_task_status(task_id, ScanStatus.RUNNING.value)
        await self._update_progress(task_id, "security")

        # --- Step 1: Publish code_metadata.ready event ---
        # This triggers the Migration Agent (subscribed) asynchronously.
        await self._event_bus.publish_code_metadata_ready(
            task_id=task_id,
            scan_id=scan_id,
            metadata={
                "metadata": code_metadata,
                "target_version": target_version,
            },
        )

        # --- Step 2: Security DAG (Security -> Conflict) ---
        security_agent = self.get_agent("security")
        conflict_agent = self.get_agent("conflict")

        if not security_agent or not conflict_agent:
            return {"error": "Security or Conflict agent not registered"}

        # Run Security Agent
        security_result = await security_agent.execute(
            task_id=task_id,
            scan_id=scan_id,
            code_metadata=code_metadata,
            scan_scope=scan_scope.value,
            scan_config=scan_config,
        )

        # Run Conflict Agent with Security output
        await self._update_progress(task_id, "conflict")
        conflict_result = await conflict_agent.execute(
            task_id=task_id,
            scan_id=scan_id,
            security_report=security_result.get("data", {}),
            code_metadata=code_metadata,
        )

        # Publish security complete
        await self._event_bus.publish_security_complete(
            task_id=task_id,
            scan_id=scan_id,
            security_report={
                "security": security_result.get("data", {}),
                "conflict": conflict_result.get("data", {}),
            },
        )

        # --- Step 3: Wait for migration (with timeout) ---
        # In MVP, migration runs in the same worker via event subscription.
        # The orchestrator polls or waits for a signal.
        migration_agent = self.get_agent("migration")
        migration_result = None
        if migration_agent and target_version:
            await self._update_progress(task_id, "migration")
            migration_result = await migration_agent.execute(
                task_id=task_id,
                scan_id=scan_id,
                code_metadata=code_metadata,
                target_version=target_version,
            )

        # Publish migration complete
        await self._event_bus.publish_migration_complete(
            task_id=task_id,
            scan_id=scan_id,
            migration_report=migration_result.get("data", {}) if migration_result else {},
        )

        # --- Step 4: Report aggregation ---
        await self._update_progress(task_id, "report")
        reporter_agent = self.get_agent("reporter")
        aggregated_report = {}
        if reporter_agent:
            reporter_result = await reporter_agent.execute(
                task_id=task_id,
                scan_id=scan_id,
                security_data={
                    "security": security_result.get("data", {}),
                    "conflict": conflict_result.get("data", {}),
                },
                migration_data=migration_result.get("data", {}) if migration_result else {},
                repo_url=repo_url,
                code_metadata=code_metadata,
            )
            aggregated_report = reporter_result.get("data", {})

        # Publish analysis complete
        await self._event_bus.publish_analysis_complete(
            task_id=task_id,
            scan_id=scan_id,
            aggregated_report=aggregated_report,
        )

        # --- Step 5: Finalize ---
        await self._update_task_status(task_id, ScanStatus.COMPLETED.value)

        # Cache result
        report_data = {
            "task_id": task_id,
            "scan_id": scan_id,
            "status": "completed",
            "security": conflict_result.get("data", {}),
            "migration": migration_result.get("data", {}) if migration_result else None,
            "aggregated": aggregated_report,
        }
        await self._cache_result(task_id, report_data)

        return report_data

    # ------------------------------------------------------------------
    # Redis helpers
    # ------------------------------------------------------------------

    async def _update_task_status(self, task_id: str, status: str) -> None:
        if self._redis:
            try:
                key = TASK_STATUS_KEY.format(task_id=task_id)
                await self._redis.setex(key, TASK_RESULT_TTL, status)
            except Exception as e:
                logger.warning("redis_status_sync_failed", task_id=task_id, error=str(e)[:100])

    async def _update_progress(self, task_id: str, stage: str) -> None:
        if self._redis:
            try:
                key = TASK_PROGRESS_KEY.format(task_id=task_id)
                await self._redis.setex(key, TASK_RESULT_TTL, stage)
            except Exception as e:
                logger.warning("orchestrator_redis_error", error=str(e)[:100])
                pass

    async def _cache_result(self, task_id: str, data: dict[str, Any]) -> None:
        if self._redis:
            try:
                import json
                key = TASK_RESULT_KEY.format(task_id=task_id)
                await self._redis.setex(
                    key, TASK_RESULT_TTL, json.dumps(data, default=str)
                )
            except Exception as e:
                logger.warning("orchestrator_redis_error", error=str(e)[:100])
                pass
