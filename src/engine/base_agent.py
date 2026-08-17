"""BaseAgent abstract class.

All Agents MUST inherit from this class. The engine layer depends
only on BaseAgent (Dependency Inversion), not on concrete Agent
implementations.

Each Agent defines:
- Input/Output Schema (Pydantic models)
- Responsibility boundary (one-line description)
- Degradation strategy (at least 1)
- Failure policy
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any

from src.utils.id_gen import generate_id


class BaseAgent(ABC):
    """Abstract base for all CodeGuard Agents.

    Subclasses MUST:
    1. Define `agent_id` (unique string identifier)
    2. Define `description` (one-line responsibility statement)
    3. Implement `run()` (core execution logic)
    4. Implement `degraded_run()` (fallback when dependencies fail)

    Subclasses MAY:
    - Override `on_start()` / `on_complete()` / `on_error()` hooks.
    - Define custom input/output schemas.
    """

    agent_id: str = "base"
    description: str = "Base agent (should be overridden)"
    version: str = "0.1.0"

    def __init__(self) -> None:
        self.run_id: str = generate_id()
        self._start_time: float | None = None
        self._degraded: bool = False
        self._degraded_reasons: list[str] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def execute(self, **kwargs: Any) -> dict[str, Any]:
        """Execute the agent with full lifecycle.

        This is the public entry point. Subclasses should NOT override this
        method; override `run()` and `degraded_run()` instead.

        Lifecycle: on_start -> run (or degraded_run) -> on_complete
        On exception: on_error -> raise

        Returns:
            Dict with keys: agent_id, run_id, success, data, degraded,
            degraded_reasons, duration_ms, error.
        """
        self.run_id = generate_id()
        self._start_time = time.monotonic()

        from src.monitoring.metrics import get_metrics

        get_metrics().inc("agent_run_total", tags={"agent": self.agent_id})
        await self.on_start(**kwargs)

        try:
            result = await self.run(**kwargs)
            success = True
            error = None
        except Exception as e:
            await self.on_error(e, **kwargs)
            # Try degraded mode
            try:
                result = await self.degraded_run(e, **kwargs)
                self._degraded = True
                self._degraded_reasons.append(str(e))
                success = True
                error = None
            except Exception as degraded_error:
                result = {}
                success = False
                error = str(degraded_error)

        await self.on_complete(result, success, error)

        duration_ms = (time.monotonic() - self._start_time) * 1000
        get_metrics().observe(
            "agent_duration_ms",
            duration_ms,
            tags={"agent": self.agent_id},
        )
        if not success:
            get_metrics().inc("agent_failure_total", tags={"agent": self.agent_id})
        if self._degraded:
            get_metrics().inc("agent_degraded_total", tags={"agent": self.agent_id})

        return {
            "agent_id": self.agent_id,
            "run_id": self.run_id,
            "success": success,
            "data": result,
            "degraded": self._degraded,
            "degraded_reasons": self._degraded_reasons,
            "duration_ms": round(duration_ms, 2),
            "error": error,
        }

    # ------------------------------------------------------------------
    # Core logic (subclass implementations)
    # ------------------------------------------------------------------

    @abstractmethod
    async def run(self, **kwargs: Any) -> dict[str, Any]:
        """Core execution logic.

        Args come from orchestrator/engine, validated before dispatch.
        MUST return a dict (not raw Pydantic model).

        Raises:
            Any exception triggers degraded_run() fallback.
        """
        ...

    @abstractmethod
    async def degraded_run(self, original_error: Exception, **kwargs: Any) -> dict[str, Any]:
        """Fallback execution when run() fails.

        This is called automatically when run() raises. The Agent MUST
        produce a best-effort result here. The result is marked degraded.

        MUST return a dict.
        MUST NOT raise (or the agent is marked as failed).
        """
        ...

    # ------------------------------------------------------------------
    # Lifecycle hooks (optional overrides)
    # ------------------------------------------------------------------

    async def on_start(self, **kwargs: Any) -> None:
        """Called before run(). Override for setup logic."""
        pass

    async def on_complete(
        self, result: dict[str, Any], success: bool, error: str | None
    ) -> None:
        """Called after run() or degraded_run() completes.
        Override for cleanup, logging, metrics.
        """
        pass

    async def on_error(self, exception: Exception, **kwargs: Any) -> None:
        """Called when run() raises. Override for alerting, logging.
        This is called BEFORE degraded_run() is attempted.
        """
        pass
