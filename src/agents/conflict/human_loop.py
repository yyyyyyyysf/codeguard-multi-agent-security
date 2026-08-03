"""Human-in-the-loop module via LangGraph checkpoint.

When the auto-resolver cannot resolve a finding (rules don't cover the case),
the workflow pauses via LangGraph's interrupt mechanism. A human operator
reviews the pending items and provides a decision.

State machine:
    IDLE -> WAITING_FOR_HUMAN -> HUMAN_RESPONDED -> RESOLVED
                                  |
                                  +--> TIMEOUT -> FAIL_SAFE_BLOCK

Timeout behavior (fail-safe):
    If the human doesn't respond within the configured timeout (default 24h),
    all pending findings default to BLOCK. This preserves security posture
    and prevents indefinite PR blockage without a decision.
"""

from __future__ import annotations

import time
from enum import Enum
from typing import Any

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import StateGraph
from typing_extensions import TypedDict


class HumanLoopState(str, Enum):
    IDLE = "idle"
    WAITING_FOR_HUMAN = "waiting_for_human"
    HUMAN_RESPONDED = "human_responded"
    TIMEOUT = "timeout"
    RESOLVED = "resolved"


class HumanLoopConfig(TypedDict, total=False):
    """Configuration for the human-in-the-loop mechanism."""
    timeout_hours: int
    fail_safe_blocking: bool  # Default to block on timeout


class HumanLoopStateData(TypedDict):
    """State carried through the human-loop LangGraph."""
    status: str
    pending_items: list[dict[str, Any]]
    resolved_items: list[dict[str, Any]]
    human_decisions: dict[str, str]  # finding_id -> block|waive|defer
    timeout_at: float
    error: str


class HumanLoopManager:
    """Manages human-in-the-loop checkpoints via LangGraph.

    Usage:
        manager = HumanLoopManager(timeout_hours=24)
        state = await manager.request_human_input(
            unresolved_findings=[...],
            task_id="task-001",
        )
        # ... wait for human input (days) ...
        decision = await manager.resume_with_human_input(
            human_decisions={"CVE-2024-xxx": "waive", "rule-abc": "block"},
        )
    """

    def __init__(
        self,
        timeout_hours: int = 24,
        fail_safe_blocking: bool = True,
    ) -> None:
        self._timeout_hours = timeout_hours
        self._fail_safe_blocking = fail_safe_blocking
        self._memory = MemorySaver()
        self._graph = self._build_graph()
        self._current_state: HumanLoopStateData | None = None
        self._thread_id: str = ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def request_human_input(
        self,
        unresolved_findings: list[dict[str, Any]],
        *,
        task_id: str = "",
        scan_id: str = "",
    ) -> dict[str, Any]:
        """Pause the workflow and request human input.

        Args:
            unresolved_findings: Findings the auto-resolver couldn't decide.
            task_id: Associated task ID.
            scan_id: Associated scan ID.

        Returns:
            State dict with status=waiting_for_human and the pending items.
        """
        self._thread_id = f"human_loop:{task_id}:{scan_id}"
        timeout_at = time.time() + (self._timeout_hours * 3600)

        initial_state: HumanLoopStateData = {
            "status": HumanLoopState.IDLE.value,
            "pending_items": unresolved_findings,
            "resolved_items": [],
            "human_decisions": {},
            "timeout_at": timeout_at,
            "error": "",
        }

        # Build and run the graph to the interrupt point
        config = {"configurable": {"thread_id": self._thread_id}}
        app = self._graph.compile(checkpointer=self._memory, interrupt_before=["human_review"])

        try:
            # This will run until the 'human_review' node, then interrupt
            state = app.invoke(initial_state, config)
            self._current_state = state
            return state
        except Exception as e:
            return {
                "status": HumanLoopState.IDLE.value,
                "pending_items": unresolved_findings,
                "resolved_items": [],
                "human_decisions": {},
                "timeout_at": timeout_at,
                "error": str(e),
            }

    async def resume_with_human_input(
        self,
        human_decisions: dict[str, str],
    ) -> dict[str, Any]:
        """Resume the workflow after human input is received.

        Args:
            human_decisions: Map of finding_id -> block|waive|defer.

        Returns:
            Final state with all items resolved.
        """
        if not self._current_state:
            return {"status": "error", "error": "No pending human loop state"}

        config = {"configurable": {"thread_id": self._thread_id}}
        app = self._graph.compile(checkpointer=self._memory, interrupt_before=["human_review"])

        # Update with human decisions and resume
        update = {
            "human_decisions": human_decisions,
            "status": HumanLoopState.HUMAN_RESPONDED.value,
        }

        try:
            state = app.invoke(update, config)
            self._current_state = state
            return state
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "pending_items": self._current_state.get("pending_items", []),
            }

    def check_timeout(self) -> bool:
        """Check if the human loop has timed out.

        Returns True if the timeout has been exceeded.
        """
        if not self._current_state:
            return False
        timeout_at = self._current_state.get("timeout_at", 0)
        return time.time() > timeout_at

    def get_timeout_fallback_verdicts(
        self,
    ) -> dict[str, str]:
        """Get the fail-safe verdicts when timeout occurs.

        All pending items default to 'block' (conservative, safety-first).
        """
        if not self._current_state:
            return {}

        if self._fail_safe_blocking:
            return {
                item.get("finding_id", item.get("cve_id", item.get("rule_id", ""))): "block"
                for item in self._current_state.get("pending_items", [])
            }
        return {}

    # ------------------------------------------------------------------
    # LangGraph graph
    # ------------------------------------------------------------------

    def _build_graph(self) -> StateGraph:
        """Build the simple human-loop state graph.

        Nodes:
            validate -> human_review [interrupt] -> apply_decisions

        The 'human_review' node is an interrupt point where the graph
        pauses and waits for external (human) input.
        """
        graph = StateGraph(HumanLoopStateData)

        graph.add_node("validate", self._validate_node)
        graph.add_node("human_review", self._human_review_node)
        graph.add_node("apply_decisions", self._apply_decisions_node)
        graph.add_node("timeout_handler", self._timeout_handler_node)

        graph.set_entry_point("validate")
        graph.add_edge("validate", "human_review")
        graph.add_conditional_edges(
            "human_review",
            self._after_human_review,
            {
                "apply": "apply_decisions",
                "timeout": "timeout_handler",
                "wait": "__end__",
            },
        )
        graph.add_edge("apply_decisions", "__end__")
        graph.add_edge("timeout_handler", "apply_decisions")

        return graph

    # ------------------------------------------------------------------
    # Nodes
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_node(state: HumanLoopStateData) -> HumanLoopStateData:
        """Validate that there are pending items to review."""
        if not state.get("pending_items"):
            state["status"] = HumanLoopState.RESOLVED.value
        else:
            state["status"] = HumanLoopState.IDLE.value
        return state

    @staticmethod
    def _human_review_node(state: HumanLoopStateData) -> HumanLoopStateData:
        """Interrupt point: wait for human input.

        In LangGraph, this node is configured as an interrupt_before node,
        so the graph pauses before executing it. The state at this point
        is checkpointed in MemorySaver.
        """
        # Check timeout
        timeout_at = state.get("timeout_at", 0)
        if time.time() > timeout_at:
            state["status"] = HumanLoopState.TIMEOUT.value
        elif state.get("human_decisions"):
            state["status"] = HumanLoopState.HUMAN_RESPONDED.value
        else:
            state["status"] = HumanLoopState.WAITING_FOR_HUMAN.value

        return state

    @staticmethod
    def _after_human_review(state: HumanLoopStateData) -> str:
        """Route after human_review node."""
        status = state.get("status", "")
        if status == HumanLoopState.HUMAN_RESPONDED.value:
            return "apply"
        if status == HumanLoopState.TIMEOUT.value:
            return "timeout"
        return "wait"

    @staticmethod
    def _apply_decisions_node(state: HumanLoopStateData) -> HumanLoopStateData:
        """Apply human decisions to pending items."""
        decisions = state.get("human_decisions", {})
        pending = state.get("pending_items", [])
        resolved = list(state.get("resolved_items", []))

        for item in pending:
            finding_id = item.get("finding_id") or item.get("cve_id") or item.get("rule_id", "")
            verdict = decisions.get(finding_id, "block")  # Default to block

            resolved.append({
                **item,
                "verdict": verdict,
                "reason": f"Human decision: {verdict}",
                "operator": "human:reviewer",
                "appealable": False,  # Human decisions are final
            })

        state["resolved_items"] = resolved
        state["pending_items"] = []
        state["status"] = HumanLoopState.RESOLVED.value
        return state

    @staticmethod
    def _timeout_handler_node(state: HumanLoopStateData) -> HumanLoopStateData:
        """Handle timeout: all pending items block (fail-safe)."""
        pending = state.get("pending_items", [])
        resolved = list(state.get("resolved_items", []))

        for item in pending:
            finding_id = item.get("finding_id") or item.get("cve_id") or item.get("rule_id", "")
            resolved.append({
                **item,
                "verdict": "block",
                "reason": f"Human loop timeout — defaulting to block (fail-safe)",
                "operator": "system:timeout",
                "appealable": True,  # Can still appeal after timeout
            })

        state["resolved_items"] = resolved
        state["pending_items"] = []
        state["status"] = HumanLoopState.RESOLVED.value
        return state
