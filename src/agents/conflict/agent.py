"""Conflict Resolution Agent — LangGraph StateGraph + Human-in-the-loop.

Uses a real LangGraph StateGraph (not manual await) for the security DAG:
  auto_resolve → [conditional] → human_review (interrupt) → finalize

Checkpoint: LangGraph's MemorySaver persists state at interrupt_before,
enabling pause/resume across API calls. Thread ID = task_id.

Design invariants:
- ZERO LLM calls — all verdicts from deterministic rules or human input.
- Decision-ONLY — does NOT call GitHub API (integrations layer handles that).
- Full audit trail — every verdict recorded with rule_id/operator/evidence.
- Fail-safe — timeout defaults to BLOCK, never auto-waive on uncertainty.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any, Literal

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from typing_extensions import TypedDict

from src.agents.conflict.auto_resolver import AutoResolver
from src.agents.conflict.models import (
    AuditEntry,
    AuditTrail,
    FinalSecurityDecision,
    SecurityVerdict,
)
from src.core.models import Verdict
from src.engine.base_agent import BaseAgent
from src.storage.audit_log import AuditLogger
from src.storage.rule_store import RuleStore
from src.utils.id_gen import generate_id
from src.utils.logging import get_logger

logger = get_logger(__name__)

class ConflictState(TypedDict, total=False):
    """State carried through the security DAG."""
    security_report: dict[str, Any]
    exemption_rules: list[dict[str, Any]]
    is_framework_upgrade: bool
    target_version: dict[str, str] | None
    config: dict[str, Any]
    scan_id: str
    task_id: str
    # Auto-resolve outputs
    auto_resolved: list[dict[str, Any]]
    unresolved: list[dict[str, Any]]
    # Human-in-the-loop
    human_input: dict[str, str] | None    # finding_id -> block|waive|defer
    human_intervention_required: bool
    pending_human_items: list[str]
    # Final output
    final_decision: dict[str, Any] | None
    error: str


# ------------------------------------------------------------------
# Agent
# ------------------------------------------------------------------

class ConflictResolutionAgent(BaseAgent):
    """Conflict resolution agent backed by LangGraph StateGraph.

    Input:  SecurityReport (from SecurityAuditAgent) + exemption rules
    Output: FinalSecurityDecision (blocking verdict per finding + overall_blocking)

    Graph topology:
        auto_resolve ──[has unresolved?]──> human_review (INTERRUPT) ──> finalize
                       ──[all resolved ]──> finalize
    """

    agent_id = "conflict_resolution"
    description = (
        "Resolves security findings via deterministic exemption rules and "
        "human-in-the-loop for edge cases. Zero LLM, full audit trail. "
        "Powered by LangGraph StateGraph with native Checkpoint."
    )

    def __init__(
        self,
        rule_store: RuleStore | None = None,
        audit_logger: AuditLogger | None = None,
        human_loop_timeout_hours: int = 24,
    ) -> None:
        super().__init__()
        self._rule_store = rule_store
        self._audit_logger = audit_logger
        self._default_timeout = human_loop_timeout_hours
        # The graph is built lazily in _ensure_graph() (async) so the checkpointer
        # can be AsyncSqliteSaver (persistent, cross-process) when CODEGUARD_CHECKPOINT_DB_PATH
        # is set, or MemorySaver (in-process) otherwise. A synchronous build cannot
        # construct an async saver, and tests rely on MemorySaver isolation.
        self._graph = None
        self._checkpoint_db = os.getenv("CODEGUARD_CHECKPOINT_DB_PATH", "")

    async def _ensure_graph(self) -> None:
        """Lazily build the compiled graph, choosing the checkpointer.

        When CODEGUARD_CHECKPOINT_DB_PATH is set, use AsyncSqliteSaver so a paused
        graph survives across processes (cross-process human-in-the-loop resume).
        Otherwise fall back to an in-process MemorySaver (tests / no persistence).
        """
        if self._graph is not None:
            return
        db_path = self._checkpoint_db
        if not db_path:
            checkpointer = MemorySaver()
        else:
            import aiosqlite
            from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
            db_dir = os.path.dirname(db_path) or "."
            os.makedirs(db_dir, exist_ok=True)
            conn = await aiosqlite.connect(db_path)
            self._ckpt_conn = conn  # hold the connection for agent lifetime
            checkpointer = AsyncSqliteSaver(conn)
        self._graph = self._build_graph(checkpointer)

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def _build_graph(self, checkpointer: Any) -> Any:
        """Build the LangGraph StateGraph for security conflict resolution.

        Nodes:
            auto_resolve  — Run 5-rule engine, split resolved/unresolved.
            human_review  — INTERRUPT point: wait for human input.
            finalize      — Assemble FinalSecurityDecision + audit log.

        The checkpointer is provided by _ensure_graph() (async-gated) so we can
        use AsyncSqliteSaver for cross-process persistence when configured.
        """
        graph = StateGraph(ConflictState)

        graph.add_node("auto_resolve", self._auto_resolve_node)
        graph.add_node("human_review", self._human_review_node)
        graph.add_node("finalize", self._finalize_node)

        graph.set_entry_point("auto_resolve")

        # Conditional: unresolved items? -> human_review, else -> finalize
        graph.add_conditional_edges(
            "auto_resolve",
            self._route_after_resolve,
            {
                "human_review": "human_review",
                "finalize": "finalize",
            },
        )
        graph.add_edge("human_review", "finalize")
        graph.add_edge("finalize", END)

        return graph.compile(
            checkpointer=checkpointer,
            interrupt_before=["human_review"],  # ← Pause here for human input
        )

    # ------------------------------------------------------------------
    # Node: auto_resolve
    # ------------------------------------------------------------------

    @staticmethod
    def _auto_resolve_node(state: ConflictState) -> ConflictState:
        """Run the 5-rule auto-resolver engine."""
        security = state.get("security_report", {})
        rules = state.get("exemption_rules", [])
        is_upgrade = state.get("is_framework_upgrade", False)
        target = state.get("target_version")

        resolver = AutoResolver(rules)
        resolved, unresolved = resolver.resolve(
            vulnerabilities=security.get("vulnerabilities", []),
            code_issues=security.get("code_issues", []),
            is_framework_upgrade=is_upgrade,
            target_version=target,
            config=state.get("config", {}),
        )

        state["auto_resolved"] = resolved
        state["unresolved"] = unresolved
        state["human_intervention_required"] = len(unresolved) > 0
        state["pending_human_items"] = [
            item.get("cve_id") or item.get("rule_id", "")
            for item in unresolved
        ]

        logger.info(
            "auto_resolve_complete",
            resolved=len(resolved),
            unresolved=len(unresolved),
            needs_human=len(unresolved) > 0,
        )
        return state

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    @staticmethod
    def _route_after_resolve(state: ConflictState) -> Literal["human_review", "finalize"]:
        """Route: if unresolved items exist -> human_review, else -> finalize."""
        if state.get("unresolved"):
            return "human_review"
        return "finalize"

    # ------------------------------------------------------------------
    # Node: human_review (INTERRUPT point)
    # ------------------------------------------------------------------

    @staticmethod
    def _human_review_node(state: ConflictState) -> ConflictState:
        """Apply human decisions to unresolved items.

        This node is guarded by interrupt_before. LangGraph pauses
        BEFORE executing this node. When human input arrives,
        the caller updates state["human_input"] and resumes.
        """
        human_input = state.get("human_input") or {}
        unresolved = state.get("unresolved", [])
        resolved = list(state.get("auto_resolved", []))

        for item in unresolved:
            finding_id = (
                item.get("finding_id")
                or item.get("cve_id")
                or item.get("rule_id", "")
            )
            verdict = human_input.get(finding_id, "block")  # Default: block

            resolved.append({
                **item,
                "finding_id": finding_id,
                "verdict": verdict,
                "reason": f"Human decision: {verdict}",
                "rule_id": None,
                "operator": "human:reviewer",
                "evidence_link": item.get("evidence_url", ""),
                "appealable": False,
            })

        state["auto_resolved"] = resolved
        state["unresolved"] = []
        state["human_intervention_required"] = False
        state["pending_human_items"] = []
        return state

    # ------------------------------------------------------------------
    # Node: finalize
    # ------------------------------------------------------------------

    def _finalize_node(self, state: ConflictState) -> ConflictState:
        """Assemble FinalSecurityDecision from resolved verdicts."""
        all_resolved = state.get("auto_resolved", [])
        scan_id = state.get("scan_id", generate_id())

        decisions = []
        for v in all_resolved:
            fid = v.get("finding_id") or v.get("cve_id") or v.get("rule_id", "")
            decisions.append(SecurityVerdict(
                finding_id=fid,
                finding_type=(
                    "vulnerability" if "cve_id" in v or "dependency_type" in v else "code_issue"
                ),
                verdict=v.get("verdict", "block"),
                reason=v.get("reason", ""),
                rule_id=v.get("rule_id"),
                operator=v.get("operator", "auto"),
                evidence_link=v.get("evidence_link"),
                appealable=v.get("appealable", True),
            ))

        overall_blocking = any(d.verdict == Verdict.BLOCK.value for d in decisions)
        now = datetime.now(UTC).isoformat()

        # Audit trail
        audit = AuditTrail()
        audit.append(AuditEntry(
            timestamp=now,
            action="conflict_resolution_complete",
            detail={"scan_id": scan_id, "verdicts": len(decisions)},
            operator="system",
            row_hash="",
        ))

        # Persist audit log
        if self._audit_logger:
            task_id = state.get("task_id", "")
            for d in decisions:
                try:
                    self._audit_logger.log(
                        action="verdict_made",
                        operator=d.operator or "auto",
                        detail={
                            "finding_id": d.finding_id, "verdict": d.verdict, "reason": d.reason
                        },
                        evidence_link=d.evidence_link,
                        scan_id=scan_id,
                        task_id=task_id,
                    )
                except Exception:
                    logger.warning("audit_log_write_failed", finding_id=d.finding_id)

        decision = FinalSecurityDecision(
            scan_id=scan_id,
            overall_blocking=overall_blocking,
            decisions=decisions,
            audit_trail=audit,
            executed_at=now,
            executed_by="auto",
            human_intervention_required=state.get("human_intervention_required", False),
            pending_human_items=state.get("pending_human_items", []),
            appeal_count=sum(1 for d in decisions if d.appealable),
        )

        state["final_decision"] = decision.model_dump()
        return state

    # ------------------------------------------------------------------
    # Core logic — uses StateGraph.ainvoke
    # ------------------------------------------------------------------

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        """Execute conflict resolution via LangGraph StateGraph.

        If unresolved items remain after auto_resolve, the graph pauses
        at human_review. Call resume_with_human_input() to continue.
        """
        security_report = kwargs.get("security_report", {})
        code_metadata = kwargs.get("code_metadata", {})
        config_dict = kwargs.get("config", {})
        task_id = kwargs.get("task_id", generate_id())
        scan_id = kwargs.get("scan_id", generate_id())

        # Load exemption rules
        rules = []
        if self._rule_store:
            try:
                rules = self._rule_store.get_active_rules()
            except Exception:
                logger.warning("rule_store_load_failed", scan_id=scan_id)

        # Check for framework upgrade
        target_version = code_metadata.get("target_version") or {}
        is_framework_upgrade = bool(target_version.get("framework"))

        initial_state: ConflictState = {
            "security_report": security_report,
            "exemption_rules": rules,
            "is_framework_upgrade": is_framework_upgrade,
            "target_version": target_version if target_version else None,
            "config": config_dict,
            "scan_id": scan_id,
            "task_id": task_id,
            "auto_resolved": [],
            "unresolved": [],
            "human_input": None,
            "human_intervention_required": False,
            "pending_human_items": [],
            "final_decision": None,
            "error": "",
        }

        # Run the graph (pauses at human_review if needed)
        thread_id = f"conflict:{task_id}:{scan_id}"
        config = {"configurable": {"thread_id": thread_id}}
        await self._ensure_graph()

        result = await self._graph.ainvoke(initial_state, config)
        final = result.get("final_decision")
        if final:
            return final

        # The graph paused at human_review before a decision was produced.
        # Return a fail-safe decision that BLOCKS until a human adjudicates.
        # Never silently default to allow (violates the project fail-safe guarantee).
        pending = result.get("pending_human_items") or []
        return {
            "scan_id": scan_id,
            "overall_blocking": True,
            "decisions": [],
            "audit_trail": {"entries": []},
            "executed_at": datetime.now(UTC).isoformat(),
            "executed_by": "system:paused_for_human_review",
            "human_intervention_required": True,
            "pending_human_items": pending,
            "appeal_count": 0,
            "paused_for_human_review": True,
        }

    async def resume_with_human_input(
        self,
        task_id: str,
        scan_id: str,
        human_decisions: dict[str, str],
    ) -> dict[str, Any]:
        """Resume the paused graph with human decisions.

        Args:
            task_id: Same task_id used in run().
            scan_id: Same scan_id used in run().
            human_decisions: Map of finding_id -> block|waive|defer.

        Returns:
            FinalSecurityDecision dict with human decisions applied.
        """
        thread_id = f"conflict:{task_id}:{scan_id}"
        config = {"configurable": {"thread_id": thread_id}}

        await self._ensure_graph()
        try:
            # Inject the human decisions into the saved checkpoint, then resume from
            # the interrupt point. Passing input directly to ainvoke() would re-run
            # the already-executed nodes; update_state() + ainvoke(None) continues
            # from the human_review interrupt without replaying auto_resolve.
            self._graph.update_state(config, {"human_input": human_decisions})
            result = await self._graph.ainvoke(None, config)
            return result.get("final_decision") or {}
        except Exception as e:
            logger.error("conflict_resume_failed", error=str(e)[:200])
            raise

    async def get_pending_human_items(
        self,
        task_id: str,
        scan_id: str,
    ) -> list[str]:
        """Return the finding IDs waiting for human review, or [] if not paused.

        Reads the LangGraph checkpoint for the given thread. If the graph
        is not paused at the ``human_review`` interrupt (e.g. checkpointer
        lost or already resolved), returns an empty list so callers can
        fail safely instead of silently re-running the graph.
        """
        await self._ensure_graph()
        thread_id = f"conflict:{task_id}:{scan_id}"
        config = {"configurable": {"thread_id": thread_id}}
        try:
            snapshot = await self._graph.aget_state(config)
        except Exception as exc:
            logger.warning(
                "conflict_state_lookup_failed",
                task_id=task_id,
                error=str(exc)[:200],
            )
            return []

        if snapshot is None or "human_review" not in (snapshot.next or ()):
            return []
        return list(snapshot.values.get("pending_human_items", []))

    # ------------------------------------------------------------------
    # Degradation
    # ------------------------------------------------------------------

    async def degraded_run(
        self, original_error: Exception, **kwargs: Any
    ) -> dict[str, Any]:
        """Fallback: block all findings (safety-first)."""
        security_report = kwargs.get("security_report", {})
        scan_id = kwargs.get("scan_id", generate_id())
        now = datetime.now(UTC).isoformat()

        vulns = security_report.get("vulnerabilities", [])
        issues = security_report.get("code_issues", [])

        decisions = []
        for v in vulns:
            decisions.append(SecurityVerdict(
                finding_id=v.get("cve_id", ""),
                finding_type="vulnerability",
                verdict="block",
                reason="Resolver degraded — defaulting to block",
                operator="system:degraded",
                appealable=True,
            ))
        for iss in issues:
            decisions.append(SecurityVerdict(
                finding_id=iss.get("rule_id", ""),
                finding_type="code_issue",
                verdict="block",
                reason="Resolver degraded — defaulting to block",
                operator="system:degraded",
                appealable=True,
            ))

        decision = FinalSecurityDecision(
            scan_id=scan_id,
            overall_blocking=len(decisions) > 0,
            decisions=decisions,
            audit_trail=AuditTrail(),
            executed_at=now,
            executed_by="system:degraded",
        )
        return decision.model_dump()
