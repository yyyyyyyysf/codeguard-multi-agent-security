"""Conflict Resolution Agent — Deterministic rule engine + Human-in-the-loop.

Orchestrates:
1. Auto-resolver: matches findings against exemption rules (5 core rules).
2. Human loop: pauses via LangGraph checkpoint for unresolved findings.
3. Final decision: aggregates all verdicts into FinalSecurityDecision.

Design invariants:
- ZERO LLM calls — all verdicts from deterministic rules or human input.
- Decision-ONLY — does NOT call GitHub API (integrations layer handles that).
- Full audit trail — every verdict recorded with rule_id/operator/evidence.
- Fail-safe — timeout defaults to BLOCK, never auto-waive on uncertainty.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from src.agents.conflict.auto_resolver import AutoResolver
from src.agents.conflict.human_loop import HumanLoopManager
from src.agents.conflict.models import (
    AuditEntry,
    AuditTrail,
    FinalSecurityDecision,
    ResolutionConfig,
    SecurityVerdict,
)
from src.core.models import Verdict
from src.engine.base_agent import BaseAgent
from src.storage.audit_log import AuditLogger
from src.storage.rule_store import RuleStore
from src.utils.id_gen import generate_id
from src.utils.logging import get_logger

logger = get_logger(__name__)


class ConflictResolutionAgent(BaseAgent):
    """Conflict resolution agent: auto-resolve + human-in-the-loop. Zero LLM.

    Input:  SecurityReport (from SecurityAuditAgent) + exemption rules
    Output: FinalSecurityDecision (blocking verdict per finding + overall_blocking)
    """

    agent_id = "conflict_resolution"
    description = (
        "Resolves security findings via deterministic exemption rules and "
        "human-in-the-loop for edge cases. Zero LLM, full audit trail."
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

    # ------------------------------------------------------------------
    # Core logic
    # ------------------------------------------------------------------

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        """Execute conflict resolution on a SecurityReport.

        Args:
            security_report: SecurityReport dict from SecurityAuditAgent.
            code_metadata: CodeMetadata dict (for context like upgrade detection).
            config: Optional ResolutionConfig overrides.

        Returns:
            FinalSecurityDecision as dict.
        """
        security_report = kwargs.get("security_report", {})
        code_metadata = kwargs.get("code_metadata", {})
        config_dict = kwargs.get("config", {})
        task_id = kwargs.get("task_id", generate_id())
        scan_id = kwargs.get("scan_id", generate_id())

        config = ResolutionConfig(**config_dict)
        started = time.monotonic()

        # Load exemption rules
        rules = []
        if self._rule_store:
            try:
                rules = self._rule_store.get_active_rules()
            except Exception:
                rules = []

        # Detect if this is a framework upgrade PR
        target_version = code_metadata.get("target_version") or {}
        is_framework_upgrade = bool(target_version.get("framework"))

        # --- Step 1: Auto-resolve ---
        resolver = AutoResolver(rules)
        resolved, unresolved = resolver.resolve(
            vulnerabilities=security_report.get("vulnerabilities", []),
            code_issues=security_report.get("code_issues", []),
            is_framework_upgrade=is_framework_upgrade,
            target_version=target_version if target_version else None,
            config={
                "critical_cannot_waive": config.critical_cannot_waive,
                "auto_waive_low_confidence": config.auto_waive_low_confidence,
            },
        )

        # --- Step 2: Human loop for unresolved ---
        human_decisions: list[dict[str, Any]] = []
        human_intervention_required = False
        pending_ids: list[str] = []

        if unresolved:
            human_intervention_required = True
            pending_ids = [
                item.get("cve_id") or item.get("rule_id", "") for item in unresolved
            ]
            loop = HumanLoopManager(
                timeout_hours=config.human_loop_timeout_hours,
                fail_safe_blocking=config.fail_safe_blocking,
            )

            # Request human input (this pauses if checkpoint is active)
            loop_state = await loop.request_human_input(
                unresolved, task_id=task_id, scan_id=scan_id
            )

            # Check if timed out immediately (e.g., in automated mode)
            if loop.check_timeout():
                timeout_verdicts = loop.get_timeout_fallback_verdicts()
                for item in unresolved:
                    fid = item.get("cve_id") or item.get("rule_id", "")
                    verdict = timeout_verdicts.get(fid, "block")
                    human_decisions.append({
                        **item,
                        "verdict": verdict,
                        "reason": "Human loop timeout — defaulting to block (fail-safe)",
                        "operator": "system:timeout",
                        "appealable": True,
                    })
                human_intervention_required = False
                pending_ids = []

        # --- Step 3: Assemble FinalSecurityDecision ---
        all_verdicts = resolved + human_decisions

        decisions = []
        for v in all_verdicts:
            finding_id = v.get("finding_id") or v.get("cve_id") or v.get("rule_id", "")
            is_vuln = "cve_id" in v or "dependency_type" in v
            decisions.append(SecurityVerdict(
                finding_id=finding_id,
                finding_type="vulnerability" if is_vuln else "code_issue",
                verdict=v.get("verdict", "block"),
                reason=v.get("reason", ""),
                rule_id=v.get("rule_id"),
                operator=v.get("operator", "auto"),
                evidence_link=v.get("evidence_link"),
                appealable=v.get("appealable", True),
            ))

        # overall_blocking: True if ANY finding is blocked
        overall_blocking = any(d.verdict == Verdict.BLOCK.value for d in decisions)

        # Audit trail
        now = datetime.now(timezone.utc).isoformat()
        audit = AuditTrail()
        audit.append(AuditEntry(
            timestamp=now,
            action="conflict_resolution_started",
            detail={"scan_id": scan_id, "findings_count": len(all_verdicts)},
            operator="system",
            row_hash="",
        ))
        for d in decisions:
            audit.append(AuditEntry(
                timestamp=now,
                action="verdict_made",
                detail={
                    "finding_id": d.finding_id,
                    "verdict": d.verdict,
                    "reason": d.reason,
                    "rule_id": d.rule_id,
                },
                operator=d.operator or "auto",
                evidence_link=d.evidence_link,
                row_hash="",
            ))

        if human_intervention_required:
            audit.append(AuditEntry(
                timestamp=now,
                action="human_intervention_required",
                detail={"pending_findings": pending_ids},
                operator="system",
                row_hash="",
            ))

        # Persist audit log
        if self._audit_logger:
            for entry in audit.entries:
                try:
                    self._audit_logger.log(
                        action=entry.action,
                        operator=entry.operator,
                        detail=entry.detail,
                        evidence_link=entry.evidence_link,
                        scan_id=scan_id,
                        task_id=task_id,
                    )
                except Exception:
                    pass  # Audit log failure is non-fatal for security decision

        decision = FinalSecurityDecision(
            scan_id=scan_id,
            overall_blocking=overall_blocking,
            decisions=decisions,
            audit_trail=audit,
            executed_at=now,
            executed_by="auto",
            human_intervention_required=human_intervention_required,
            pending_human_items=pending_ids,
            appeal_count=sum(1 for d in decisions if d.appealable),
        )

        logger.info(
            "conflict_resolution_complete",
            scan_id=scan_id,
            total=len(decisions),
            blocking=decision.blocking_count,
            waived=decision.waived_count,
            deferred=decision.deferred_count,
            needs_human=human_intervention_required,
            overall_blocking=overall_blocking,
        )

        return decision.model_dump()

    # ------------------------------------------------------------------
    # Degradation
    # ------------------------------------------------------------------

    async def degraded_run(
        self, original_error: Exception, **kwargs: Any
    ) -> dict[str, Any]:
        """Fallback: block all findings (safety-first degradation).

        When the resolver fails entirely, we default to blocking
        everything. This preserves security posture.
        """
        security_report = kwargs.get("security_report", {})
        scan_id = kwargs.get("scan_id", generate_id())
        now = datetime.now(timezone.utc).isoformat()

        vulns = security_report.get("vulnerabilities", [])
        issues = security_report.get("code_issues", [])

        decisions = []
        for v in vulns:
            cid = v.get("cve_id", "")
            decisions.append(SecurityVerdict(
                finding_id=cid,
                finding_type="vulnerability",
                verdict="block",
                reason=f"Resolver degraded — defaulting to block: {str(original_error)}",
                operator="system:degraded",
                appealable=True,
            ))
        for issue in issues:
            rid = issue.get("rule_id", "")
            decisions.append(SecurityVerdict(
                finding_id=rid,
                finding_type="code_issue",
                verdict="block",
                reason=f"Resolver degraded — defaulting to block: {str(original_error)}",
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
