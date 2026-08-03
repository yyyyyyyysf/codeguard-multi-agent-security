"""Data models for Conflict Resolution Agent.

All models use Pydantic. The FinalSecurityDecision is the
authoritative output that directly controls PR merge status.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class SecurityVerdict(BaseModel):
    """A single adjudicated finding.

    Every verdict must be traceable: which rule was applied,
    who made the call, and what evidence supports it.
    """

    finding_id: str = Field(
        ..., description="CVE ID or Semgrep rule ID from SecurityReport"
    )
    finding_type: str = Field(
        ..., description="vulnerability | code_issue"
    )
    verdict: str = Field(
        ..., description="block | waive | defer"
    )
    reason: str = Field(
        ..., description="Human-readable justification for this verdict"
    )
    rule_id: str | None = Field(
        None, description="Exemption rule ID that triggered this verdict (auto-resolve)"
    )
    operator: str | None = Field(
        None, description="system or human:{user_id}"
    )
    evidence_link: str | None = Field(
        None, description="URL to authoritative evidence"
    )
    appealable: bool = Field(
        default=True, description="Whether the developer can appeal this verdict"
    )


class AuditEntry(BaseModel):
    """A single immutable audit trail entry."""

    timestamp: str = Field(
        ..., description="UTC ISO 8601"
    )
    action: str = Field(
        ..., description="verdict_made | appeal_submitted | appeal_approved | blocking_executed | rule_matched"
    )
    detail: dict = Field(
        default_factory=dict, description="Structured details of the action"
    )
    operator: str = Field(
        default="system", description="system or human:{user_id}"
    )
    evidence_link: str | None = Field(
        None, description="URL to supporting evidence"
    )
    row_hash: str = Field(
        default="", description="SHA256(prev_hash + current_row) for integrity"
    )


class AuditTrail(BaseModel):
    """Append-only audit trail for a single analysis run.

    Immutable after creation. New entries are only appended.
    The row_hash chain enables tamper detection.
    """

    entries: list[AuditEntry] = Field(
        default_factory=list, description="Ordered list of audit entries"
    )

    def append(self, entry: AuditEntry) -> None:
        """Append a new entry to the trail."""
        self.entries.append(entry)

    @property
    def count(self) -> int:
        return len(self.entries)


class FinalSecurityDecision(BaseModel):
    """Authoritative output of the Conflict Resolution Agent.

    This is the decision that gates PR merge. overall_blocking=True
    means the PR MUST NOT be merged until all blocking findings are resolved.

    This model contains ONLY the business decision. It does NOT contain
    any GitHub API call logic — that belongs in the integrations layer.
    """

    scan_id: str = Field(..., description="Associated scan ID")
    overall_blocking: bool = Field(
        default=False,
        description="True if at least one finding is blocked and not waived",
    )
    decisions: list[SecurityVerdict] = Field(
        default_factory=list, description="Per-finding verdicts"
    )
    audit_trail: AuditTrail = Field(
        default_factory=AuditTrail, description="Full audit trail for this scan"
    )
    executed_at: str = Field(
        default="", description="UTC ISO 8601 timestamp of decision execution"
    )
    executed_by: str = Field(
        default="auto", description="auto | human:{operator_id}"
    )
    human_intervention_required: bool = Field(
        default=False,
        description="True if human input is needed (checkpoint paused)",
    )
    pending_human_items: list[str] = Field(
        default_factory=list,
        description="Finding IDs awaiting human review",
    )
    appeal_count: int = Field(
        default=0, description="Number of finding IDs that are appealable"
    )

    @property
    def blocking_count(self) -> int:
        return sum(1 for d in self.decisions if d.verdict == "block")

    @property
    def waived_count(self) -> int:
        return sum(1 for d in self.decisions if d.verdict == "waive")

    @property
    def deferred_count(self) -> int:
        return sum(1 for d in self.decisions if d.verdict == "defer")


class ResolutionConfig(BaseModel):
    """Runtime configuration for conflict resolution.

    Allows per-scan overrides without modifying persistent rule storage.
    """

    human_loop_timeout_hours: int = Field(
        default=24, ge=1, le=168, description="Max wait for human input"
    )
    critical_cannot_waive: bool = Field(
        default=True, description="If True, CVSS >= 9.0 findings cannot be waived"
    )
    auto_waive_low_confidence: bool = Field(
        default=True, description="Auto-waive code_issues with confidence=low"
    )
    fail_safe_blocking: bool = Field(
        default=True,
        description="If True, human loop timeout defaults to blocking",
    )
