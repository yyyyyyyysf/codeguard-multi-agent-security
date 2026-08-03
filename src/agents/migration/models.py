"""Data models for Migration Assessment Agent.

All models use Pydantic. MigrationReport is the canonical output.
BreakingChangeImpact distinguishes between deterministic (ast_rule)
and LLM-assisted (llm_analysis) findings.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class AffectedFile(BaseModel):
    """A single file affected by a breaking change."""

    path: str = Field(..., description="Relative file path")
    line_number: int = Field(default=0, description="1-indexed line number", ge=0)
    code_snippet: str = Field(
        default="", description="The affected code fragment (max 200 chars)"
    )
    impact_level: str = Field(
        default="warning", description="breaking | warning"
    )


class BreakingChangeImpact(BaseModel):
    """A breaking change matched to affected code."""

    change_desc: str = Field(
        ..., description="Human-readable description of the breaking change"
    )
    source: str = Field(
        ..., description="ast_rule | llm_analysis — how this finding was produced"
    )
    official_reference_url: str | None = Field(
        None, description="URL to the official changelog/release notes"
    )
    affected_files: list[AffectedFile] = Field(
        default_factory=list, description="Files impacted by this change"
    )
    fix_suggestion: str = Field(
        default="", description="Suggested remediation or migration guide"
    )


class EffortEstimate(BaseModel):
    """Estimated effort for the migration."""

    affected_file_count: int = Field(default=0, description="Count of files needing changes")
    estimated_person_days: float = Field(
        default=0.0, description="Rough person-day estimate", ge=0.0
    )
    confidence: str = Field(
        default="medium", description="high | medium | low — trust level of this estimate"
    )


class MigrationReport(BaseModel):
    """Complete output of the Migration Assessment Agent.

    This is an ADVISORY report. It does NOT participate in security
    decisions and its output is never routed to the Conflict Agent.
    """

    scan_id: str = Field(..., description="Associated scan ID")
    framework: str = Field(..., description="Framework name (fastapi, django, etc.)")
    from_version: str = Field(..., description="Current version")
    to_version: str = Field(..., description="Target version")
    breaking_changes: list[BreakingChangeImpact] = Field(
        default_factory=list, description="Matched breaking changes with impact"
    )
    risk_level: str = Field(
        default="low", description="Overall risk: high | medium | low"
    )
    effort_estimate: EffortEstimate = Field(
        default_factory=EffortEstimate, description="Effort assessment"
    )
    degraded: bool = Field(
        default=False, description="True if LLM was unavailable (AST-only results)"
    )
    degraded_reasons: list[str] = Field(
        default_factory=list, description="Per-step degradation reasons"
    )
    scan_duration_ms: int = Field(default=0, description="Total scan time in ms")

    @property
    def total_affected_files(self) -> int:
        seen: set[str] = set()
        for bc in self.breaking_changes:
            for af in bc.affected_files:
                seen.add(af.path)
        return len(seen)

    @property
    def ast_rule_count(self) -> int:
        return sum(1 for bc in self.breaking_changes if bc.source == "ast_rule")

    @property
    def llm_analysis_count(self) -> int:
        return sum(1 for bc in self.breaking_changes if bc.source == "llm_analysis")
