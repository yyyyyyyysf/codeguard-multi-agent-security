"""API request schemas (Pydantic v2).

All request validation happens here, at the API boundary.
Invalid input is rejected before any business logic runs.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class TargetVersion(BaseModel):
    """Migration target version info."""
    framework: str = Field(..., description="Framework name", min_length=1, max_length=50)
    from_version: str = Field(..., description="Current version")
    to_version: str = Field(..., description="Target version")


class PRInfo(BaseModel):
    """Pull request context for webhook-triggered scans."""
    pr_number: int = Field(..., ge=1, description="PR number")
    base_branch: str = Field(default="main", description="Target branch")
    head_branch: str = Field(default="", description="Source branch")
    base_sha: str | None = Field(default=None, description="Base commit SHA (for diff scan)")
    head_sha: str | None = Field(default=None, description="Head commit SHA (for diff scan)")


class ScanConfig(BaseModel):
    """Per-scan configuration overrides."""
    enable_security: bool = Field(default=True, description="Run security scan")
    enable_migration: bool = Field(default=True, description="Run migration assessment")
    block_severity: str = Field(default="high", description="high | critical")
    file_whitelist: list[str] = Field(default_factory=list)
    file_blacklist: list[str] = Field(default_factory=lambda: ["test/", "tests/"])


class AnalyzeRequest(BaseModel):
    """POST /api/v1/analyze request body."""
    repo_url: str = Field(
        ..., description="Repository URL (https or ssh)",
        min_length=1, max_length=500,
    )
    branch: str = Field(default="main", max_length=200)
    commit_sha: str | None = Field(default=None, description="For idempotency check")
    target: TargetVersion | None = Field(default=None, description="Migration target")
    scan_type: str = Field(default="diff", description="full | diff")
    scan_config: ScanConfig | None = Field(default=None)
    pr_info: PRInfo | None = Field(default=None, description="PR context")
    callback_url: str | None = Field(default=None, description="Webhook callback URL")

    @field_validator("repo_url")
    @classmethod
    def validate_repo_url(cls, v: str) -> str:
        from src.utils.repo_url import assert_repo_url_safe
        assert_repo_url_safe(v)
        return v

    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, v: str) -> str:
        if v not in ("full", "diff"):
            raise ValueError("scan_type must be 'full' or 'diff'")
        return v

    @field_validator("callback_url")
    @classmethod
    def validate_callback_url(cls, v: str | None) -> str | None:
        if v and not v.startswith("https://"):
            raise ValueError("callback_url must be https://")
        return v


class AppealRequest(BaseModel):
    """POST /api/v1/tasks/{task_id}/appeal request body."""
    finding_id: str = Field(..., description="CVE ID or rule ID to appeal", min_length=1)
    reason: str = Field(
        ...,
        description="Justification for the exemption",
        min_length=10,
        max_length=2000,
    )
    evidence_url: str | None = Field(default=None, description="Supporting evidence URL")


class RuleUpdateRequest(BaseModel):
    """PUT /api/v1/rules/{rule_id} request body."""
    enabled: bool | None = Field(default=None, description="Enable/disable the rule")
    pattern: str | None = Field(default=None, description="Updated pattern")
    reason: str | None = Field(default=None, description="Updated justification")
