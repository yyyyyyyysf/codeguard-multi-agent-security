"""API response schemas (Pydantic v2).

All response models are decoupled from internal models to avoid
leaking internal fields or implementation details.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    """Standard error response body."""
    code: str = Field(..., description="Machine-readable error code")
    message: str = Field(..., description="Human-readable description")
    retryable: bool = Field(default=False)
    detail: dict = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    """Wrapper for error responses."""
    error: ErrorDetail


class AnalyzeResponse(BaseModel):
    """POST /api/v1/analyze response."""
    task_id: str = Field(..., description="Assigned task ID (UUID v4)")
    status: str = Field(default="pending")


class TaskStatusResponse(BaseModel):
    """GET /api/v1/tasks/{task_id} response."""
    task_id: str
    status: str = Field(..., description="pending | running | completed | failed")
    progress: int = Field(default=0, ge=0, le=100)
    current_stage: str = Field(default="", description="Current execution stage")
    created_at: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    security_result: dict | None = None
    migration_result: dict | None = None
    full_report_url: str | None = None


class AppealResponse(BaseModel):
    """POST /api/v1/tasks/{task_id}/appeal response."""
    appeal_id: str
    status: str = "pending_review"
    estimated_hours: int = 24


class RuleItem(BaseModel):
    """Single exemption rule in the list."""
    rule_id: str
    rule_type: str
    pattern: str
    reason: str
    scope: str = "global"
    enabled: bool = True
    created_by: str = ""
    created_at: str = ""


class RuleListResponse(BaseModel):
    """GET /api/v1/rules response."""
    rules: list[RuleItem]
    count: int


class HealthResponse(BaseModel):
    """GET /health response."""
    status: str = "ok"
    version: str = "0.1.0"
    dependencies: dict = Field(default_factory=dict)
