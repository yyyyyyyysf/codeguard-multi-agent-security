"""Unified exception hierarchy for CodeGuard.

All application-level errors MUST use these classes.
Do NOT raise raw Exception or ValueError in business logic.

Usage:
    raise TaskNotFoundError(task_id)
    raise OSVApiUnavailableError("OSV API returned 502", retryable=True)

Architecture constraint:
    Agent layer MUST NOT raise external-service errors directly.
    Agent raises domain errors (e.g., ScanPartialFailedError),
    and the orchestration layer maps them to external errors if needed.
"""

from __future__ import annotations

from typing import Any


class CodeGuardError(Exception):
    """Base exception for all CodeGuard-specific errors.

    Attributes:
        code: Machine-readable error code (e.g., "TASK-001").
        message: Human-readable description.
        http_status: HTTP status code for API responses.
        retryable: Whether the caller can safely retry.
        detail: Optional additional context dict.
    """

    code: str = "INTERNAL-000"
    http_status: int = 500
    retryable: bool = False

    def __init__(
        self,
        message: str = "",
        *,
        retryable: bool | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        self.message = message or self.__class__.__doc__ or ""
        if retryable is not None:
            self.retryable = retryable
        self.detail = detail or {}
        super().__init__(self.message)

    def to_dict(self) -> dict[str, Any]:
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "retryable": self.retryable,
                "detail": self.detail,
            }
        }


# ============================================================
# Task-layer errors (TASK-xxx)
# ============================================================

class TaskNotFoundError(CodeGuardError):
    """The requested task does not exist or has expired."""
    code = "TASK-001"
    http_status = 404


class TaskDuplicateError(CodeGuardError):
    """Idempotency guard: this commit has already been scanned.
    Not a real error - the existing task_id is returned.
    """
    code = "TASK-002"
    http_status = 409


class TaskInvalidParamError(CodeGuardError):
    """Invalid or missing parameter in the task submission request."""
    code = "TASK-003"
    http_status = 400


# ============================================================
# Analysis-layer errors (ANALYSIS-xxx)
# ============================================================

class RepoCloneFailedError(CodeGuardError):
    """Failed to clone or pull the target repository."""
    code = "ANALYSIS-001"
    http_status = 502
    retryable = True


class ASTParseFailedError(CodeGuardError):
    """Tree-sitter AST parsing failed for one or more files."""
    code = "ANALYSIS-002"
    http_status = 500


class ScanPartialFailedError(CodeGuardError):
    """Analysis completed but some sub-scans failed and were degraded.
    HTTP 200 because the caller gets partial results with degraded markers.
    """
    code = "ANALYSIS-003"
    http_status = 200


# ============================================================
# External-service errors (EXT-xxx)
# ============================================================

class OSVApiUnavailableError(CodeGuardError):
    """OSV API is unreachable or returned a server error.
    Triggers degradation: fall back to local cache.
    """
    code = "EXT-001"
    http_status = 502
    retryable = True


class GitHubAPIRateLimitError(CodeGuardError):
    """GitHub API rate limit exceeded. Wait and retry."""
    code = "EXT-002"
    http_status = 429
    retryable = True


class LLMTimeoutError(CodeGuardError):
    """LLM inference timed out.
    Triggers degradation: fall back to rule-only migration analysis.
    """
    code = "EXT-003"
    http_status = 504
    retryable = True


# ============================================================
# Security errors (SEC-xxx)
# ============================================================

class AppealExpiredError(CodeGuardError):
    """The exemption appeal has expired (human-loop timeout)."""
    code = "SEC-001"
    http_status = 410


class RuleConflictError(CodeGuardError):
    """The exemption rule conflicts with an existing rule."""
    code = "SEC-002"
    http_status = 409


class UnauthorizedActionError(CodeGuardError):
    """The requested action requires authorization that was not provided."""
    code = "SEC-003"
    http_status = 403
