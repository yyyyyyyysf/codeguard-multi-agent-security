"""Global constants for CodeGuard.

All magic numbers, default values, and configuration keys
that are used across multiple modules live here.
Module-specific constants stay in their respective packages.
"""

from __future__ import annotations

from typing import Final

# ============================================================
# API / Server
# ============================================================

DEFAULT_HOST: Final[str] = "0.0.0.0"
DEFAULT_PORT: Final[int] = 8000
API_VERSION: Final[str] = "v1"
API_PREFIX: Final[str] = f"/api/{API_VERSION}"

# ============================================================
# Redis Keys
# ============================================================

REDIS_PREFIX: Final[str] = "codeguard"

# Task state
TASK_STATUS_KEY: Final[str] = f"{REDIS_PREFIX}:task:{{task_id}}:status"
TASK_PROGRESS_KEY: Final[str] = f"{REDIS_PREFIX}:task:{{task_id}}:progress"
TASK_RESULT_KEY: Final[str] = f"{REDIS_PREFIX}:task:{{task_id}}:result"
TASK_RESULT_TTL: Final[int] = 3600  # 1 hour

# Idempotency
TASK_DEDUP_KEY: Final[str] = f"{REDIS_PREFIX}:task:dedup:{{repo_hash}}:{{pr_number}}:{{commit_sha}}"
TASK_DEDUP_TTL: Final[int] = 259200  # 72 hours

# Result reuse
SCAN_CACHE_KEY: Final[str] = f"{REDIS_PREFIX}:cache:scan:{{commit_sha}}:security"
SCAN_CACHE_TTL: Final[int] = 604800  # 7 days

# Rule config
RULE_CONFIG_CACHE_KEY: Final[str] = f"{REDIS_PREFIX}:config:exemption:hash"
RULE_CONFIG_CACHE_TTL: Final[int] = 3600  # 1 hour

# Rate limiting (MVP reserved)
RATE_LIMIT_KEY: Final[str] = f"{REDIS_PREFIX}:rate_limit:{{identifier}}:{{minute}}"
RATE_LIMIT_TTL: Final[int] = 60  # 1 minute

# Pub/Sub channels
CHANNEL_CODE_METADATA_READY: Final[str] = "code_metadata.ready"
CHANNEL_SECURITY_COMPLETE: Final[str] = "security.complete"
CHANNEL_MIGRATION_COMPLETE: Final[str] = "migration.complete"
CHANNEL_ANALYSIS_COMPLETE: Final[str] = "analysis.complete"

# ============================================================
# Celery
# ============================================================

CELERY_TASK_DEFAULT_QUEUE: Final[str] = "codeguard"
CELERY_TASK_MAX_RETRIES: Final[int] = 3
CELERY_TASK_RETRY_DELAY: Final[int] = 5  # seconds
CELERY_TASK_SOFT_TIME_LIMIT: Final[int] = 300  # 5 minutes
CELERY_TASK_TIME_LIMIT: Final[int] = 360  # 6 minutes

# ============================================================
# Security / Blocking
# ============================================================

DEFAULT_BLOCK_SEVERITY: Final[str] = "high"  # "high" | "critical"
HUMAN_LOOP_TIMEOUT_HOURS: Final[int] = 24
CRITICAL_CVSS_THRESHOLD: Final[float] = 9.0
HIGH_CVSS_THRESHOLD: Final[float] = 7.0

# Security SLA
SECURITY_PATH_LATENCY_MS: Final[int] = 3000   # 3 seconds
TOTAL_ANALYSIS_LATENCY_MS: Final[int] = 5000  # 5 seconds

# ============================================================
# CVE Cache
# ============================================================

CVE_HOT_CACHE_SIZE: Final[int] = 200          # Top N popular packages in Redis
CVE_HOT_CACHE_TTL: Final[int] = 3600          # 1 hour
CVE_LOCAL_SYNC_INTERVAL_HOURS: Final[int] = 24
CVE_STALENESS_WARNING_HOURS: Final[int] = 24  # Force OSV re-fetch if cache older than this

# ============================================================
# External API Timeouts (seconds)
# ============================================================

OSV_API_TIMEOUT: Final[int] = 10
GITHUB_API_TIMEOUT: Final[int] = 10
LLM_API_TIMEOUT: Final[int] = 30
WEBHOOK_RECEIVE_TIMEOUT: Final[int] = 5
WEBHOOK_CALLBACK_TIMEOUT: Final[int] = 5

# ============================================================
# Sandbox
# ============================================================

SANDBOX_TIMEOUT_SECONDS: Final[int] = 30
SANDBOX_MAX_MEMORY_MB: Final[int] = 512

# ============================================================
# Git
# ============================================================

GIT_CLONE_TIMEOUT: Final[int] = 120
GIT_CLONE_DEPTH: Final[int] = 50  # Shallow clone for performance
DEFAULT_BRANCH: Final[str] = "main"

# ============================================================
# Webhook
# ============================================================

WEBHOOK_SIGNATURE_HEADER: Final[str] = "X-Hub-Signature-256"
WEBHOOK_CALLBACK_SIGNATURE_HEADER: Final[str] = "X-CodeGuard-Signature-256"
WEBHOOK_MAX_RETRIES: Final[int] = 5
WEBHOOK_RETRY_BACKOFF: Final[list[int]] = [1, 3, 10, 30, 60]  # seconds

# ============================================================
# Report
# ============================================================

REPORT_FORMAT_JSON: Final[str] = "json"
REPORT_FORMAT_HTML: Final[str] = "html"
PR_COMMENT_MAX_LENGTH: Final[int] = 65536  # GitHub's limit

# ============================================================
# File size limits
# ============================================================

MAX_FILE_SIZE_BYTES: Final[int] = 1_048_576  # 1 MB, skip larger files
SKIP_BINARY_EXTENSIONS: Final[set[str]] = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".mp3", ".mp4", ".avi", ".mov", ".wmv",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".pyc", ".pyo", ".so", ".dll", ".exe", ".bin",
    ".db", ".sqlite", ".sqlite3",
}
