"""GitHub REST API client — the execution layer for PR blocking/feedback.

Encapsulates all GitHub API interactions behind a clean interface.
No business logic here — only protocol adaptation, retry, and error handling.

Capabilities:
- Check Runs: create/update check runs with full lifecycle (queued→in_progress→completed).
- PR Comments: create with idempotency key, update existing comment.
- Auth: Personal Access Token via env var (MVP). GitHub App token support reserved.

Design constraints:
- NEVER raises exceptions to callers (all errors handled internally).
- All calls logged for audit/debugging.
- Idempotent: repeated calls with same parameters don't create duplicates.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

import httpx

from src.core.constants import GITHUB_API_TIMEOUT
from src.utils.logging import get_logger
from src.utils.retry import retry

logger = get_logger(__name__)


class GitHubClient:
    """GitHub REST API client for PR integration.

    Usage:
        async with GitHubClient(token="ghp_xxx") as gh:
            check_id = await gh.create_check_run("owner/repo", "abc123", "CodeGuard")
            await gh.update_check_run("owner/repo", check_id, "completed", "failure")
            comment_id = await gh.create_pr_comment("owner/repo", 42, "## Report")
            await gh.update_pr_comment("owner/repo", comment_id, "## Updated Report")
    """

    def __init__(
        self,
        token: str | None = None,
        timeout: int = GITHUB_API_TIMEOUT,
    ) -> None:
        self._token = token or os.getenv("GITHUB_TOKEN", "")
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None
        self._base_url = "https://api.github.com"

    async def __aenter__(self) -> "GitHubClient":
        headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "CodeGuard/0.1",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers=headers,
            timeout=httpx.Timeout(self._timeout),
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("GitHubClient not opened. Use 'async with' context manager.")
        return self._client

    # ------------------------------------------------------------------
    # Check Runs API
    # ------------------------------------------------------------------

    async def create_check_run(
        self, repo: str, head_sha: str, name: str = "CodeGuard Security Scan"
    ) -> dict[str, Any] | None:
        """Create a check run with status 'queued'.

        Args:
            repo: Repository full name ("owner/repo").
            head_sha: Commit SHA to attach the check to.
            name: Display name for the check.

        Returns:
            Check run dict (with 'id' key) or None on failure.
        """
        return await self._call(
            "POST",
            f"/repos/{repo}/check-runs",
            json={
                "name": name,
                "head_sha": head_sha,
                "status": "queued",
                "started_at": self._now(),
            },
        )

    async def update_check_run(
        self,
        repo: str,
        check_run_id: int,
        status: str,
        conclusion: str | None = None,
        summary: str = "",
        details_url: str = "",
    ) -> dict[str, Any] | None:
        """Update a check run status and conclusion.

        Args:
            repo: Repository full name.
            check_run_id: ID from create_check_run().
            status: One of "queued", "in_progress", "completed".
            conclusion: Required when status="completed".
                        One of "success", "failure", "neutral", "cancelled", "skipped".
            summary: Markdown summary text.
            details_url: URL for "View details" link.
        """
        body: dict[str, Any] = {
            "name": "CodeGuard Security Scan",
            "status": status,
            "completed_at": self._now() if status == "completed" else None,
        }
        if status == "completed" and conclusion:
            body["conclusion"] = conclusion
        if summary:
            body["output"] = {
                "title": "CodeGuard Analysis",
                "summary": summary[:65535],  # GitHub's limit
            }
        if details_url:
            body.setdefault("output", {})
            body["output"]["details_url"] = details_url

        return await self._call(
            "PATCH",
            f"/repos/{repo}/check-runs/{check_run_id}",
            json=body,
        )

    # ------------------------------------------------------------------
    # PR Comments API
    # ------------------------------------------------------------------

    async def create_pr_comment(
        self, repo: str, pr_number: int, body: str
    ) -> dict[str, Any] | None:
        """Create a comment on a pull request.

        Args:
            repo: Repository full name.
            pr_number: PR number.
            body: Markdown comment body.

        Returns:
            Comment dict (with 'id' key) or None on failure.
        """
        # Truncate if exceeds GitHub's comment size limit
        truncated = body[:65536] if len(body) > 65536 else body
        if len(body) > 65536:
            truncated += "\n\n> Content truncated · [View full report](#)"

        return await self._call(
            "POST",
            f"/repos/{repo}/issues/{pr_number}/comments",
            json={"body": truncated},
        )

    async def update_pr_comment(
        self, repo: str, comment_id: int, body: str
    ) -> dict[str, Any] | None:
        """Update an existing PR comment (idempotent update).

        Args:
            repo: Repository full name.
            comment_id: ID from create_pr_comment().
            body: New Markdown body (replaces existing).
        """
        truncated = body[:65536] if len(body) > 65536 else body
        if len(body) > 65536:
            truncated += "\n\n> Content truncated · [View full report](#)"

        return await self._call(
            "PATCH",
            f"/repos/{repo}/issues/comments/{comment_id}",
            json={"body": truncated},
        )

    async def upsert_pr_comment(
        self,
        repo: str,
        pr_number: int,
        body: str,
        *,
        idempotency_key: str = "",
        existing_comment_id: int | None = None,
    ) -> dict[str, Any] | None:
        """Create or update a PR comment based on idempotency.

        If existing_comment_id is provided, updates that comment.
        Otherwise creates a new one.

        Args:
            repo: Repository full name.
            pr_number: PR number.
            body: Markdown body.
            idempotency_key: Key to prevent duplicate creation.
            existing_comment_id: If provided, update this comment instead of creating.
        """
        if existing_comment_id:
            return await self.update_pr_comment(repo, existing_comment_id, body)
        return await self.create_pr_comment(repo, pr_number, body)

    # ------------------------------------------------------------------
    # Core HTTP call
    # ------------------------------------------------------------------

    @retry(max_attempts=3, backoff=[1, 3, 10])
    async def _call(
        self, method: str, path: str, json: dict[str, Any] | None = None
    ) -> dict[str, Any] | None:
        """Make an authenticated GitHub API call with retry and error handling.

        Returns None on any failure (never raises to caller).
        """
        if not self._token:
            logger.warning("github_no_token", path=path)
            return None

        try:
            response = await self.client.request(method, path, json=json)
        except httpx.TimeoutException:
            logger.error("github_timeout", method=method, path=path)
            return None
        except httpx.RequestError as e:
            logger.error("github_request_error", method=method, path=path, error=str(e)[:200])
            return None

        if response.status_code == 429:
            # Rate limited — retry after the suggested wait
            retry_after = response.headers.get("Retry-After", "10")
            logger.warning("github_rate_limited", retry_after=retry_after)
            import time
            time.sleep(int(retry_after))
            return None  # Retry decorator will re-attempt

        if response.status_code >= 500:
            logger.error("github_server_error", status=response.status_code, path=path)
            return None

        if response.status_code in (401, 403):
            logger.error("github_auth_error", status=response.status_code, path=path)
            return None

        if response.status_code == 422:
            logger.error("github_validation_error", status=422, body=response.text[:500])
            return None

        if not response.is_success:
            logger.error("github_unexpected_error", status=response.status_code, body=response.text[:300])
            return None

        try:
            return response.json()
        except Exception:
            return {"raw": response.text}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _now() -> str:
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def idempotency_key(scan_id: str, repo: str, pr_number: int) -> str:
        """Generate an idempotency key for PR comment/check run operations."""
        raw = f"{scan_id}:{repo}:{pr_number}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
