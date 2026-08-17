"""Tests for GitHubClient - Check Runs, PR comments, idempotency, retry."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.integrations.github_client import GitHubClient


class TestGitHubClientHelpers:
    def test_idempotency_key_deterministic(self):
        k1 = GitHubClient.idempotency_key("scan-1", "owner/repo", 42)
        k2 = GitHubClient.idempotency_key("scan-1", "owner/repo", 42)
        assert k1 == k2
        assert len(k1) == 16

    def test_idempotency_key_different_inputs(self):
        k1 = GitHubClient.idempotency_key("scan-1", "a/b", 1)
        k2 = GitHubClient.idempotency_key("scan-2", "a/b", 1)
        assert k1 != k2


class TestGitHubClientNoToken:
    @pytest.mark.asyncio
    async def test_create_check_run_no_token(self):
        async with GitHubClient(token="") as gh:
            result = await gh.create_check_run("o/r", "sha", "test")
        assert result is None

    @pytest.mark.asyncio
    async def test_create_pr_comment_no_token(self):
        async with GitHubClient(token="") as gh:
            result = await gh.create_pr_comment("o/r", 1, "body")
        assert result is None


class TestGitHubClientMockHTTP:
    """Tests with mocked HTTP transport."""

    @staticmethod
    def _make_client():
        """Create a GitHubClient with its internal httpx client mocked."""
        client = GitHubClient(token="ghp_test123")
        mock = AsyncMock()
        client._client = mock
        return client, mock

    @staticmethod
    def _ok_resp(data=None):
        resp = MagicMock()
        resp.status_code = 201
        resp.is_success = True
        resp.json.return_value = data or {"id": 1, "status": "queued"}
        return resp

    @pytest.mark.asyncio
    async def test_create_check_run_success(self):
        gh, mock = self._make_client()
        mock.request = AsyncMock(return_value=self._ok_resp({"id": 12345, "status": "queued"}))
        result = await gh.create_check_run("owner/repo", "abc123")
        assert result["id"] == 12345
        assert result["status"] == "queued"

    @pytest.mark.asyncio
    async def test_create_check_run_correct_params(self):
        gh, mock = self._make_client()
        mock.request = AsyncMock(return_value=self._ok_resp({"id": 1}))
        await gh.create_check_run("o/r", "sha123", "My Check")
        call_args = mock.request.call_args
        assert call_args[0][0] == "POST"
        assert "/check-runs" in call_args[0][1]
        body = call_args[1]["json"]
        assert body["head_sha"] == "sha123"
        assert body["name"] == "My Check"
        assert body["status"] == "queued"

    @pytest.mark.asyncio
    async def test_update_check_run_to_completed(self):
        gh, mock = self._make_client()
        mock.request = AsyncMock(return_value=self._ok_resp(
            {"id": 1, "status": "completed", "conclusion": "failure"}
        ))
        result = await gh.update_check_run("o/r", 1, "completed", "failure", summary="Found 3 issues")
        assert result["conclusion"] == "failure"
        body = mock.request.call_args[1]["json"]
        assert body["status"] == "completed"
        assert body["conclusion"] == "failure"
        assert "output" in body

    @pytest.mark.asyncio
    async def test_create_pr_comment_success(self):
        gh, mock = self._make_client()
        mock.request = AsyncMock(return_value=self._ok_resp({"id": 999, "body": "## Report"}))
        result = await gh.create_pr_comment("o/r", 42, "## Report")
        assert result["id"] == 999

    @pytest.mark.asyncio
    async def test_update_pr_comment(self):
        gh, mock = self._make_client()
        mock.request = AsyncMock(return_value=self._ok_resp({"id": 999}))
        result = await gh.update_pr_comment("o/r", 999, "## Updated")
        assert result["id"] == 999

    @pytest.mark.asyncio
    async def test_upsert_creates_when_no_existing_id(self):
        gh, mock = self._make_client()
        mock.request = AsyncMock(return_value=self._ok_resp({"id": 100}))
        result = await gh.upsert_pr_comment("o/r", 42, "## New")
        assert result["id"] == 100
        assert mock.request.call_args[0][0] == "POST"

    @pytest.mark.asyncio
    async def test_upsert_updates_when_existing_id(self):
        gh, mock = self._make_client()
        mock.request = AsyncMock(return_value=self._ok_resp({"id": 100}))
        result = await gh.upsert_pr_comment("o/r", 42, "## Updated", existing_comment_id=100)
        assert result["id"] == 100
        assert mock.request.call_args[0][0] == "PATCH"

    @pytest.mark.asyncio
    async def test_429_rate_limit_returns_none(self):
        gh, mock = self._make_client()
        resp = MagicMock()
        resp.status_code = 429
        resp.headers = {"Retry-After": "1"}
        mock.request = AsyncMock(return_value=resp)
        result = await gh.create_check_run("o/r", "sha")
        assert result is None

    @pytest.mark.asyncio
    async def test_5xx_returns_none(self):
        gh, mock = self._make_client()
        resp = MagicMock()
        resp.status_code = 502
        mock.request = AsyncMock(return_value=resp)
        result = await gh.create_pr_comment("o/r", 1, "body")
        assert result is None

    @pytest.mark.asyncio
    async def test_401_returns_none(self):
        gh, mock = self._make_client()
        resp = MagicMock()
        resp.status_code = 401
        mock.request = AsyncMock(return_value=resp)
        result = await gh.create_check_run("o/r", "sha")
        assert result is None

    @pytest.mark.asyncio
    async def test_timeout_returns_none(self):
        gh, mock = self._make_client()
        import httpx
        mock.request = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        result = await gh.create_check_run("o/r", "sha")
        assert result is None

    @pytest.mark.asyncio
    async def test_pr_comment_truncates_long_body(self):
        gh, mock = self._make_client()
        mock.request = AsyncMock(return_value=self._ok_resp({"id": 1}))
        long_body = "x" * 70000
        result = await gh.create_pr_comment("o/r", 1, long_body)
        assert result is not None
        body = mock.request.call_args[1]["json"]["body"]
        assert len(body) <= 66000
