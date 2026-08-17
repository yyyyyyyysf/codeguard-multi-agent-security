"""Tests for Celery task helpers — state, idempotency, degradation.

Tests the sync helper functions that underpin Celery tasks.
Celery decorators are framework plumbing tested via integration.
"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest


class TestRedisHelpers:
    """Test Redis-backed state management through the module-level _redis_module."""

    @pytest.fixture(autouse=True)
    def mock_redis_module(self):
        """Replace _redis_module with a MagicMock for each test."""
        mock_redis = MagicMock()
        mock_redis.from_url.return_value = mock_redis
        with patch("src.tasks.analysis._redis_module", mock_redis):
            yield mock_redis

    def test_set_status(self, mock_redis_module):
        from src.tasks.analysis import _sync_set_status
        _sync_set_status("task-abc", "running")
        mock_redis_module.setex.assert_called_once()
        args = mock_redis_module.setex.call_args[0]
        assert "task-abc" in args[0]

    def test_cache_json(self, mock_redis_module):
        from src.tasks.analysis import _sync_cache_json
        _sync_cache_json("key-1", {"status": "ok"}, ttl=7200)
        mock_redis_module.setex.assert_called_once()

    def test_load_json(self, mock_redis_module):
        mock_redis_module.get.return_value = json.dumps({"val": 42})
        from src.tasks.analysis import _sync_load_json
        result = _sync_load_json("k")
        assert result == {"val": 42}

    def test_load_json_missing(self, mock_redis_module):
        mock_redis_module.get.return_value = None
        from src.tasks.analysis import _sync_load_json
        assert _sync_load_json("missing") is None

    def test_check_idempotent_new(self, mock_redis_module):
        mock_redis_module.exists.return_value = False
        from src.tasks.analysis import _sync_check_idempotent
        assert not _sync_check_idempotent("fresh")

    def test_check_idempotent_duplicate(self, mock_redis_module):
        mock_redis_module.exists.return_value = True
        from src.tasks.analysis import _sync_check_idempotent
        assert _sync_check_idempotent("done")


class TestRedisFailGracefully:
    """Redis failures never crash."""

    @pytest.fixture(autouse=True)
    def mock_redis_down(self):
        mock_r = MagicMock()
        mock_r.from_url.side_effect = Exception("Connection refused")
        with patch("src.tasks.analysis._redis_module", mock_r):
            yield

    def test_set_status_no_crash(self):
        from src.tasks.analysis import _sync_set_status
        _sync_set_status("t1", "running")  # Should not raise

    def test_load_json_no_crash(self):
        from src.tasks.analysis import _sync_load_json
        assert _sync_load_json("any") is None

    def test_check_idempotent_no_crash(self):
        from src.tasks.analysis import _sync_check_idempotent
        assert not _sync_check_idempotent("any")


class TestAsyncBridge:
    """Test _sync_run_async coroutine bridge."""

    @pytest.mark.asyncio
    async def test_returns_result(self):
        from src.tasks.analysis import _sync_run_async
        async def double(x): return x * 2
        assert _sync_run_async(double(21)) == 42

    def test_from_sync_context(self):
        from src.tasks.analysis import _sync_run_async
        async def greet(): return "hi"
        assert _sync_run_async(greet()) == "hi"


class TestTaskLogic:
    """Task functions with mocked lower-level deps."""

    @patch.dict(os.environ, {"REDIS_URL": "redis://localhost:6379/0"})
    def test_migration_skips_without_target(self):
        from src.tasks.analysis import migration_task
        result = migration_task(task_id="t1", target=None)
        assert result["status"] == "migration_skipped"

    @patch.dict(os.environ, {"REDIS_URL": "redis://localhost:6379/0"})
    def test_security_task_handles_empty_input(self):
        from src.tasks.analysis import security_chain_task
        result = security_chain_task(task_id="t1", code_metadata={})
        assert "status" in result

    @patch.dict(os.environ, {"REDIS_URL": "redis://localhost:6379/0"})
    def test_report_task_handles_missing_data(self):
        from src.tasks.analysis import report_aggregation_task
        result = report_aggregation_task(task_id="t1")
        assert "status" in result
