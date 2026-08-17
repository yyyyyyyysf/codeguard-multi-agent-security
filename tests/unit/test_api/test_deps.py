"""Tests for dependency injection and auth."""

import sys
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient


def _make_mock_celery_module():
    """Return a module that mimics src.tasks.analysis without hitting Celery."""
    mock_task = MagicMock()
    mock_task.apply_async.return_value = MagicMock(id="mock-id")
    mod = MagicMock()
    mod.analysis_main_task = mock_task
    return mod


class TestAPIDeps:
    @pytest.fixture
    def client(self):
        with patch.dict(
            sys.modules,
            {"src.tasks.analysis": _make_mock_celery_module()},
        ):
            from src.api.app import create_app
            app = create_app()
            app.state.redis = None
            with TestClient(app) as c:
                yield c

    def test_health_check_no_auth(self, client):
        """Health check works without API key."""
        resp = client.get("/health")
        assert resp.status_code == 200

    @patch.dict("os.environ", {"CODEGUARD_API_KEY": "secret-key-123"})
    def test_analyze_no_api_key_dev_mode(self, client):
        """In dev mode (no API key configured), requests are rejected."""
        resp = client.post(
            "/api/v1/analyze",
            json={"repo_url": "https://github.com/user/repo"},
        )
        assert resp.status_code == 401

    @patch.dict("os.environ", {"CODEGUARD_API_KEY": "secret-key-123"})
    def test_analyze_with_valid_api_key(self, client):
        resp = client.post(
            "/api/v1/analyze",
            json={"repo_url": "https://github.com/user/repo"},
            headers={"X-API-Key": "secret-key-123"},
        )
        assert resp.status_code == 202

    @patch.dict("os.environ", {"CODEGUARD_API_KEY": "secret-key-123"})
    def test_analyze_with_invalid_api_key(self, client):
        resp = client.post(
            "/api/v1/analyze",
            json={"repo_url": "https://github.com/user/repo"},
            headers={"X-API-Key": "wrong-key"},
        )
        assert resp.status_code == 401

    @patch.dict("os.environ", {"CODEGUARD_API_KEY": "secret-key-123"})
    def test_analyze_missing_api_key(self, client):
        resp = client.post(
            "/api/v1/analyze",
            json={"repo_url": "https://github.com/user/repo"},
        )
        assert resp.status_code == 401
