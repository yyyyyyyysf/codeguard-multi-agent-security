"""Tests for API routers (analyze, appeal, rules, health)."""

import sys
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Create a test client with mocked dependencies (no Celery involved).

    Requires CODEGUARD_API_KEY to be set (secure-by-default policy).
    """
    with patch.dict("os.environ", {"CODEGUARD_API_KEY": "test-api-key"}):
        from src.api.app import create_app
        app = create_app()
        app.state.redis = None
        with TestClient(app) as c:
            c.headers["X-API-Key"] = "test-api-key"
            yield c


@pytest.fixture
def client_with_celery_mock():
    """Test client where the Celery task import inside the handler is mocked.

    Without this, ``from src.tasks.analysis import analysis_main_task``
    inside the handler triggers the Celery constructor in celery_app.py,
    which tries to connect to Redis and blocks for minutes.
    """
    mock_task = MagicMock()
    mock_result = MagicMock(id="celery-mock-id")
    mock_task.apply_async.return_value = mock_result

    # Set CODEGUARD_API_KEY so verify_api_key passes.
    # The patch.dict must be active before create_app() runs the lifespan handler
    # and before requests are dispatched.
    with patch.dict("os.environ", {"CODEGUARD_API_KEY": "test-api-key"}):
        with patch.dict(sys.modules, {"src.tasks.analysis": MagicMock(
            analysis_main_task=mock_task,
        )}):
            from src.api.app import create_app
            app = create_app()
            app.state.redis = None
            with TestClient(app) as c:
                # Prepend X-API-Key header to every request
                c.headers["X-API-Key"] = "test-api-key"
                yield c


class TestAnalyzeEndpoint:
    def test_submit_valid_request(self, client_with_celery_mock):
        resp = client_with_celery_mock.post(
            "/api/v1/analyze",
            json={"repo_url": "https://github.com/user/repo"},
        )
        assert resp.status_code == 202
        data = resp.json()
        assert "task_id" in data
        assert data["status"] == "pending"

    def test_submit_full_request(self, client_with_celery_mock):
        resp = client_with_celery_mock.post(
            "/api/v1/analyze",
            json={
                "repo_url": "https://github.com/user/repo",
                "scan_type": "full",
                "target": {"framework": "fastapi", "from_version": "0.100.0", "to_version": "0.110.0"},
                "pr_info": {"pr_number": 42},
            },
        )
        assert resp.status_code == 202

    def test_reject_invalid_repo_url(self, client):
        resp = client.post(
            "/api/v1/analyze",
            json={"repo_url": "not-a-url"},
        )
        assert resp.status_code == 400 or resp.status_code == 422

    def test_reject_missing_repo_url(self, client):
        resp = client.post("/api/v1/analyze", json={})
        assert resp.status_code in (400, 422)

    def test_get_task_not_found(self, client_with_celery_mock):
        resp = client_with_celery_mock.get("/api/v1/tasks/nonexistent-id")
        assert resp.status_code in (200, 404)


class TestAppealEndpoint:
    def test_submit_appeal(self, client):
        resp = client.post(
            "/api/v1/tasks/fake-task-id/appeal",
            json={
                "finding_id": "CVE-2024-0001",
                "reason": "This vulnerability requires local access, not applicable to cloud deployment",
                "evidence_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "appeal_id" in data
        assert data["status"] == "pending_review"


class TestRulesEndpoint:
    def test_list_rules(self, client):
        resp = client.get("/api/v1/rules")
        assert resp.status_code == 200
        data = resp.json()
        assert "rules" in data

    def test_update_rule_not_implemented(self, client):
        resp = client.put(
            "/api/v1/rules/rule-1",
            json={"enabled": False},
        )
        assert resp.status_code == 501


class TestHealthEndpoint:
    def test_health_check(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "version" in data
        assert "dependencies" in data
