"""Tests for webhook receiver — signature verification, event dispatch."""

import hashlib
import hmac
import json
import sys
import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

_TEST_SECRET = "test-secret"


@pytest.fixture
def client():
    """Test client with Celery and Redis fully mocked.

    The webhook handler imports ``src.tasks.analysis`` which constructs
    a Celery app that tries to connect to Redis. Mocking Celery + Redis
    keeps the tests fast and self-contained.
    """
    mock_task = MagicMock()
    mock_result = MagicMock(id="celery-mock-id")
    mock_task.apply_async.return_value = mock_result

    mock_redis = MagicMock()
    mock_redis.get.return_value = None
    mock_redis.setex.return_value = None

    with patch.dict("os.environ", {"GITHUB_WEBHOOK_SECRET": _TEST_SECRET}):
        with patch.dict(sys.modules, {
            "src.tasks.analysis": MagicMock(analysis_main_task=mock_task),
        }):
            from src.api.app import create_app
            app = create_app()
            app.state.redis = mock_redis
            from src.webhook.receiver import router as webhook_router
            app.include_router(webhook_router)
            with TestClient(app) as c:
                yield c


def _sign(body: bytes) -> str:
    return f"sha256={hmac.new(_TEST_SECRET.encode(), body, hashlib.sha256).hexdigest()}"


class TestWebhookSignature:
    def test_ping_returns_pong(self, client):
        body = b'{"zen":"test"}'
        resp = client.post(
            "/webhook/github",
            content=body,
            headers={
                "X-GitHub-Event": "ping",
                "X-Hub-Signature-256": _sign(body),
            },
        )
        assert resp.status_code == 200
        assert resp.json()["message"] == "pong"

    def test_valid_pr_event_accepted(self, client):
        body = json.dumps({
            "action": "opened",
            "pull_request": {
                "number": 42,
                "draft": False,
                "head": {"sha": "abc123", "ref": "feature"},
                "base": {"sha": "def456", "ref": "main"},
            },
            "repository": {
                "full_name": "owner/repo",
                "clone_url": "https://github.com/owner/repo.git",
            },
        })
        body_bytes = body.encode()
        resp = client.post(
            "/webhook/github",
            content=body_bytes,
            headers={
                "X-GitHub-Event": "pull_request",
                "X-Hub-Signature-256": _sign(body_bytes),
            },
        )
        assert resp.status_code == 200
        assert resp.json()["message"] == "accepted"

    def test_push_event_accepted(self, client):
        body = json.dumps({
            "ref": "refs/heads/main",
            "before": "abc111",
            "after": "def222",
            "repository": {
                "full_name": "owner/repo",
                "clone_url": "https://github.com/owner/repo.git",
                "default_branch": "main",
            },
        })
        body_bytes = body.encode()
        resp = client.post(
            "/webhook/github",
            content=body_bytes,
            headers={
                "X-GitHub-Event": "push",
                "X-Hub-Signature-256": _sign(body_bytes),
            },
        )
        assert resp.status_code == 200

    def test_non_branch_push_skipped(self, client):
        """Push to non-default branch logs but still returns 200."""
        body = json.dumps({
            "ref": "refs/heads/feature-x",
            "before": "a1", "after": "b2",
            "repository": {
                "full_name": "o/r",
                "clone_url": "https://github.com/o/r.git",
                "default_branch": "main",
            },
        })
        body_bytes = body.encode()
        resp = client.post(
            "/webhook/github",
            content=body_bytes,
            headers={
                "X-GitHub-Event": "push",
                "X-Hub-Signature-256": _sign(body_bytes),
            },
        )
        assert resp.status_code == 200


class TestWebhookSignatureVerification:
    """Tests for HMAC signature verification."""

    def test_missing_secret_rejected(self, client):
        """Without a configured secret, the endpoint returns 500."""
        with patch.dict("os.environ", {}, clear=True):
            from src.api.app import create_app
            app2 = create_app()
            from src.webhook.receiver import router as wr
            app2.include_router(wr)
            app2.state.redis = MagicMock()
            with TestClient(app2) as c2:
                resp = c2.post(
                    "/webhook/github",
                    content=b'{"test": true}',
                    headers={"X-GitHub-Event": "ping"},
                )
                assert resp.status_code == 503

    @patch.dict("os.environ", {"GITHUB_WEBHOOK_SECRET": "test-secret"})
    def test_missing_signature_rejected(self, client):
        resp = client.post(
            "/webhook/github",
            content=b'{"test": true}',
            headers={"X-GitHub-Event": "pull_request"},
        )
        assert resp.status_code == 401

    @patch.dict("os.environ", {"GITHUB_WEBHOOK_SECRET": "test-secret"})
    def test_invalid_signature_rejected(self, client):
        resp = client.post(
            "/webhook/github",
            content=b'{"test": true}',
            headers={
                "X-GitHub-Event": "pull_request",
                "X-Hub-Signature-256": "sha256=0000000000000000000000000000000000000000000000000000000000000000",
            },
        )
        assert resp.status_code == 401

    @patch.dict("os.environ", {"GITHUB_WEBHOOK_SECRET": "test-secret"})
    def test_valid_signature_accepted(self, client):
        body = b'{"action":"opened","pull_request":{"number":1,"draft":false,"head":{"sha":"abc"},"base":{"sha":"def","ref":"main"}},"repository":{"full_name":"o/r","clone_url":"https://github.com/o/r.git"}}'
        sig = hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()
        resp = client.post(
            "/webhook/github",
            content=body,
            headers={
                "X-GitHub-Event": "pull_request",
                "X-Hub-Signature-256": f"sha256={sig}",
            },
        )
        assert resp.status_code == 200


class TestWebhookRouter:
    def test_should_scan_pr_opened(self):
        from src.webhook.router import should_scan_pr
        assert should_scan_pr("pull_request", "opened", False)

    def test_should_scan_pr_synchronize(self):
        from src.webhook.router import should_scan_pr
        assert should_scan_pr("pull_request", "synchronize", False)

    def test_should_not_scan_draft(self):
        from src.webhook.router import should_scan_pr
        assert not should_scan_pr("pull_request", "opened", True)

    def test_should_not_scan_closed(self):
        from src.webhook.router import should_scan_pr
        assert not should_scan_pr("pull_request", "closed", False)

    def test_should_not_scan_edited(self):
        from src.webhook.router import should_scan_pr
        assert not should_scan_pr("pull_request", "edited", False)

    def test_should_scan_push(self):
        from src.webhook.router import should_scan_pr
        assert should_scan_pr("push", "", False)
