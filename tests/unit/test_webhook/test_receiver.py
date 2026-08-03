"""Tests for webhook receiver — signature verification, event dispatch."""

import hashlib
import hmac
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from src.api.app import create_app
    app = create_app()
    # Mount webhook router
    from src.webhook.receiver import router as webhook_router
    app.include_router(webhook_router)
    app.state.redis = None
    with TestClient(app) as c:
        yield c


class TestWebhookSignature:
    def test_ping_returns_pong(self, client):
        resp = client.post(
            "/webhook/github",
            content=b'{"zen":"test"}',
            headers={
                "X-GitHub-Event": "ping",
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
        resp = client.post(
            "/webhook/github",
            content=body,
            headers={"X-GitHub-Event": "pull_request"},
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
        resp = client.post(
            "/webhook/github",
            content=body,
            headers={"X-GitHub-Event": "push"},
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
        resp = client.post(
            "/webhook/github",
            content=body,
            headers={"X-GitHub-Event": "push"},
        )
        assert resp.status_code == 200


class TestWebhookSignatureVerification:
    """Tests for HMAC signature verification."""

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
