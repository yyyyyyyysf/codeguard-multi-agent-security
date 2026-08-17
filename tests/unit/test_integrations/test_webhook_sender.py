"""Tests for WebhookSender — signing, retry, event types."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.integrations.webhook_sender import WebhookSender
from src.utils.hashing import compute_hmac_sha256, verify_signature


class TestWebhookSenderPayload:
    def test_build_payload_structure(self):
        payload = WebhookSender._build_payload(
            event="security.complete",
            task_id="t1",
            scan_id="s1",
            repo="owner/repo",
            pr_number=42,
            payload={"blocking_count": 3},
            report_url="https://x.com/r",
        )
        assert payload["event"] == "security.complete"
        assert payload["task_id"] == "t1"
        assert payload["scan_id"] == "s1"
        assert payload["repo"] == "owner/repo"
        assert payload["pr_number"] == 42
        assert payload["data"]["blocking_count"] == 3
        assert payload["report_url"] == "https://x.com/r"
        assert "timestamp" in payload


class TestWebhookSigning:
    def test_signature_verification_roundtrip(self):
        """Generated signature can be verified by receiver."""
        key = "pre-shared-secret"
        body = '{"event":"security.complete"}'
        sig = compute_hmac_sha256(body, key)
        assert verify_signature(body, key, sig)

    def test_different_key_fails(self):
        sig = compute_hmac_sha256("body", "key-a")
        assert not verify_signature("body", "key-b", sig)


class TestWebhookSenderMockHTTP:
    @pytest.fixture
    def sender(self):
        return WebhookSender(pre_shared_key="test-key-123")

    @pytest.mark.asyncio
    async def test_send_event_success(self, sender):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            ok = await sender.send_event(
                "https://hooks.example.com/cg",
                "security.complete",
                task_id="t1",
                scan_id="s1",
                repo="o/r",
                payload={"blocking": True},
            )
            assert ok

    @pytest.mark.asyncio
    async def test_send_event_failure_with_retry(self, sender):
        """Non-2xx response triggers retry, eventually returns False."""
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post = AsyncMock(return_value=mock_resp)

        # Override retry to be fast
        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch.object(sender, "_send_with_retry", wraps=sender._send_with_retry), \
             patch("time.sleep", return_value=None):  # Speed up retries
            # Override backoff to be instant
            with patch("src.integrations.webhook_sender.WEBHOOK_RETRY_BACKOFF", [0, 0, 0, 0, 0]):
                ok = await sender.send_event(
                    "https://hooks.example.com/cg",
                    "analysis.complete",
                    task_id="t1",
                    scan_id="s1",
                )
                assert not ok

    @pytest.mark.asyncio
    async def test_send_event_timeout(self, sender):
        import httpx
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("time.sleep", return_value=None), \
             patch("src.integrations.webhook_sender.WEBHOOK_RETRY_BACKOFF", [0, 0, 0, 0, 0]):
            ok = await sender.send_event("https://x.com/hook", "security.complete")
            assert not ok

    @pytest.mark.asyncio
    async def test_signature_header_present(self, sender):
        """Verify the signature header is set on outbound requests."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            await sender.send_event("https://x.com/hook", "security.complete", scan_id="s1")

        call_kwargs = mock_client.post.call_args
        headers = call_kwargs[1]["headers"]
        assert "X-CodeGuard-Signature-256" in headers
        assert headers["X-CodeGuard-Signature-256"].startswith("sha256=")

    @pytest.mark.asyncio
    async def test_convenience_methods(self, sender):
        """send_security_complete etc. delegate correctly."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            ok = await sender.send_migration_complete(
                "https://x.com/hook", task_id="t1", scan_id="s1",
            )
            assert ok

    @pytest.mark.asyncio
    async def test_no_pre_shared_key_still_works(self):
        """Without a key, requests still go out (just no signature)."""
        sender = WebhookSender(pre_shared_key="")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            ok = await sender.send_event("https://x.com/hook", "security.complete")
            assert ok
