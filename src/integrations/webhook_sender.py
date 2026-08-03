"""Generic outbound webhook sender with HMAC signing and retry.

Sends structured callback events to user-configured URLs.
Integrates with internal event bus — security.complete,
migration.complete, analysis.complete.

Features:
- HMAC-SHA256 signing for receiver verification.
- Exponential backoff retry (1s/3s/10s/30s/60s, max 5 attempts).
- 5s request timeout to avoid blocking Celery workers.
- Failure logging with full payload for manual retry.

MVP: Core signing + retry. v0.2: Feishu/DingTalk/Jira adapters.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

import httpx

from src.core.constants import (
    WEBHOOK_CALLBACK_SIGNATURE_HEADER,
    WEBHOOK_CALLBACK_TIMEOUT,
    WEBHOOK_MAX_RETRIES,
    WEBHOOK_RETRY_BACKOFF,
)
from src.utils.hashing import compute_hmac_sha256
from src.utils.logging import get_logger

logger = get_logger(__name__)


class WebhookSender:
    """Outbound webhook sender with signing and retry.

    Usage:
        sender = WebhookSender(pre_shared_key="my-secret")
        ok = await sender.send_event(
            callback_url="https://hooks.example.com/codeguard",
            event="security.complete",
            task_id="task-001",
            scan_id="scan-001",
            payload={"blocking_count": 3},
        )
    """

    def __init__(self, pre_shared_key: str | None = None) -> None:
        self._key = pre_shared_key or os.getenv("WEBHOOK_CALLBACK_PRE_SHARED_KEY", "")
        self._timeout = WEBHOOK_CALLBACK_TIMEOUT

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def send_event(
        self,
        callback_url: str,
        event: str,
        *,
        task_id: str = "",
        scan_id: str = "",
        repo: str = "",
        pr_number: int | None = None,
        payload: dict[str, Any] | None = None,
        report_url: str = "",
    ) -> bool:
        """Send a structured event to a callback URL.

        Args:
            callback_url: Target webhook URL.
            event: Event type (security.complete, migration.complete, analysis.complete).
            task_id: Associated task ID.
            scan_id: Associated scan ID.
            repo: Repository name.
            pr_number: PR number if applicable.
            payload: Event-specific data.
            report_url: Link to full report.

        Returns:
            True if the callback succeeded (2xx response).
            False after all retries exhausted.
        """
        body = self._build_payload(
            event=event,
            task_id=task_id,
            scan_id=scan_id,
            repo=repo,
            pr_number=pr_number,
            payload=payload or {},
            report_url=report_url,
        )
        body_json = json.dumps(body, default=str, ensure_ascii=False)

        return await self._send_with_retry(callback_url, body_json)

    async def send_security_complete(
        self, callback_url: str, **kwargs: Any
    ) -> bool:
        """Convenience: send security.complete event."""
        return await self.send_event(callback_url, "security.complete", **kwargs)

    async def send_migration_complete(
        self, callback_url: str, **kwargs: Any
    ) -> bool:
        """Convenience: send migration.complete event."""
        return await self.send_event(callback_url, "migration.complete", **kwargs)

    async def send_analysis_complete(
        self, callback_url: str, **kwargs: Any
    ) -> bool:
        """Convenience: send analysis.complete event."""
        return await self.send_event(callback_url, "analysis.complete", **kwargs)

    # ------------------------------------------------------------------
    # Retry logic
    # ------------------------------------------------------------------

    async def _send_with_retry(self, callback_url: str, body: str) -> bool:
        """Send with exponential backoff retry.

        Returns True on first 2xx response, False after max retries.
        """
        last_error = ""

        for attempt in range(WEBHOOK_MAX_RETRIES):
            try:
                ok, error = await self._send_once(callback_url, body)
                if ok:
                    logger.info("webhook_callback_success", url=callback_url[:80], attempt=attempt + 1)
                    return True
                last_error = error
            except Exception as e:
                last_error = str(e)[:200]

            if attempt < WEBHOOK_MAX_RETRIES - 1:
                delay = WEBHOOK_RETRY_BACKOFF[min(attempt, len(WEBHOOK_RETRY_BACKOFF) - 1)]
                logger.warning("webhook_retry", attempt=attempt + 1, delay=delay, error=last_error)
                time.sleep(delay)

        logger.error(
            "webhook_callback_exhausted",
            url=callback_url[:80],
            attempts=WEBHOOK_MAX_RETRIES,
            last_error=last_error,
        )
        return False

    async def _send_once(self, url: str, body: str) -> tuple[bool, str]:
        """Send one HTTP request. Returns (ok, error_message)."""
        headers: dict[str, str] = {
            "Content-Type": "application/json",
        }
        if self._key:
            sig = compute_hmac_sha256(body, self._key)
            headers[WEBHOOK_CALLBACK_SIGNATURE_HEADER] = f"sha256={sig}"

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(self._timeout)) as client:
                response = await client.post(url, content=body, headers=headers)

                if 200 <= response.status_code < 300:
                    return True, ""
                return False, f"HTTP {response.status_code}: {response.text[:200]}"

        except httpx.TimeoutException:
            return False, f"Timeout after {self._timeout}s"
        except httpx.RequestError as e:
            return False, str(e)[:200]

    # ------------------------------------------------------------------
    # Payload building
    # ------------------------------------------------------------------

    @staticmethod
    def _build_payload(
        event: str,
        task_id: str,
        scan_id: str,
        repo: str,
        pr_number: int | None,
        payload: dict[str, Any],
        report_url: str,
    ) -> dict[str, Any]:
        """Build the standardized callback payload."""
        return {
            "event": event,
            "task_id": task_id,
            "scan_id": scan_id,
            "repo": repo,
            "pr_number": pr_number,
            "timestamp": time.time(),
            "data": payload,
            "report_url": report_url,
        }
