"""Webhook event dispatcher.

Abstract base for webhook handlers + event routing.
New platforms (GitLab, Bitbucket, etc.) add new handlers
without modifying the receiver or routing logic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class WebhookHandler(ABC):
    """Abstract base for webhook event handlers."""

    platform: str = "unknown"

    @abstractmethod
    async def handle_event(self, event_type: str, body: dict[str, Any]) -> dict[str, Any]:
        """Process a webhook event.

        Args:
            event_type: Event type string (e.g., "pull_request").
            body: Parsed JSON body.

        Returns:
            Dict with task_id if a scan was triggered, empty dict otherwise.
        """
        ...


def should_scan_pr(event_type: str, action: str, is_draft: bool, scan_drafts: bool = False) -> bool:
    """Determine if a PR event should trigger a scan.

    Args:
        event_type: GitHub event type.
        action: PR action (opened, synchronize, reopened, etc.).
        is_draft: Whether the PR is a draft.
        scan_drafts: Whether draft PRs should be scanned.

    Returns:
        True if a scan should be triggered.
    """
    if event_type == "push":
        return True

    if event_type != "pull_request":
        return False

    if is_draft and not scan_drafts:
        return False

    scannable_actions = {"opened", "synchronize", "reopened"}
    return action in scannable_actions
