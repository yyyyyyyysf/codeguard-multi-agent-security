"""Redis Pub/Sub event bus for inter-Agent communication.

Publishes structured events on standardized channels.
Agents subscribe to events they care about (decoupled via channels).

Channel naming convention:
    code_metadata.ready       - Preprocessing completed
    security.complete         - Security scan completed
    migration.complete        - Migration assessment completed
    analysis.complete         - Full analysis completed

Each event carries: event_type, task_id, scan_id, timestamp, payload.
"""

from __future__ import annotations

import json
import time
from typing import Any


class EventBus:
    """Redis-backed Pub/Sub event bus.

    Usage:
        bus = EventBus(redis_client)
        await bus.publish("code_metadata.ready", scan_id="abc", payload={...})
        await bus.subscribe("code_metadata.ready", callback=my_handler)
    """

    def __init__(self, redis_client: Any = None) -> None:
        self._redis = redis_client
        self._subscribers: dict[str, list[callable]] = {}

    # ------------------------------------------------------------------
    # Publish
    # ------------------------------------------------------------------

    async def publish(
        self,
        channel: str,
        *,
        task_id: str = "",
        scan_id: str = "",
        payload: dict[str, Any] | None = None,
    ) -> bool:
        """Publish an event to a channel.

        Args:
            channel: Event channel name.
            task_id: Associated task ID.
            scan_id: Associated scan ID.
            payload: Event data.

        Returns:
            True if published (or queued), False if Redis unavailable.
        """
        event = {
            "event_type": channel,
            "task_id": task_id,
            "scan_id": scan_id,
            "timestamp": time.time(),
            "payload": payload or {},
        }
        event_json = json.dumps(event, default=str)

        if self._redis:
            try:
                await self._redis.publish(channel, event_json)
                return True
            except Exception:
                pass  # Fall through to in-process subscribers

        # In-process subscribers (used when Redis is unavailable or in tests)
        if channel in self._subscribers:
            for callback in self._subscribers[channel]:
                try:
                    callback(event)
                except Exception:
                    continue
            return True

        return False

    # ------------------------------------------------------------------
    # Subscribe
    # ------------------------------------------------------------------

    def subscribe(self, channel: str, callback: callable) -> None:
        """Register a callback for a channel.

        In production: also subscribes via Redis async listener.
        In MVP: in-process callback dispatch.

        Args:
            channel: Channel to subscribe to.
            callback: Callable that receives the event dict.
        """
        if channel not in self._subscribers:
            self._subscribers[channel] = []
        self._subscribers[channel].append(callback)

        # If Redis is available, set up async listener
        if self._redis:
            # Note: Full Redis pub/sub listener requires a dedicated
            # connection. For MVP, in-process dispatch is sufficient
            # because all agents run within the same Celery worker.
            pass

    def unsubscribe(self, channel: str, callback: callable) -> None:
        """Remove a callback subscription."""
        if channel in self._subscribers:
            self._subscribers[channel] = [
                cb for cb in self._subscribers[channel] if cb != callback
            ]

    # ------------------------------------------------------------------
    # Convenience methods
    # ------------------------------------------------------------------

    async def publish_code_metadata_ready(
        self, task_id: str, scan_id: str, metadata: dict[str, Any]
    ) -> None:
        """Publish event: preprocessing completed."""
        await self.publish(
            "code_metadata.ready",
            task_id=task_id,
            scan_id=scan_id,
            payload=metadata,
        )

    async def publish_security_complete(
        self, task_id: str, scan_id: str, security_report: dict[str, Any]
    ) -> None:
        """Publish event: security scan completed."""
        await self.publish(
            "security.complete",
            task_id=task_id,
            scan_id=scan_id,
            payload=security_report,
        )

    async def publish_migration_complete(
        self, task_id: str, scan_id: str, migration_report: dict[str, Any]
    ) -> None:
        """Publish event: migration assessment completed."""
        await self.publish(
            "migration.complete",
            task_id=task_id,
            scan_id=scan_id,
            payload=migration_report,
        )

    async def publish_analysis_complete(
        self, task_id: str, scan_id: str, aggregated_report: dict[str, Any]
    ) -> None:
        """Publish event: full analysis completed."""
        await self.publish(
            "analysis.complete",
            task_id=task_id,
            scan_id=scan_id,
            payload=aggregated_report,
        )
