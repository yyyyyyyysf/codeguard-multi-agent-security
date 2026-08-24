"""Tests for the Redis Pub/Sub EventBus."""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.engine.event_bus import EventBus


class TestEventBusPublish:
    @pytest.mark.asyncio
    async def test_publishes_to_redis(self):
        redis = MagicMock()
        redis.publish = AsyncMock(return_value=1)
        bus = EventBus(redis)

        ok = await bus.publish(
            "code_metadata.ready",
            task_id="t1",
            scan_id="s1",
            payload={"language": "python"},
        )

        assert ok is True
        redis.publish.assert_awaited_once()
        channel, raw = redis.publish.await_args.args
        assert channel == "code_metadata.ready"
        event = json.loads(raw)
        assert event["task_id"] == "t1"
        assert event["scan_id"] == "s1"
        assert event["payload"]["language"] == "python"

    @pytest.mark.asyncio
    async def test_redis_failure_falls_back_to_inprocess(self):
        redis = MagicMock()
        redis.publish = AsyncMock(side_effect=RuntimeError("redis down"))
        bus = EventBus(redis)
        received = []
        bus.subscribe("security.complete", received.append)

        ok = await bus.publish("security.complete", task_id="t1")

        assert ok is True
        assert len(received) == 1
        assert received[0]["event_type"] == "security.complete"

    @pytest.mark.asyncio
    async def test_unsubscribe(self):
        bus = EventBus(None)
        calls = []
        bus.subscribe("a", calls.append)
        bus.unsubscribe("a", calls.append)
        await bus.publish("a", task_id="x")
        assert calls == []
