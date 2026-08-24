"""Tests for the metrics collector and agent instrumentation."""

import pytest

from src.engine.base_agent import BaseAgent
from src.monitoring.metrics import MetricsCollector, get_metrics


class TestMetricsCollector:
    def test_inc_and_get_counter(self):
        m = MetricsCollector()
        m.inc("scans_total", tags={"type": "full"})
        m.inc("scans_total", tags={"type": "full"})
        assert m.get_counter("scans_total", {"type": "full"}) == 2

    def test_gauge(self):
        m = MetricsCollector()
        m.set_gauge("queue_depth", 5)
        assert m.get_gauge("queue_depth") == 5

    def test_histogram_stats(self):
        m = MetricsCollector()
        m.observe("duration_ms", 100)
        m.observe("duration_ms", 200)
        stats = m.get_histogram_stats("duration_ms")
        assert stats["count"] == 2
        assert stats["avg"] == 150


class _FakeAgent(BaseAgent):
    agent_id = "fake_agent"

    async def run(self, **kwargs):
        return {"ok": True}

    async def degraded_run(self, original_error, **kwargs):
        return {}


class TestAgentMetrics:
    @pytest.mark.asyncio
    async def test_successful_run_records_metrics(self):
        metrics = get_metrics()
        before = metrics.snapshot()

        agent = _FakeAgent()
        result = await agent.execute()

        assert result["success"] is True
        after = metrics.snapshot()
        key = "agent_run_total[agent=fake_agent]"
        assert after["counters"].get(key, 0) == before["counters"].get(key, 0) + 1
        dur_key = "agent_duration_ms[agent=fake_agent]"
        assert after["histogram_stats"].get(dur_key, {}).get("count", 0) == (
            before["histogram_stats"].get(dur_key, {}).get("count", 0) + 1
        )

    @pytest.mark.asyncio
    async def test_failed_agent_records_failure(self):
        metrics = get_metrics()
        before = metrics.snapshot()

        class _BrokenAgent(BaseAgent):
            agent_id = "broken_agent"

            async def run(self, **kwargs):
                raise RuntimeError("boom")

            async def degraded_run(self, original_error, **kwargs):
                raise RuntimeError("no fallback either")

        result = await _BrokenAgent().execute()

        assert result["success"] is False
        after = metrics.snapshot()
        key = "agent_failure_total[agent=broken_agent]"
        assert after["counters"].get(key, 0) == before["counters"].get(key, 0) + 1
