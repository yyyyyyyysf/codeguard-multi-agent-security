"""Observability metrics for CodeGuard.

Tracks key operational indicators across all layers.
MVP: structured logging + in-memory counters (zero external deps).
Production: swap to Prometheus client library with same metric names.
"""

from __future__ import annotations

from src.utils.logging import get_logger

logger = get_logger(__name__)


class MetricsCollector:
    """Thread-safe metrics collector. MVP: in-memory dicts.

    Usage:
        metrics = MetricsCollector()
        metrics.inc("scan_request_total", tags={"scan_type": "full"})
        metrics.observe("scan_duration_seconds", 1.2, tags={"stage": "security"})
        metrics.set_gauge("worker_queue_depth", 5)
    """

    def __init__(self) -> None:
        self._counters: dict[str, int] = {}
        self._gauges: dict[str, float] = {}
        self._histograms: dict[str, list[float]] = {}

    # ------------------------------------------------------------------
    # Counter
    # ------------------------------------------------------------------

    def inc(self, name: str, value: int = 1, tags: dict[str, str] | None = None) -> None:
        key = self._format_key(name, tags)
        self._counters[key] = self._counters.get(key, 0) + value
        logger.debug("metric_counter", metric=name, value=value, **self._safe_tags(tags))

    def get_counter(self, name: str, tags: dict[str, str] | None = None) -> int:
        return self._counters.get(self._format_key(name, tags), 0)

    # ------------------------------------------------------------------
    # Gauge
    # ------------------------------------------------------------------

    def set_gauge(self, name: str, value: float, tags: dict[str, str] | None = None) -> None:
        key = self._format_key(name, tags)
        self._gauges[key] = value

    def get_gauge(self, name: str, tags: dict[str, str] | None = None) -> float:
        return self._gauges.get(self._format_key(name, tags), 0.0)

    # ------------------------------------------------------------------
    # Histogram
    # ------------------------------------------------------------------

    def observe(self, name: str, value: float, tags: dict[str, str] | None = None) -> None:
        key = self._format_key(name, tags)
        if key not in self._histograms:
            self._histograms[key] = []
        self._histograms[key].append(value)
        logger.debug("metric_histogram", metric=name, value=value, **self._safe_tags(tags))

    def get_histogram_stats(self, name: str, tags: dict[str, str] | None = None) -> dict[str, float]:
        values = self._histograms.get(self._format_key(name, tags), [])
        if not values:
            return {"count": 0, "sum": 0, "avg": 0, "p95": 0}
        sorted_vals = sorted(values)
        p95_idx = int(len(sorted_vals) * 0.95)
        return {
            "count": len(values),
            "sum": sum(values),
            "avg": sum(values) / len(values),
            "p95": sorted_vals[p95_idx] if p95_idx > 0 else sorted_vals[-1],
        }

    # ------------------------------------------------------------------
    # Snapshot
    # ------------------------------------------------------------------

    def snapshot(self) -> dict:
        """Return all current metric values for health checks / debugging."""
        return {
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
            "histogram_stats": {
                k: self.get_histogram_stats(k) for k in self._histograms
            },
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _format_key(name: str, tags: dict[str, str] | None) -> str:
        if not tags:
            return name
        tag_str = ",".join(f"{k}={v}" for k, v in sorted(tags.items()))
        return f"{name}[{tag_str}]"

    @staticmethod
    def _safe_tags(tags: dict[str, str] | None) -> dict[str, str]:
        return tags or {}


# Global singleton
_metrics = MetricsCollector()


def get_metrics() -> MetricsCollector:
    return _metrics


# ==================================================================
# Pre-defined metric names (documented contract)
# ==================================================================

# Business metrics
METRIC_SCAN_REQUEST_TOTAL = "scan_request_total"
METRIC_SCAN_DURATION_SECONDS = "scan_duration_seconds"
METRIC_BLOCKING_RATE = "blocking_rate"
METRIC_CACHE_HIT_RATE = "cache_hit_rate"

# Health metrics
METRIC_EXTERNAL_API_ERRORS = "external_api_errors"
METRIC_DEGRADED_SCAN_COUNT = "degraded_scan_count"
METRIC_WORKER_QUEUE_DEPTH = "worker_queue_depth"
METRIC_TASK_FAILURE_RATE = "task_failure_rate"

# Security events
METRIC_BLOCKING_EXECUTED = "blocking_executed"
METRIC_APPEAL_COUNT = "appeal_count"
METRIC_HUMAN_INTERVENTION_COUNT = "human_intervention_count"
