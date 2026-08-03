"""3-tier CVE cache: Redis hot -> SQLite warm -> OSV API cold.

Query priority:
1. Redis (Top 200 popular packages, 1h TTL)
2. Local SQLite (1 year of high/critical CVEs, daily sync)
3. OSV API (real-time query, authoritative source)

All lookups return normalized Vulnerability dicts.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any

from src.core.constants import (
    CVE_HOT_CACHE_SIZE,
    CVE_LOCAL_SYNC_INTERVAL_HOURS,
    CVE_STALENESS_WARNING_HOURS,
)
from src.core.models import Ecosystem, Severity
from src.storage.osv_client import OSVClient


class CVECache:
    """3-tier vulnerability cache.

    Usage:
        cache = CVECache(redis_client, db_path="data/cve_cache.db")
        vulns = await cache.lookup("fastapi", "0.100.0", Ecosystem.PYPI)
    """

    def __init__(
        self,
        redis_client: Any = None,
        db_path: str | None = None,
    ) -> None:
        self._redis = redis_client
        self._db_path = db_path or os.getenv(
            "CVE_CACHE_DB_PATH", "data/cve_cache.db"
        )
        self._init_sqlite()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def lookup(
        self, package_name: str, version: str, ecosystem: Ecosystem
    ) -> list[dict[str, Any]]:
        """Look up vulnerabilities for a package version.

        Order: Redis -> SQLite -> OSV API.
        Each hit at a lower tier is promoted to the tier above.
        """
        cache_key = f"cve:{ecosystem.value}:{package_name}:{version}"

        # Tier 1: Redis hot cache
        if self._redis:
            result = await self._redis_get(cache_key)
            if result is not None:
                return result

        # Tier 2: SQLite local cache
        result = self._sqlite_lookup(package_name, version, ecosystem.value)
        if result:
            # Promote to Redis
            if self._redis:
                await self._redis_set(cache_key, result, ttl=3600)
            return result

        # Tier 3: OSV API (real-time)
        result = await self._fetch_from_osv(package_name, version, ecosystem)
        if result is not None:
            # Persist to SQLite and promote to Redis
            self._sqlite_insert_batch(package_name, version, ecosystem.value, result)
            if self._redis:
                await self._redis_set(cache_key, result, ttl=3600)

        return result or []

    async def lookup_batch(
        self, packages: list[tuple[str, str, Ecosystem]]
    ) -> dict[str, list[dict[str, Any]]]:
        """Look up vulnerabilities for multiple packages.

        Returns:
            Dict mapping "name@version" -> list of normalized vulnerability dicts.
        """
        results: dict[str, list[dict[str, Any]]] = {}
        for name, ver, eco in packages:
            key = f"{name}@{ver}"
            try:
                results[key] = await self.lookup(name, ver, eco)
            except Exception:
                results[key] = []  # Degraded: empty for this package
        return results

    async def sync_hot_cache(self) -> None:
        """Refresh the Redis hot cache with top N popular packages.

        Called periodically (e.g., via cron) to keep the hot tier warm.
        """
        if not self._redis:
            return

        popular_packages = self._get_popular_packages()
        for pkg_name, pkg_version, ecosystem in popular_packages[:CVE_HOT_CACHE_SIZE]:
            await self.lookup(pkg_name, pkg_version, ecosystem)

    def get_sync_status(self) -> dict[str, Any]:
        """Return sync status for monitoring."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT COUNT(*), MAX(updated_at) FROM cve_cache"
        ).fetchone()
        return {
            "cached_count": row[0],
            "last_synced_at": row[1],
            "db_path": self._db_path,
            "redis_available": self._redis is not None,
        }

    # ------------------------------------------------------------------
    # Redis helpers
    # ------------------------------------------------------------------

    async def _redis_get(self, key: str) -> list[dict[str, Any]] | None:
        try:
            data = await self._redis.get(key)
            if data:
                return json.loads(data)
        except Exception:
            pass
        return None

    async def _redis_set(
        self, key: str, data: list[dict[str, Any]], ttl: int = 3600
    ) -> None:
        try:
            await self._redis.setex(key, ttl, json.dumps(data))
        except Exception:
            pass  # Redis failure is non-fatal

    # ------------------------------------------------------------------
    # SQLite helpers
    # ------------------------------------------------------------------

    def _init_sqlite(self) -> None:
        """Create SQLite database and tables if not exists."""
        os.makedirs(os.path.dirname(self._db_path) or ".", exist_ok=True)
        conn = self._get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL,
                version TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                cve_id TEXT NOT NULL,
                severity TEXT,
                cvss_score REAL,
                fixed_version TEXT,
                summary TEXT,
                evidence_source TEXT DEFAULT 'local_cache',
                evidence_url TEXT,
                raw_json TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(package_name, version, ecosystem, cve_id)
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_cve_lookup
            ON cve_cache(package_name, version, ecosystem)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_cve_updated
            ON cve_cache(updated_at)
        """)
        conn.commit()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _sqlite_lookup(
        self, package_name: str, version: str, ecosystem: str
    ) -> list[dict[str, Any]]:
        """Query SQLite cache. Returns empty list if not found."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT * FROM cve_cache
               WHERE package_name = ? AND version = ? AND ecosystem = ?
               ORDER BY cvss_score DESC""",
            (package_name, version, ecosystem),
        ).fetchall()

        if not rows:
            return []

        # Check staleness
        latest_update = max(row["updated_at"] for row in rows)
        try:
            updated_dt = datetime.fromisoformat(latest_update)
            age_hours = (
                datetime.now(timezone.utc) - updated_dt.replace(tzinfo=timezone.utc)
            ).total_seconds() / 3600
        except (ValueError, TypeError):
            age_hours = 0

        # If cache is stale, return empty to force OSV re-fetch
        if age_hours > CVE_STALENESS_WARNING_HOURS:
            return []

        return [self._row_to_dict(row) for row in rows]

    def _sqlite_insert_batch(
        self,
        package_name: str,
        version: str,
        ecosystem: str,
        vulns: list[dict[str, Any]],
    ) -> None:
        """Insert or update multiple vulnerability records."""
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()

        for vuln in vulns:
            conn.execute(
                """INSERT OR REPLACE INTO cve_cache
                   (package_name, version, ecosystem, cve_id, severity,
                    cvss_score, fixed_version, summary, evidence_source,
                    evidence_url, raw_json, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    package_name,
                    version,
                    ecosystem,
                    vuln.get("cve_id", ""),
                    vuln.get("severity", "unknown"),
                    vuln.get("cvss_score"),
                    vuln.get("fixed_version"),
                    vuln.get("summary", ""),
                    vuln.get("evidence_source", "local_cache"),
                    vuln.get("evidence_url", ""),
                    json.dumps(vuln),
                    now,
                ),
            )
        conn.commit()

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "cve_id": row["cve_id"],
            "package_name": row["package_name"],
            "version": row["version"],
            "severity": row["severity"],
            "cvss_score": row["cvss_score"],
            "fixed_version": row["fixed_version"],
            "summary": row["summary"],
            "evidence_source": row["evidence_source"],
            "evidence_url": row["evidence_url"],
        }

    # ------------------------------------------------------------------
    # OSV API
    # ------------------------------------------------------------------

    async def _fetch_from_osv(
        self, package_name: str, version: str, ecosystem: Ecosystem
    ) -> list[dict[str, Any]] | None:
        """Fetch from OSV API. Returns None on failure (caller handles degradation)."""
        try:
            async with OSVClient() as client:
                raw_vulns = await client.query_vulns(package_name, version, ecosystem)
        except Exception:
            return None  # Degradation: OSV unavailable

        normalized = []
        for v in raw_vulns:
            cve_ids = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
            main_cve = cve_ids[0] if cve_ids else v.get("osv_id", "")

            normalized.append({
                "cve_id": main_cve,
                "package_name": package_name,
                "version": version,
                "severity": v.get("severity", "unknown"),
                "cvss_score": v.get("cvss_score"),
                "fixed_version": v.get("fixed_version"),
                "summary": v.get("summary", ""),
                "evidence_source": "OSV",
                "evidence_url": v.get("references", [None])[0] if v.get("references") else "",
            })

        return normalized

    def _get_popular_packages(self) -> list[tuple[str, str, Ecosystem]]:
        """Get list of popular packages for hot cache warming.

        In production, this would come from download statistics.
        For MVP, returns a static list of common Python dependencies.
        """
        return [
            # Top Python packages (versions are placeholders - real versions from real scans)
            ("fastapi", "0.110.0", Ecosystem.PYPI),
            ("django", "5.0.0", Ecosystem.PYPI),
            ("flask", "3.0.0", Ecosystem.PYPI),
            ("requests", "2.31.0", Ecosystem.PYPI),
            ("sqlalchemy", "2.0.0", Ecosystem.PYPI),
            ("pydantic", "2.6.0", Ecosystem.PYPI),
            ("celery", "5.3.0", Ecosystem.PYPI),
            ("redis", "5.0.0", Ecosystem.PYPI),
            ("httpx", "0.27.0", Ecosystem.PYPI),
            ("uvicorn", "0.27.0", Ecosystem.PYPI),
            ("numpy", "1.26.0", Ecosystem.PYPI),
            ("pandas", "2.2.0", Ecosystem.PYPI),
            ("jinja2", "3.1.0", Ecosystem.PYPI),
            ("cryptography", "42.0.0", Ecosystem.PYPI),
            ("pyyaml", "6.0.0", Ecosystem.PYPI),
        ]
