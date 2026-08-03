"""Exemption rule storage and caching.

Rules define when security findings can be automatically waived.
Read-heavy workload: cached in Redis, persisted in SQLite.

Rule types:
- cve_whitelist: Waive specific CVEs.
- path_whitelist: Waive findings in specific paths (e.g., test/).
- severity_downgrade: Downgrade severity for specific patterns.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any

from src.core.models import RuleType, Severity


class RuleStore:
    """CRUD store for exemption rules with Redis caching.

    Usage:
        store = RuleStore(redis_client, "data/codeguard.db")
        rules = store.get_active_rules()
    """

    def __init__(
        self,
        redis_client: Any = None,
        db_path: str | None = None,
    ) -> None:
        self._redis = redis_client
        self._db_path = db_path or os.getenv(
            "DATABASE_URL", "data/codeguard.db"
        ).replace("sqlite:///", "")
        self._init_db()

    # ------------------------------------------------------------------
    # Query API
    # ------------------------------------------------------------------

    def get_active_rules(self) -> list[dict[str, Any]]:
        """Get all currently active exemption rules.

        Tries Redis cache first, falls back to SQLite.
        """
        if self._redis:
            cached = self._redis_get("config:exemption:hash")
            if cached is not None:
                return cached

        rules = self._query_active_from_db()

        if self._redis:
            self._redis_set("config:exemption:hash", rules, ttl=3600)

        return rules

    def get_rule(self, rule_id: str) -> dict[str, Any] | None:
        """Get a single rule by ID."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM exemption_rules WHERE rule_id = ?",
            (rule_id,),
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def create_rule(
        self,
        *,
        rule_type: RuleType,
        pattern: str,
        reason: str,
        created_by: str,
        scope: str = "global",
        expires_at: str | None = None,
    ) -> str:
        """Create a new exemption rule. Returns the rule_id.

        Args:
            rule_type: Type of exemption.
            pattern: Pattern to match (CVE ID, path glob, severity threshold).
            reason: Justification for the exemption (required).
            created_by: Who created this rule.
            scope: Rule scope (global | repo:{url} | path:{pattern}).
            expires_at: Optional expiry time (ISO 8601).
        """
        from src.utils.id_gen import generate_id

        rule_id = generate_id()
        now = datetime.now(timezone.utc).isoformat()

        conn = self._get_conn()
        conn.execute(
            """INSERT INTO exemption_rules
               (rule_id, rule_type, pattern, reason, scope,
                created_by, created_at, expires_at, enabled)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)""",
            (rule_id, rule_type.value, pattern, reason, scope,
             created_by, now, expires_at),
        )
        conn.commit()

        # Invalidate cache
        self._invalidate_cache()
        return rule_id

    def update_rule(
        self,
        rule_id: str,
        *,
        enabled: bool | None = None,
        pattern: str | None = None,
        reason: str | None = None,
        expires_at: str | None = None,
    ) -> bool:
        """Update an existing rule. Returns True if the rule was found."""
        conn = self._get_conn()
        updates: list[str] = []
        params: list[Any] = []

        if enabled is not None:
            updates.append("enabled = ?")
            params.append(1 if enabled else 0)
        if pattern is not None:
            updates.append("pattern = ?")
            params.append(pattern)
        if reason is not None:
            updates.append("reason = ?")
            params.append(reason)
        if expires_at is not None:
            updates.append("expires_at = ?")
            params.append(expires_at)

        if not updates:
            return False

        params.append(rule_id)
        conn.execute(
            f"UPDATE exemption_rules SET {', '.join(updates)} WHERE rule_id = ?",
            params,
        )
        conn.commit()

        if conn.total_changes > 0:
            self._invalidate_cache()
            return True
        return False

    def delete_rule(self, rule_id: str) -> bool:
        """Soft-delete (disable) a rule. Hard delete is forbidden per audit policy."""
        return self.update_rule(rule_id, enabled=False)

    def get_rules_by_type(self, rule_type: RuleType) -> list[dict[str, Any]]:
        """Get active rules of a specific type."""
        rules = self.get_active_rules()
        return [r for r in rules if r["rule_type"] == rule_type.value and r["enabled"]]

    # ------------------------------------------------------------------
    # Cache helpers
    # ------------------------------------------------------------------

    def _invalidate_cache(self) -> None:
        """Invalidate the Redis rule cache."""
        if self._redis:
            try:
                import asyncio
                asyncio.create_task(self._redis.delete("config:exemption:hash"))
            except Exception:
                pass

    def _redis_get(self, key: str) -> list[dict[str, Any]] | None:
        try:
            data = self._redis.get(key)
            if data:
                return json.loads(data)
        except Exception:
            pass
        return None

    def _redis_set(
        self, key: str, data: list[dict[str, Any]], ttl: int = 3600
    ) -> None:
        try:
            self._redis.setex(key, ttl, json.dumps(data))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # SQLite helpers
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        os.makedirs(os.path.dirname(self._db_path) or ".", exist_ok=True)
        conn = self._get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS exemption_rules (
                rule_id TEXT PRIMARY KEY,
                rule_type TEXT NOT NULL,
                pattern TEXT NOT NULL,
                reason TEXT NOT NULL,
                scope TEXT NOT NULL DEFAULT 'global',
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                enabled INTEGER NOT NULL DEFAULT 1
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_rules_type ON exemption_rules(rule_type, enabled)
        """)
        conn.commit()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _query_active_from_db(self) -> list[dict[str, Any]]:
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT * FROM exemption_rules
               WHERE enabled = 1
               AND (expires_at IS NULL OR expires_at > datetime('now'))
               ORDER BY created_at DESC"""
        ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "rule_id": row["rule_id"],
            "rule_type": row["rule_type"],
            "pattern": row["pattern"],
            "reason": row["reason"],
            "scope": row["scope"],
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "enabled": bool(row["enabled"]),
        }
