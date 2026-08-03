"""Append-only audit log with chain-hash integrity protection.

Every security decision, human intervention, and exemption is
permanently recorded. The chain hash (SHA256 of prev_hash + current_row)
makes tampering detectable, satisfying compliance requirements.

Design:
- Append-only: INSERT only, no UPDATE/DELETE.
- Chain hash: Each row includes row_hash = SHA256(prev_row_hash + row_data).
- Separate storage: SQLite for MVP, designed for migration to PostgreSQL.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any


class AuditLogger:
    """Append-only audit log with chain-hash integrity.

    Usage:
        logger = AuditLogger("data/audit.db")
        logger.log(
            action="verdict_made",
            operator="system",
            detail={"finding_id": "CVE-2024-xxx", "verdict": "block"},
            evidence_link="https://osv.dev/CVE-2024-xxx",
        )
    """

    def __init__(self, db_path: str | None = None) -> None:
        self._db_path = db_path or os.getenv(
            "DATABASE_URL", "data/codeguard.db"
        ).replace("sqlite:///", "")
        self._init_db()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log(
        self,
        *,
        action: str,
        operator: str,
        detail: dict[str, Any],
        evidence_link: str | None = None,
        scan_id: str | None = None,
        task_id: str | None = None,
    ) -> int:
        """Append a new audit entry. Returns the entry ID.

        Args:
            action: Action type (scan_started, vulnerability_found,
                    verdict_made, appeal_submitted, appeal_approved,
                    blocking_executed, etc.)
            operator: "system" or "human:{user_id}"
            detail: Structured details of the action.
            evidence_link: Optional URL to evidence.
            scan_id: Associated scan ID.
            task_id: Associated task ID.

        Returns:
            The auto-generated entry ID.
        """
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()

        # Get previous row hash for chain integrity
        prev = conn.execute(
            "SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = prev["row_hash"] if prev else "0" * 64

        # Compute current row hash
        row_data = json.dumps({
            "timestamp": now,
            "action": action,
            "operator": operator,
            "detail": detail,
            "evidence_link": evidence_link or "",
            "scan_id": scan_id or "",
            "task_id": task_id or "",
        }, sort_keys=True)
        row_hash = hashlib.sha256(
            (prev_hash + row_data).encode("utf-8")
        ).hexdigest()

        cursor = conn.execute(
            """INSERT INTO audit_log
               (timestamp, action, operator, detail, evidence_link,
                scan_id, task_id, row_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                now,
                action,
                operator,
                json.dumps(detail, ensure_ascii=False),
                evidence_link or "",
                scan_id or "",
                task_id or "",
                row_hash,
            ),
        )
        conn.commit()
        return cursor.lastrowid

    def query(
        self,
        *,
        action: str | None = None,
        scan_id: str | None = None,
        task_id: str | None = None,
        operator: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query audit log entries with optional filters."""
        conn = self._get_conn()
        conditions = []
        params: list[Any] = []

        if action:
            conditions.append("action = ?")
            params.append(action)
        if scan_id:
            conditions.append("scan_id = ?")
            params.append(scan_id)
        if task_id:
            conditions.append("task_id = ?")
            params.append(task_id)
        if operator:
            conditions.append("operator = ?")
            params.append(operator)

        where = " AND ".join(conditions) if conditions else "1=1"
        rows = conn.execute(
            f"SELECT * FROM audit_log WHERE {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()

        return [self._row_to_dict(row) for row in rows]

    def verify_integrity(self) -> dict[str, Any]:
        """Verify the chain hash integrity of the entire audit log.

        Returns:
            Dict with valid (bool), total_rows, first_bad_row,
            and computed_hash vs stored_hash at each position.
        """
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT id, row_hash, timestamp, action, operator, detail, "
            "evidence_link, scan_id, task_id FROM audit_log ORDER BY id ASC"
        ).fetchall()

        prev_hash = "0" * 64
        result = {"valid": True, "total_rows": len(rows), "bad_rows": []}

        for row in rows:
            row_data = json.dumps({
                "timestamp": row["timestamp"],
                "action": row["action"],
                "operator": row["operator"],
                "detail": json.loads(row["detail"]) if row["detail"] else {},
                "evidence_link": row["evidence_link"] or "",
                "scan_id": row["scan_id"] or "",
                "task_id": row["task_id"] or "",
            }, sort_keys=True)
            expected_hash = hashlib.sha256(
                (prev_hash + row_data).encode("utf-8")
            ).hexdigest()

            if expected_hash != row["row_hash"]:
                result["valid"] = False
                result["bad_rows"].append({
                    "id": row["id"],
                    "expected": expected_hash,
                    "stored": row["row_hash"],
                })

            prev_hash = row["row_hash"]

        return result

    def get_recent(self, limit: int = 10) -> list[dict[str, Any]]:
        """Get the most recent audit entries."""
        return self.query(limit=limit)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        """Create audit_log table if not exists."""
        os.makedirs(os.path.dirname(self._db_path) or ".", exist_ok=True)
        conn = self._get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                operator TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT '{}',
                evidence_link TEXT NOT NULL DEFAULT '',
                scan_id TEXT NOT NULL DEFAULT '',
                task_id TEXT NOT NULL DEFAULT '',
                row_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_scan ON audit_log(scan_id)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_task ON audit_log(task_id)
        """)
        conn.commit()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "action": row["action"],
            "operator": row["operator"],
            "detail": json.loads(row["detail"]) if row["detail"] else {},
            "evidence_link": row["evidence_link"],
            "scan_id": row["scan_id"],
            "task_id": row["task_id"],
            "row_hash": row["row_hash"],
        }
