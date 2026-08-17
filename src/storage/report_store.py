"""Report storage abstraction layer.

Currently stores reports as local JSON/HTML files.
Interface is abstracted so v1.0 can swap in S3-compatible object storage
without changing consumer code.

MVP storage layout:
{report_dir}/
  {scan_id}/
    report.json     # Machine-readable full report
    report.html     # Human-readable report
    pr_comment.md   # PR comment (generated)
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class ReportStorage(ABC):
    """Abstract report storage interface."""

    @abstractmethod
    def save_json(self, scan_id: str, data: dict[str, Any]) -> str:
        """Save report as JSON. Returns the file path or URI."""
        ...

    @abstractmethod
    def save_html(self, scan_id: str, html: str) -> str:
        """Save report as HTML. Returns the file path or URI."""
        ...

    @abstractmethod
    def save_markdown(self, scan_id: str, markdown: str, filename: str = "report.md") -> str:
        """Save a markdown file. Returns the file path or URI."""
        ...

    @abstractmethod
    def load_json(self, scan_id: str) -> dict[str, Any] | None:
        """Load a JSON report. Returns None if not found."""
        ...

    @abstractmethod
    def exists(self, scan_id: str) -> bool:
        """Check if a report exists for the given scan_id."""
        ...

    @abstractmethod
    def delete(self, scan_id: str) -> bool:
        """Delete all report files for a scan. Returns True if anything was deleted."""
        ...


class LocalFileReportStorage(ReportStorage):
    """Local filesystem report storage (MVP implementation).

    Usage:
        storage = LocalFileReportStorage("/tmp/codeguard_reports")
        path = storage.save_json("scan-abc", report_dict)
    """

    def __init__(self, base_dir: str | None = None) -> None:
        self._base = Path(
            base_dir or os.getenv("REPORT_STORAGE_DIR", "/tmp/codeguard_reports")
        )
        self._base.mkdir(parents=True, exist_ok=True)

    def _scan_dir(self, scan_id: str) -> Path:
        d = self._base / scan_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def save_json(self, scan_id: str, data: dict[str, Any]) -> str:
        path = self._scan_dir(scan_id) / "report.json"
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
        )
        return str(path)

    def save_html(self, scan_id: str, html: str) -> str:
        path = self._scan_dir(scan_id) / "report.html"
        path.write_text(html, encoding="utf-8")
        return str(path)

    def save_markdown(self, scan_id: str, markdown: str, filename: str = "report.md") -> str:
        path = self._scan_dir(scan_id) / filename
        path.write_text(markdown, encoding="utf-8")
        return str(path)

    def load_json(self, scan_id: str) -> dict[str, Any] | None:
        path = self._base / scan_id / "report.json"
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def exists(self, scan_id: str) -> bool:
        return (self._base / scan_id / "report.json").exists()

    def delete(self, scan_id: str) -> bool:
        scan_dir = self._base / scan_id
        if not scan_dir.exists():
            return False
        import shutil
        shutil.rmtree(str(scan_dir), ignore_errors=True)
        return True

    def list_reports(self, limit: int = 50) -> list[str]:
        """List recent scan_ids."""
        dirs = sorted(
            [d.name for d in self._base.iterdir() if d.is_dir()],
            reverse=True,
        )
        return dirs[:limit]
