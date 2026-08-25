"""Semgrep-based static code analyzer.

Runs Semgrep rules against source code. Zero LLM.
Supports: Python (MVP), extensible to JS/TS/Java.

Deployment modes:
- Python SDK (preferred): import semgrep directly.
- Subprocess fallback: semgrep CLI via sandbox.

Confidence levels:
- high: Well-tested rules (e.g., hardcoded secrets).
- medium: Community rules with reasonable accuracy.
- low: Experimental rules; findings are informational only, not blocking.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.utils.sandbox import run_tool_safely

# Check Semgrep availability
try:
    import semgrep  # noqa: F401
    HAS_SEMGREP_SDK = True
except ImportError:
    HAS_SEMGREP_SDK = False


# ------------------------------------------------------------------
# Confidence-based rule classification
# ------------------------------------------------------------------

HIGH_CONFIDENCE_RULES = {
    "generic.secrets.security.detected-private-key",
    "generic.secrets.security.detected-aws-access-key",
    "python.lang.security.audit.detect-sql-string",
    "python.lang.security.audit.hardcoded-tmp-file",
}

LOW_CONFIDENCE_RULES: set[str] = set()  # Populated from experimental rulesets

# Rules that are always blocking regardless of severity
ALWAYS_BLOCKING_RULES = {
    "generic.secrets.security.detected-private-key",
    "generic.secrets.security.detected-aws-access-key",
}


class CodeScanner:
    """Static code analysis via Semgrep rule engine.

    Usage:
        scanner = CodeScanner()
        issues, degraded, reason = await scanner.scan(
            repo_path="/tmp/repo",
            changed_files=[{"path": "main.py"}],
            language="python",
        )
    """

    def __init__(self, config_dir: str | None = None) -> None:
        self._config_dir = Path(config_dir or "config/semgrep")
        self._use_sdk = HAS_SEMGREP_SDK

    async def scan(
        self,
        repo_path: str | Path,
        changed_files: list[dict[str, Any]],
        *,
        language: str = "python",
        file_blacklist: list[str] | None = None,
    ) -> tuple[list[dict[str, Any]], bool, str]:
        """Run Semgrep scan on changed files.

        Args:
            repo_path: Repository root directory.
            changed_files: List of file metadata dicts.
            language: Programming language (only Python in MVP).
            file_blacklist: Path patterns to skip.

        Returns:
            (code_issues, degraded, degraded_reason) tuple.
        """
        blacklist = file_blacklist or ["test/", "tests/", "docs/"]

        # Filter to scan-eligible files
        scan_files = [
            f for f in changed_files
            if self._should_scan(f.get("path", ""), language, blacklist)
        ]

        if not scan_files:
            return [], False, ""

        # Run Semgrep
        if self._use_sdk:
            issues, degraded, reason = await self._scan_with_sdk(
                repo_path, scan_files
            )
        else:
            issues, degraded, reason = await self._scan_with_cli(
                repo_path, scan_files
            )

        # Classify confidence and blocking
        for issue in issues:
            rule_id = issue.get("rule_id", "")
            if rule_id in HIGH_CONFIDENCE_RULES:
                issue["confidence"] = "high"
            elif rule_id in LOW_CONFIDENCE_RULES:
                issue["confidence"] = "low"
            else:
                issue["confidence"] = "medium"

            # Blocking logic
            severity = issue.get("severity", "medium")
            confidence = issue.get("confidence", "medium")
            rule_id = issue.get("rule_id", "")

            if (
                rule_id in ALWAYS_BLOCKING_RULES
                or severity in ("critical", "high") and confidence != "low"
            ):
                issue["blocking"] = True
            else:
                issue["blocking"] = False

        return issues, degraded, reason

    # ------------------------------------------------------------------
    # SDK mode (preferred)
    # ------------------------------------------------------------------

    async def _scan_with_sdk(
        self, repo_path: str | Path, files: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], bool, str]:
        """Scan using the Semgrep Python SDK."""
        try:
            # The SDK can be called programmatically.
            # For MVP, we use the CLI fallback which is more widely tested.
            # When semgrep SDK is stable, replace this block.
            return await self._scan_with_cli(repo_path, files)
        except Exception:
            degraded = True
            reason = "Semgrep SDK failed; results may be incomplete"
            return [], degraded, reason

    # ------------------------------------------------------------------
    # CLI fallback
    # ------------------------------------------------------------------

    async def _scan_with_cli(
        self, repo_path: str | Path, files: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], bool, str]:
        """Scan using `semgrep` CLI via sandboxed subprocess."""
        repo = Path(repo_path)
        targets = [str(repo / f["path"]) for f in files if (repo / f["path"]).exists()]

        if not targets:
            return [], False, ""

        # Use local custom rules (offline, deterministic output).
        # NOTE: `--config auto` is intentionally avoided: it downloads registry
        # rules at scan time (network-dependent) and conflicts with `--metrics off`
        # on semgrep >= 1.174 ("Cannot create auto config when metrics are off").
        args = [
            "scan",
            "--config", str(self._config_dir),
            "--json",                   # Machine-readable output
            "--no-git-ignore",          # Don't skip .gitignored files
            "--metrics", "off",         # No telemetry
            "--quiet",
        ] + targets

        rc, stdout, stderr = run_tool_safely("semgrep", args, timeout=60)

        if rc != 0 and not stdout:
            # Semgrep returned non-zero with no output -> real failure
            degraded = True
            reason = f"Semgrep execution failed (rc={rc}): {stderr[:200]}"
            return [], degraded, reason

        try:
            raw = json.loads(stdout) if stdout else {"results": []}
        except json.JSONDecodeError:
            degraded = True
            reason = "Semgrep output was not valid JSON"
            return [], degraded, reason

        issues = self._parse_semgrep_output(raw)
        return issues, False, ""

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    def _parse_semgrep_output(self, raw: dict[str, Any]) -> list[dict[str, Any]]:
        """Parse Semgrep JSON output into CodeIssue-like dicts."""
        issues = []
        for result in raw.get("results", []):
            path = result.get("path", "")
            check_id = result.get("check_id", "")
            extra = result.get("extra", {})
            severity = extra.get("severity", "medium").lower()
            message = extra.get("message", "")
            fix_lines = extra.get("fix", "")
            start = result.get("start", {})
            line_number = start.get("line", 0)

            # Extract code snippet from lines if available
            lines = extra.get("lines", "")
            snippet = lines.strip()[:200] if lines else ""

            issues.append({
                "rule_id": check_id,
                "severity": severity,
                "confidence": "medium",  # Overridden by classifier later
                "file_path": path,
                "line_number": line_number,
                "code_snippet": snippet,
                "message": message.strip()[:500] if message else "",
                "fix_suggestion": fix_lines.strip()[:500] if fix_lines else "",
                "blocking": False,  # Overridden by classifier later
            })

        return issues

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    # Language -> file extension mapping (extensible via config)
    LANGUAGE_EXTENSIONS: dict[str, list[str]] = {
        "python": [".py"],
        "javascript": [".js", ".jsx", ".mjs"],
        "typescript": [".ts", ".tsx"],
        "java": [".java"],
        "go": [".go"],
        "rust": [".rs"],
        "ruby": [".rb"],
        "php": [".php"],
        "c": [".c", ".h"],
        "cpp": [".cpp", ".hpp", ".cc", ".cxx"],
    }

    @classmethod
    def _should_scan(
        cls, file_path: str, language: str, blacklist: list[str]
    ) -> bool:
        """Determine if a file should be scanned by Semgrep.

        Language filtering is driven by LANGUAGE_EXTENSIONS config,
        not hardcoded per-language checks. Add new languages by
        extending the dict — no code changes needed.
        """
        # Language -> extension lookup
        valid_extensions = cls.LANGUAGE_EXTENSIONS.get(language, [])
        if valid_extensions:
            import os
            ext = os.path.splitext(file_path)[1].lower()
            if ext not in valid_extensions:
                return False

        # Blacklist filter: return False if any blacklisted path matches
        return all(pattern.rstrip("/") not in file_path for pattern in blacklist)
