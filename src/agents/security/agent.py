"""Security Audit Agent — Zero LLM, pure rule engine.

Orchestrates two independent scan pipelines:
1. CVE dependency scan (3-tier cache -> OSV/GitHub Advisory)
2. Semgrep code rule scan (static analysis)

Both pipelines are independently degradable:
- CVE scan falls back to local cache if OSV unavailable.
- Code scan falls back gracefully if Semgrep is not installed.

Security invariants enforced here:
- No LLM calls in any code path.
- Every finding has an evidence_source.
- Direct dependency CVSS >= 7.0 always blocking.
- Degraded results explicitly marked.
"""

from __future__ import annotations

import time
from typing import Any

from src.agents.security.code_scanner import CodeScanner
from src.agents.security.cve_scanner import CVEScanner
from src.agents.security.models import CodeIssue, SecurityReport, SecurityScanConfig, Vulnerability
from src.engine.base_agent import BaseAgent
from src.utils.id_gen import generate_id
from src.utils.logging import get_logger

logger = get_logger(__name__)


class SecurityAuditAgent(BaseAgent):
    """Security audit agent: CVE + code pattern scanning. Zero LLM.

    Input:  CodeMetadata (dependencies + changed_files + language)
    Output: SecurityReport (vulnerabilities + code_issues + blocking summary)
    """

    agent_id = "security_audit"
    description = (
        "Scans dependencies for known CVEs (OSV/GitHub Advisory) and source code "
        "for security anti-patterns (Semgrep rules). Zero LLM, evidence from "
        "authoritative databases only."
    )

    def __init__(
        self,
        redis_client: Any = None,
        cve_db_path: str | None = None,
        semgrep_config_dir: str | None = None,
        block_on_degraded: bool = False,
    ) -> None:
        super().__init__()
        self._cve_scanner = CVEScanner(redis_client, cve_db_path)
        self._code_scanner = CodeScanner(semgrep_config_dir)
        self._block_on_degraded = block_on_degraded

    # ------------------------------------------------------------------
    # Core logic
    # ------------------------------------------------------------------

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        """Execute both CVE and code scans.

        Args:
            code_metadata: dict with dependencies, transitive_deps, changed_files,
                          language, scan_scope, repo_path
            scan_scope: "full" | "diff"
            scan_config: optional SecurityScanConfig dict

        Returns:
            SecurityReport as dict (for JSON serialization to orchestrator).
        """
        code_metadata = kwargs.get("code_metadata", {})
        scan_scope = kwargs.get("scan_scope", "full")
        scan_config_dict = kwargs.get("scan_config", {})

        config = SecurityScanConfig(**scan_config_dict)
        scan_id = kwargs.get("scan_id", generate_id())
        started = time.monotonic()

        dependencies = code_metadata.get("dependencies", [])
        transitive_deps = code_metadata.get("transitive_deps", [])
        changed_files = code_metadata.get("changed_files", [])
        language = code_metadata.get("language", "python")
        repo_path = code_metadata.get("repo_path", "")

        degraded = False
        degraded_reasons: list[str] = []

        # --- Pipeline 1: CVE scan ---
        vulnerabilities: list[dict[str, Any]] = []
        if config.enable_cve_scan and dependencies:
            vulns, cve_degraded, cve_reason = await self._cve_scanner.scan(
                dependencies, transitive_deps
            )

            # Annotate file locations
            deps_file_map = self._build_deps_file_map(changed_files)
            vulns = self._cve_scanner.annotate_file_locations(vulns, deps_file_map)

            if cve_degraded:
                degraded = True
                degraded_reasons.append(f"CVE scan degraded: {cve_reason}")
                logger.warning("cve_scan_degraded", reason=cve_reason)

            vulnerabilities = vulns

        # --- Pipeline 2: Code scan ---
        code_issues: list[dict[str, Any]] = []
        if config.enable_code_scan and changed_files:
            issues, code_degraded, code_reason = await self._code_scanner.scan(
                repo_path,
                changed_files,
                language=language,
                file_blacklist=config.file_blacklist,
            )

            if code_degraded:
                degraded = True
                degraded_reasons.append(f"Code scan degraded: {code_reason}")
                logger.warning("code_scan_degraded", reason=code_reason)

            code_issues = issues

        # --- Assemble report ---
        duration_ms = int((time.monotonic() - started) * 1000)

        report = SecurityReport(
            scan_id=scan_id,
            scan_scope=scan_scope,
            rule_set_version="0.1.0",
            cve_db_version="",  # Populated by CVE cache on next iteration
            vulnerabilities=[Vulnerability(**v) for v in vulnerabilities],
            code_issues=[CodeIssue(**ci) for ci in code_issues],
            scan_duration_ms=duration_ms,
            scanned_deps_count=len(dependencies) + len(transitive_deps),
            degraded=degraded,
            degraded_reasons=degraded_reasons,
        )

        logger.info(
            "security_scan_complete",
            scan_id=scan_id,
            vuln_count=len(vulnerabilities),
            issue_count=len(code_issues),
            blocking_count=report.blocking_count,
            duration_ms=duration_ms,
            degraded=degraded,
        )

        # Propagate degradation to agent-level flag
        if degraded:
            self._degraded = True
            self._degraded_reasons = degraded_reasons

            # When configured to block on degraded scans, every finding
            # that passed through a degraded scanner becomes blocking.
            # This implements "scan incomplete → deny" for safety-first.
            if self._block_on_degraded:
                for v in report.vulnerabilities:
                    v.blocking = True
                for ci in report.code_issues:
                    ci.blocking = True

        return report.model_dump()

    # ------------------------------------------------------------------
    # Degradation
    # ------------------------------------------------------------------

    async def degraded_run(
        self, original_error: Exception, **kwargs: Any
    ) -> dict[str, Any]:
        """Fallback: run CVE scan with local cache only, skip code scan.

        This is the minimal viable security scan when dependencies are failing.
        At minimum, we check the local SQLite CVE cache.
        """
        code_metadata = kwargs.get("code_metadata", {})
        scan_id = kwargs.get("scan_id", generate_id())
        started = time.monotonic()

        dependencies = code_metadata.get("dependencies", [])

        # CVE scan with local cache only (no OSV API)
        vulns = []
        try:
            # Direct SQLite lookup bypasses the cache's OSV fallback
            from src.storage.cve_cache import CVECache
            cache = CVECache(db_path=self._cve_scanner._cache._db_path)
            for dep in dependencies:
                name = dep.get("name", "")
                version = dep.get("version", "")
                eco = dep.get("ecosystem", "pypi")
                cached = cache._sqlite_lookup(name, version, eco)
                for v in cached:
                    v["dependency_type"] = "direct"
                    v["blocking"] = v.get("severity") in ("critical", "high")
                    v["file_location"] = ""
                vulns.extend(cached)
        except Exception:
            pass

        duration_ms = int((time.monotonic() - started) * 1000)

        report = SecurityReport(
            scan_id=scan_id,
            scan_scope=kwargs.get("scan_scope", "full"),
            vulnerabilities=[Vulnerability(**v) for v in vulns],
            code_issues=[],
            scan_duration_ms=duration_ms,
            scanned_deps_count=len(dependencies),
            degraded=True,
            degraded_reasons=[f"Agent degraded after error: {str(original_error)}"],
        )

        return report.model_dump()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_deps_file_map(
        changed_files: list[dict[str, Any]],
    ) -> dict[str, str]:
        """Build a mapping from package name -> file:line for dependency manifests.

        Scans files like requirements.txt to locate which line each dependency
        is declared on, for precise file_location annotation.
        """
        deps_map: dict[str, str] = {}

        for f in changed_files:
            fpath = f.get("path", "")
            content = f.get("content") or f.get("diff_lines") or ""

            # Only process dependency manifest files
            if not _is_dep_manifest(fpath):
                continue

            for line_num, line in enumerate(content.splitlines(), start=1):
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # Try to extract package name
                for separator in ("==", ">=", "<=", "~=", "!=", ">", "<"):
                    if separator in line:
                        pkg_name = line.split(separator)[0].strip().lower()
                        if pkg_name and pkg_name not in deps_map:
                            deps_map[pkg_name] = f"{fpath}:L{line_num}"
                        break

        return deps_map


def _is_dep_manifest(filepath: str) -> bool:
    """Check if a file is a dependency manifest."""
    manifest_names = {
        "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg",
        "Pipfile", "Pipfile.lock", "poetry.lock",
        "package.json", "package-lock.json", "yarn.lock",
        "pom.xml", "build.gradle", "build.gradle.kts",
        "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
        "Gemfile", "Gemfile.lock",
    }
    filename = filepath.split("/")[-1]
    return filename in manifest_names
