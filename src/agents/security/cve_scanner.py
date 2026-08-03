"""CVE vulnerability scanner with 3-tier cache (Redis -> SQLite -> OSV API).

Zero LLM. All conclusions come from authoritative databases.
Handles direct/transitive dependency blocking classification.

Blocking logic:
    direct dep   + CVSS >= 7.0 -> blocking=true
    direct dep   + CVSS <  7.0 -> blocking=false, warning
    transitive   + CVSS >= 7.0 -> blocking=false, warning (configurable)
    transitive   + CVSS <  7.0 -> blocking=false, info
"""

from __future__ import annotations

import time
from typing import Any

from src.core.errors import OSVApiUnavailableError
from src.core.models import DependencyType, Ecosystem, Severity
from src.storage.cve_cache import CVECache


class CVEScanner:
    """Dependency vulnerability scanner backed by 3-tier CVE cache.

    Usage:
        scanner = CVEScanner(redis_client, db_path="data/cve_cache.db")
        vulns, degraded, reason = await scanner.scan(dependencies)
    """

    def __init__(
        self,
        redis_client: Any = None,
        db_path: str | None = None,
    ) -> None:
        self._cache = CVECache(redis_client, db_path)

    async def scan(
        self,
        dependencies: list[dict[str, Any]],
        transitive_deps: list[dict[str, Any]] | None = None,
    ) -> tuple[list[dict[str, Any]], bool, str]:
        """Scan all dependencies for known vulnerabilities.

        Args:
            dependencies: Direct dependency dicts [{name, version, ecosystem}, ...].
            transitive_deps: Transitive dependency dicts.

        Returns:
            (vulnerabilities, degraded, degraded_reason) tuple.
            vulnerabilities is a list of normalized Vulnerability-like dicts.
        """
        started = time.monotonic()
        all_vulns: list[dict[str, Any]] = []
        degraded = False
        degraded_reason = ""

        # Build flat package list with type tags
        packages: list[tuple[str, str, Ecosystem, str]] = []
        for dep in dependencies:
            packages.append((
                dep.get("name", ""),
                dep.get("version", ""),
                Ecosystem(dep.get("ecosystem", "pypi")),
                DependencyType.DIRECT.value,
            ))
        for dep in (transitive_deps or []):
            packages.append((
                dep.get("name", ""),
                dep.get("version", ""),
                Ecosystem(dep.get("ecosystem", "pypi")),
                DependencyType.TRANSITIVE.value,
            ))

        if not packages:
            return [], False, ""

        # Batch lookup via cache
        try:
            raw_results = await self._cache.lookup_batch(
                [(name, ver, eco) for name, ver, eco, _ in packages]
            )
        except OSVApiUnavailableError:
            degraded = True
            degraded_reason = "OSV API unavailable; results from local cache only"
            # Retry with cache-only (OSV won't be called)
            raw_results = {}
            for name, ver, eco, _ in packages:
                key = f"{name}@{ver}"
                raw_results[key] = self._cache._sqlite_lookup(name, ver, eco.value)

        # Normalize and classify
        for (name, ver, eco, dep_type), (key, vulns) in zip(packages, raw_results.items()):
            for v in vulns:
                severity_str = v.get("severity", "medium")
                try:
                    severity = Severity(severity_str)
                except ValueError:
                    severity = Severity.MEDIUM

                cvss = v.get("cvss_score")
                is_direct = dep_type == DependencyType.DIRECT.value

                # Blocking logic
                if is_direct and severity.is_blocking:
                    blocking = True
                elif is_direct:
                    blocking = False  # Direct but low/medium -> warning
                elif severity == Severity.CRITICAL:
                    blocking = True  # Transitive critical -> still block
                else:
                    blocking = False  # Transitive non-critical -> info

                all_vulns.append({
                    "cve_id": v.get("cve_id", ""),
                    "package_name": name,
                    "affected_version": ver,
                    "affected_version_range": v.get("affected_version_range"),
                    "fixed_version": v.get("fixed_version"),
                    "fix_available": bool(v.get("fixed_version")),
                    "severity": severity.value,
                    "cvss_score": float(cvss) if cvss else None,
                    "dependency_type": dep_type,
                    "evidence_source": v.get("evidence_source", "local_cache"),
                    "evidence_url": v.get("evidence_url", ""),
                    "file_location": "",  # Filled by caller from dependency manifest
                    "blocking": blocking,
                    "description": v.get("summary", v.get("description", "")),
                })

        duration_ms = int((time.monotonic() - started) * 1000)
        return all_vulns, degraded, degraded_reason

    def annotate_file_locations(
        self, vulns: list[dict[str, Any]], deps_file_map: dict[str, str]
    ) -> list[dict[str, Any]]:
        """Add file_location to each vulnerability based on dependency manifest.

        Args:
            vulns: Vulnerability dicts from scan().
            deps_file_map: {"package_name": "requirements.txt:L15", ...}

        Returns:
            Same list with file_location populated.
        """
        for v in vulns:
            pkg = v.get("package_name", "")
            if pkg in deps_file_map:
                v["file_location"] = deps_file_map[pkg]
            elif not v.get("file_location"):
                v["file_location"] = "unknown"
        return vulns
