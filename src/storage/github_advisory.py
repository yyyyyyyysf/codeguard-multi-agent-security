"""GitHub Advisory Database client.

Queries the GitHub Advisory Database for vulnerability data.
Used as a secondary authoritative source alongside OSV.
API: https://github.com/advisories
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from src.core.constants import OSV_API_TIMEOUT
from src.core.errors import OSVApiUnavailableError
from src.core.models import Ecosystem


class GitHubAdvisoryClient:
    """Client for GitHub Advisory Database.

    Usage:
        async with GitHubAdvisoryClient() as client:
            advisories = await client.query_advisories("fastapi", Ecosystem.PYPI)
    """

    def __init__(
        self,
        token: str | None = None,
        timeout: int = OSV_API_TIMEOUT,
    ) -> None:
        self.token = token or os.getenv("GITHUB_ADVISORY_TOKEN", "")
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None
        self._headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            self._headers["Authorization"] = f"Bearer {self.token}"

    async def __aenter__(self) -> "GitHubAdvisoryClient":
        self._client = httpx.AsyncClient(
            base_url="https://api.github.com",
            headers=self._headers,
            timeout=httpx.Timeout(self.timeout),
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError(
                "GitHubAdvisoryClient not opened. Use 'async with' context manager."
            )
        return self._client

    async def query_advisories(
        self,
        package_name: str,
        ecosystem: Ecosystem,
        *,
        severity: str | None = None,
        per_page: int = 30,
    ) -> list[dict[str, Any]]:
        """Query GitHub Advisory Database for a package.

        Args:
            package_name: Package name to search.
            ecosystem: Package ecosystem filter.
            severity: Optional severity filter (critical/high/medium/low).
            per_page: Results per page (max 100).

        Returns:
            List of advisory dicts.
        """
        params: dict[str, Any] = {
            "per_page": min(per_page, 100),
        }
        if ecosystem == Ecosystem.PYPI:
            params["ecosystem"] = "pip"
        elif ecosystem == Ecosystem.NPM:
            params["ecosystem"] = "npm"
        elif ecosystem == Ecosystem.MAVEN:
            params["ecosystem"] = "maven"
        if severity:
            params["severity"] = severity

        try:
            response = await self.client.get(
                "/advisories",
                params={**params, "affects": package_name},
            )
            response.raise_for_status()
            return self._parse_response(response.json())
        except httpx.TimeoutException as e:
            raise OSVApiUnavailableError(
                f"GitHub Advisory timeout for {package_name}",
                retryable=True,
            ) from e
        except httpx.HTTPStatusError as e:
            raise OSVApiUnavailableError(
                f"GitHub Advisory returned {e.response.status_code}",
                retryable=e.response.status_code >= 500,
            ) from e
        except httpx.RequestError as e:
            raise OSVApiUnavailableError(
                f"GitHub Advisory unreachable: {str(e)}",
                retryable=True,
            ) from e

    async def get_advisory(self, ghsa_id: str) -> dict[str, Any] | None:
        """Get a single advisory by GHSA ID (e.g., 'GHSA-xxxx-xxxx-xxxx').

        Args:
            ghsa_id: GitHub Security Advisory ID.

        Returns:
            Advisory dict, or None if not found.
        """
        try:
            response = await self.client.get(f"/advisories/{ghsa_id}")
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return None
            raise OSVApiUnavailableError(
                f"GitHub Advisory error for {ghsa_id}: {e.response.status_code}",
                retryable=e.response.status_code >= 500,
            ) from e
        except httpx.RequestError as e:
            raise OSVApiUnavailableError(
                f"GitHub Advisory unreachable: {str(e)}",
                retryable=True,
            ) from e

    @staticmethod
    def _parse_response(data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Normalize GitHub Advisory response."""
        parsed = []
        for advisory in data:
            entry = {
                "ghsa_id": advisory.get("ghsa_id", ""),
                "cve_id": advisory.get("cve_id", ""),
                "summary": advisory.get("summary", ""),
                "description": advisory.get("description", ""),
                "severity": advisory.get("severity", "").lower() or None,
                "cvss_score": advisory.get("cvss", {}).get("score"),
                "published_at": advisory.get("published_at", ""),
                "updated_at": advisory.get("updated_at", ""),
                "references": advisory.get("references", []),
                "fixed_version": None,
            }

            # Try to extract fixed version from vulnerabilities
            for vuln in advisory.get("vulnerabilities", []):
                patched = vuln.get("patched_versions", "")
                if patched:
                    entry["fixed_version"] = patched
                    break

            parsed.append(entry)

        return parsed
