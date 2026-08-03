"""OSV API client for querying the Open Source Vulnerabilities database.

API docs: https://osv.dev/docs/
Endpoint: POST /v1/query
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from src.core.constants import OSV_API_TIMEOUT
from src.core.errors import OSVApiUnavailableError
from src.core.models import Ecosystem


class OSVClient:
    """Client for the OSV.dev vulnerability database API.

    Usage:
        async with OSVClient() as client:
            vulns = await client.query_vulns("fastapi", "0.100.0", Ecosystem.PYPI)
    """

    def __init__(
        self,
        base_url: str | None = None,
        timeout: int = OSV_API_TIMEOUT,
    ) -> None:
        self.base_url = base_url or os.getenv(
            "OSV_API_BASE_URL", "https://api.osv.dev/v1"
        )
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "OSVClient":
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(self.timeout),
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("OSVClient not opened. Use 'async with' context manager.")
        return self._client

    async def query_vulns(
        self, package_name: str, version: str, ecosystem: Ecosystem
    ) -> list[dict[str, Any]]:
        """Query vulnerabilities for a specific package version.

        Args:
            package_name: Name of the package ("fastapi").
            version: Version string ("0.100.0").
            ecosystem: Package ecosystem (pypi/npm/maven).

        Returns:
            List of vulnerability dicts with keys:
            id, summary, severity, cvss_score, fixed_version,
            aliases (CVE IDs), references.

        Raises:
            OSVApiUnavailableError: If the API is unreachable or returns an error.
        """
        request_body = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem.value,
            },
            "version": version,
        }

        try:
            response = await self.client.post("/query", json=request_body)
            response.raise_for_status()
            data = response.json()
            return self._parse_response(data)
        except httpx.TimeoutException as e:
            raise OSVApiUnavailableError(
                f"OSV API timeout for {package_name}@{version}",
                retryable=True,
            ) from e
        except httpx.HTTPStatusError as e:
            raise OSVApiUnavailableError(
                f"OSV API returned {e.response.status_code} for {package_name}@{version}",
                retryable=e.response.status_code >= 500,
            ) from e
        except httpx.RequestError as e:
            raise OSVApiUnavailableError(
                f"OSV API unreachable: {str(e)}",
                retryable=True,
            ) from e

    async def query_batch(
        self, packages: list[tuple[str, str, Ecosystem]]
    ) -> dict[str, list[dict[str, Any]]]:
        """Query vulnerabilities for multiple packages concurrently.

        Args:
            packages: List of (package_name, version, ecosystem) tuples.

        Returns:
            Dict mapping "name@version" -> list of vulnerability dicts.
        """
        import asyncio

        tasks = [
            self.query_vulns(name, ver, eco) for name, ver, eco in packages
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        output: dict[str, list[dict[str, Any]]] = {}
        for (name, ver, _), result in zip(packages, results):
            key = f"{name}@{ver}"
            if isinstance(result, Exception):
                output[key] = []  # Degraded: no results for this package
            else:
                output[key] = result

        return output

    @staticmethod
    def _parse_response(data: dict[str, Any]) -> list[dict[str, Any]]:
        """Parse raw OSV API response into a normalized list.

        OSV returns {"vulns": [...]} or {"vulns": []} if no vulns found.
        """
        vulns = data.get("vulns", [])
        parsed = []

        for vuln in vulns:
            entry = {
                "osv_id": vuln.get("id", ""),
                "summary": vuln.get("summary", ""),
                "details": vuln.get("details", ""),
                "aliases": vuln.get("aliases", []),  # CVE IDs are here
                "severity": None,
                "cvss_score": None,
                "fixed_version": None,
                "references": [ref.get("url", "") for ref in vuln.get("references", [])],
            }

            # Extract severity from database_specific or affected ranges
            db_specific = vuln.get("database_specific", {})
            if "severity" in db_specific:
                entry["severity"] = db_specific["severity"]
            if "cvss" in db_specific:
                entry["cvss_score"] = float(db_specific["cvss"])

            # Extract fixed version from affected ranges
            for affected in vuln.get("affected", []):
                for r in affected.get("ranges", []):
                    for event in r.get("events", []):
                        if "fixed" in event:
                            entry["fixed_version"] = event["fixed"]
                            break

            parsed.append(entry)

        return parsed
