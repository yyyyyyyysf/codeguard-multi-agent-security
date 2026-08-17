"""Tests for the CVE cache — GitHub Advisory fallback path."""

import os
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.models import Ecosystem
from src.storage.cve_cache import CVECache


@pytest.fixture
def db_path():
    """Unique SQLite path inside the (gitignored) data/ directory.

    pytest's tmp_path is not writable inside the Codex sandbox, so tests
    use the project's own data/ folder and clean up afterwards.
    """
    data_dir = os.path.join(os.path.dirname(__file__), "..", "..", "..", "data")
    os.makedirs(data_dir, exist_ok=True)
    path = os.path.join(data_dir, f"test_cve_cache_{uuid.uuid4().hex}.db")
    yield path
    try:
        os.remove(path)
    except OSError:
        pass


class TestGitHubAdvisoryFallback:
    @pytest.mark.asyncio
    @patch.dict(os.environ, {"GITHUB_ADVISORY_TOKEN": "ghp_test"}, clear=False)
    async def test_fetch_from_github_advisory(self, db_path):
        cache = CVECache(db_path=db_path)

        mock_client = MagicMock()
        mock_client.query_advisories = AsyncMock(return_value=[
            {
                "ghsa_id": "GHSA-abc",
                "cve_id": "CVE-2024-0001",
                "summary": "bad package",
                "severity": "high",
                "cvss_score": 8.1,
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-0001"],
                "fixed_version": "1.2.3",
            }
        ])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch(
            "src.storage.github_advisory.GitHubAdvisoryClient",
            return_value=mock_client,
        ):
            vulns = await cache._fetch_from_github_advisory("badpkg", Ecosystem.PYPI)

        assert len(vulns) == 1
        assert vulns[0]["cve_id"] == "CVE-2024-0001"
        assert vulns[0]["evidence_source"] == "GitHub Advisory"
        assert vulns[0]["fixed_version"] == "1.2.3"

    @pytest.mark.asyncio
    async def test_fetch_from_github_advisory_without_token(self, db_path):
        cache = CVECache(db_path=db_path)
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GITHUB_ADVISORY_TOKEN", None)
            assert await cache._fetch_from_github_advisory("pkg", Ecosystem.PYPI) == []

    @pytest.mark.asyncio
    @patch.dict(os.environ, {"GITHUB_ADVISORY_TOKEN": "ghp_test"}, clear=False)
    async def test_osv_empty_triggers_advisory_fallback(self, db_path):
        cache = CVECache(db_path=db_path)

        mock_osv = MagicMock()
        mock_osv.query_vulns = AsyncMock(return_value=[])
        mock_osv.__aenter__ = AsyncMock(return_value=mock_osv)
        mock_osv.__aexit__ = AsyncMock(return_value=None)

        mock_client = MagicMock()
        mock_client.query_advisories = AsyncMock(return_value=[
            {
                "ghsa_id": "GHSA-abc",
                "cve_id": "CVE-2024-0002",
                "summary": "advisory hit",
                "severity": "HIGH",
                "references": ["https://example.com/adv"],
                "vulnerabilities": [],
            }
        ])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch(
            "src.storage.cve_cache.OSVClient",
            return_value=mock_osv,
        ), patch(
            "src.storage.github_advisory.GitHubAdvisoryClient",
            return_value=mock_client,
        ):
            vulns = await cache._fetch_from_osv("pkg", "1.0.0", Ecosystem.PYPI)

        assert len(vulns) == 1
        assert vulns[0]["cve_id"] == "CVE-2024-0002"
        assert vulns[0]["evidence_source"] == "GitHub Advisory"
        assert vulns[0]["package_name"] == "pkg"
