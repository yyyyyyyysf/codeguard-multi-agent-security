"""Tests for SecurityAuditAgent execution and degradation."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.agents.security.agent import SecurityAuditAgent
from src.agents.security.models import SecurityReport


class TestSecurityAuditAgent:
    """Test the SecurityAuditAgent lifecycle and core logic."""

    @pytest.fixture
    def agent(self):
        """Create agent with mocked scanners."""
        agent = SecurityAuditAgent()
        agent._cve_scanner = MagicMock()
        agent._code_scanner = MagicMock()
        return agent

    @pytest.fixture
    def sample_code_metadata(self):
        return {
            "dependencies": [
                {"name": "fastapi", "version": "0.100.0", "ecosystem": "pypi"},
                {"name": "requests", "version": "2.28.0", "ecosystem": "pypi"},
            ],
            "transitive_deps": [],
            "changed_files": [
                {
                    "path": "requirements.txt",
                    "content": "fastapi==0.100.0\nrequests==2.28.0\n",
                    "language": "python",
                    "file_size": 100,
                },
                {
                    "path": "src/main.py",
                    "content": "from fastapi import FastAPI\napp = FastAPI()\n",
                    "language": "python",
                    "file_size": 200,
                },
            ],
            "language": "python",
            "repo_path": "/tmp/test_repo",
        }

    @pytest.mark.asyncio
    async def test_agent_execute_with_findings(self, agent, sample_code_metadata):
        """Normal execution: both scanners return results."""
        # Mock CVE scanner
        agent._cve_scanner.scan = AsyncMock(return_value=(
            [{
                "cve_id": "CVE-2024-0001",
                "package_name": "fastapi",
                "affected_version": "0.100.0",
                "severity": "high",
                "cvss_score": 8.5,
                "dependency_type": "direct",
                "evidence_source": "OSV",
                "evidence_url": "https://osv.dev/CVE-2024-0001",
                "file_location": "",
                "blocking": True,
                "description": "RCE in FastAPI <0.105.0",
                "fixed_version": "0.105.0",
                "fix_available": True,
                "affected_version_range": "<0.105.0",
            }],
            False,
            "",
        ))
        agent._cve_scanner.annotate_file_locations = MagicMock(
            side_effect=lambda vulns, deps_map: vulns
        )

        # Mock code scanner
        agent._code_scanner.scan = AsyncMock(return_value=([], False, ""))

        result = await agent.execute(
            code_metadata=sample_code_metadata,
            scan_scope="full",
            scan_id="test-scan-001",
        )

        assert result["success"]
        assert not result["degraded"]
        data = result["data"]
        assert len(data["vulnerabilities"]) == 1
        assert data["vulnerabilities"][0]["cve_id"] == "CVE-2024-0001"
        assert data["vulnerabilities"][0]["blocking"]

    @pytest.mark.asyncio
    async def test_agent_cve_scan_degraded(self, agent, sample_code_metadata):
        """CVE scan degraded but code scan succeeds."""
        agent._cve_scanner.scan = AsyncMock(return_value=(
            [],
            True,
            "OSV API unavailable; using local cache",
        ))
        agent._cve_scanner.annotate_file_locations = MagicMock(
            side_effect=lambda vulns, deps_map: vulns
        )
        agent._code_scanner.scan = AsyncMock(return_value=([], False, ""))

        result = await agent.execute(
            code_metadata=sample_code_metadata,
            scan_scope="full",
            scan_id="test-scan-002",
        )

        assert result["success"]
        assert result["degraded"]
        assert "CVE scan degraded" in result["degraded_reasons"][0]

    @pytest.mark.asyncio
    async def test_agent_degraded_run_fallback(self, agent, sample_code_metadata):
        """When run() raises, degraded_run() produces a best-effort report."""
        agent._cve_scanner.scan = AsyncMock(
            side_effect=RuntimeError("Redis connection refused")
        )

        result = await agent.execute(
            code_metadata=sample_code_metadata,
            scan_scope="full",
            scan_id="test-scan-003",
        )

        assert result["success"]  # Degraded but not failed
        assert result["degraded"]
        assert "Redis connection refused" in result["degraded_reasons"][0]

    @pytest.mark.asyncio
    async def test_empty_dependencies(self, agent):
        """No dependencies to scan -> empty report."""
        agent._cve_scanner.scan = AsyncMock(return_value=([], False, ""))
        agent._cve_scanner.annotate_file_locations = MagicMock(return_value=[])
        agent._code_scanner.scan = AsyncMock(return_value=([], False, ""))

        result = await agent.execute(
            code_metadata={
                "dependencies": [],
                "transitive_deps": [],
                "changed_files": [],
                "language": "python",
                "repo_path": "/tmp/test",
            },
            scan_scope="full",
            scan_id="test-scan-004",
        )

        assert result["success"]
        data = result["data"]
        assert len(data["vulnerabilities"]) == 0
        assert len(data["code_issues"]) == 0
        assert data.get("degraded") is False

    @pytest.mark.asyncio
    async def test_agent_output_is_valid_security_report(self, agent, sample_code_metadata):
        """The output dict is valid for SecurityReport construction."""
        agent._cve_scanner.scan = AsyncMock(return_value=(
            [{
                "cve_id": "CVE-2024-0001",
                "package_name": "fastapi",
                "affected_version": "0.100.0",
                "severity": "high",
                "cvss_score": 8.5,
                "dependency_type": "direct",
                "evidence_source": "OSV",
                "file_location": "requirements.txt:L1",
                "blocking": True,
                "description": "Test",
                "evidence_url": "",
                "fixed_version": "0.105.0",
                "fix_available": True,
                "affected_version_range": "<0.105.0",
            }],
            False,
            "",
        ))
        agent._cve_scanner.annotate_file_locations = MagicMock(
            side_effect=lambda vulns, deps_map: vulns
        )
        agent._code_scanner.scan = AsyncMock(return_value=([], False, ""))

        result = await agent.execute(
            code_metadata=sample_code_metadata,
            scan_scope="full",
            scan_id="test-scan-005",
        )

        # Should construct without validation errors
        report = SecurityReport(**result["data"])
        assert report.scan_id == "test-scan-005"
        assert len(report.vulnerabilities) == 1

    @pytest.mark.asyncio
    async def test_scan_config_can_disable_cve(self, agent, sample_code_metadata):
        """scan_config.enable_cve_scan=False skips CVE."""
        agent._code_scanner.scan = AsyncMock(return_value=([], False, ""))

        result = await agent.execute(
            code_metadata=sample_code_metadata,
            scan_scope="full",
            scan_id="test-scan-006",
            scan_config={"enable_cve_scan": False},
        )

        assert result["success"]
        agent._cve_scanner.scan.assert_not_called()
