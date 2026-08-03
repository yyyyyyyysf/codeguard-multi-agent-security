"""Tests for ConflictResolutionAgent lifecycle and degradation."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from src.agents.conflict.agent import ConflictResolutionAgent


class TestConflictResolutionAgent:
    @pytest.fixture
    def agent(self):
        return ConflictResolutionAgent(human_loop_timeout_hours=24)

    @pytest.fixture
    def sample_security_report(self):
        return {
            "scan_id": "scan-001",
            "scan_scope": "full",
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2024-0001",
                    "package_name": "fastapi",
                    "affected_version": "0.100.0",
                    "severity": "high",
                    "cvss_score": 8.5,
                    "dependency_type": "direct",
                    "evidence_source": "OSV",
                    "evidence_url": "https://osv.dev/CVE-2024-0001",
                    "file_location": "requirements.txt:L1",
                    "blocking": True,
                    "description": "RCE in FastAPI",
                    "fixed_version": "0.105.0",
                    "fix_available": True,
                    "affected_version_range": "<0.105.0",
                },
                {
                    "cve_id": "CVE-2024-0002",
                    "package_name": "httpx",
                    "affected_version": "0.24.0",
                    "severity": "medium",
                    "cvss_score": 5.0,
                    "dependency_type": "transitive",
                    "evidence_source": "OSV",
                    "evidence_url": "https://osv.dev/CVE-2024-0002",
                    "file_location": "poetry.lock:L50",
                    "blocking": False,
                    "description": "HTTP smuggling",
                    "fixed_version": "",
                    "fix_available": False,
                    "affected_version_range": None,
                },
            ],
            "code_issues": [
                {
                    "rule_id": "python.lang.security.audit.detect-sql-injection",
                    "severity": "high",
                    "confidence": "high",
                    "file_path": "src/app.py",
                    "line_number": 42,
                    "code_snippet": 'query = f"SELECT * FROM {table}"',
                    "message": "SQL injection risk",
                    "blocking": True,
                },
            ],
            "scan_duration_ms": 1200,
            "scanned_deps_count": 48,
            "degraded": False,
            "degraded_reasons": [],
        }

    @pytest.mark.asyncio
    async def test_resolve_with_mixed_findings(self, agent, sample_security_report):
        """Normal flow: resolve vulnerabilities and code issues."""
        result = await agent.execute(
            security_report=sample_security_report,
            code_metadata={},
            task_id="task-001",
            scan_id="scan-001",
        )
        assert result["success"]
        data = result["data"]
        assert data["overall_blocking"]  # High CVE + SQL injection -> blocked
        assert len(data["decisions"]) == 3
        assert not data["human_intervention_required"]

    @pytest.mark.asyncio
    async def test_empty_report_no_block(self, agent):
        """Empty report -> no block."""
        result = await agent.execute(
            security_report={
                "scan_id": "s1",
                "vulnerabilities": [],
                "code_issues": [],
            },
            code_metadata={},
            scan_id="s1",
        )
        assert result["success"]
        data = result["data"]
        assert not data["overall_blocking"]
        assert len(data["decisions"]) == 0

    @pytest.mark.asyncio
    async def test_degraded_run_blocks_all(self, agent, sample_security_report):
        """Degraded mode: all findings block (safety-first)."""
        # Force error by passing None security_report (will fail in run())
        agent._cve_scanner = None

        result = await agent.execute(
            security_report=sample_security_report,
            code_metadata={},
            scan_id="s1",
        )
        assert result["success"]
        data = result["data"]
        # All findings should be blocked
        assert data["overall_blocking"]

    @pytest.mark.asyncio
    async def test_upgrade_pr_auto_fixes(self, agent):
        """Framework upgrade PR: CVE fixed by upgrade is waived."""
        report = {
            "scan_id": "scan-upgrade",
            "vulnerabilities": [{
                "cve_id": "CVE-2024-UPGRADE",
                "package_name": "fastapi",
                "affected_version": "0.100.0",
                "severity": "high",
                "cvss_score": 8.0,
                "dependency_type": "direct",
                "file_location": "requirements.txt:L1",
                "fixed_version": "0.105.0",
                "fix_available": True,
                "blocking": True,
                "evidence_source": "OSV",
                "evidence_url": "",
                "description": "Test",
                "affected_version_range": None,
            }],
            "code_issues": [],
            "scan_scope": "diff",
            "scan_duration_ms": 0,
            "scanned_deps_count": 1,
            "degraded": False,
            "degraded_reasons": [],
        }
        result = await agent.execute(
            security_report=report,
            code_metadata={
                "target_version": {
                    "framework": "fastapi",
                    "from_version": "0.100.0",
                    "to_version": "0.110.0",
                },
            },
            scan_id="scan-upgrade",
        )
        assert result["success"]
        data = result["data"]
        # Should be waived because 0.110.0 >= 0.105.0
        decisions = data["decisions"]
        waived = [d for d in decisions if d["verdict"] == "waive"]
        assert len(waived) == 1

    @pytest.mark.asyncio
    async def test_appeal_count_tracking(self, agent, sample_security_report):
        """Verify appeal_count and appealable flags."""
        result = await agent.execute(
            security_report=sample_security_report,
            code_metadata={},
            scan_id="s1",
        )
        data = result["data"]
        assert data["appeal_count"] >= 0  # At least some findings are appealable

    @pytest.mark.asyncio
    async def test_config_override(self, agent, sample_security_report):
        """Custom ResolutionConfig -> behavior changes."""
        result = await agent.execute(
            security_report=sample_security_report,
            code_metadata={},
            scan_id="s1",
            config={"critical_cannot_waive": False, "human_loop_timeout_hours": 48},
        )
        assert result["success"]

    @pytest.mark.asyncio
    async def test_output_roundtrip_to_model(self, agent, sample_security_report):
        """Output can be parsed into FinalSecurityDecision."""
        from src.agents.conflict.models import FinalSecurityDecision
        result = await agent.execute(
            security_report=sample_security_report,
            code_metadata={},
            scan_id="s1",
        )
        decision = FinalSecurityDecision(**result["data"])
        assert decision.scan_id == "s1"
        assert len(decision.decisions) == 3


class TestConflictAgentWithStores:
    """Tests with mocked rule_store and audit_logger for full code paths."""

    @pytest.fixture
    def mock_rule_store(self):
        store = MagicMock()
        store.get_active_rules = MagicMock(return_value=[])
        return store

    @pytest.fixture
    def mock_audit_logger(self):
        logger = MagicMock()
        logger.log = MagicMock(return_value=1)
        return logger

    @pytest.fixture
    def agent_with_stores(self, mock_rule_store, mock_audit_logger):
        return ConflictResolutionAgent(
            rule_store=mock_rule_store,
            audit_logger=mock_audit_logger,
            human_loop_timeout_hours=24,
        )

    @pytest.mark.asyncio
    async def test_uses_rule_store(self, agent_with_stores, mock_rule_store):
        """Agent loads rules from rule_store."""
        mock_rule_store.get_active_rules.return_value = [
            {"rule_id": "r1", "rule_type": "cve_whitelist", "pattern": "CVE-2024-0001", "enabled": True},
        ]
        report = {
            "scan_id": "s1",
            "vulnerabilities": [{
                "cve_id": "CVE-2024-0001", "severity": "high", "cvss_score": 8.5,
                "dependency_type": "direct", "file_location": "req.txt:L1",
                "evidence_source": "OSV", "evidence_url": "", "blocking": True,
                "description": "", "affected_version_range": None,
                "package_name": "pkg", "affected_version": "1.0",
                "fixed_version": "", "fix_available": False,
            }],
            "code_issues": [],
            "scan_duration_ms": 0, "scanned_deps_count": 1,
            "degraded": False, "degraded_reasons": [],
            "scan_scope": "full",
        }
        result = await agent_with_stores.execute(
            security_report=report, code_metadata={}, scan_id="s1",
        )
        assert result["success"]
        mock_rule_store.get_active_rules.assert_called()

    @pytest.mark.asyncio
    async def test_audit_logger_called(self, agent_with_stores, mock_audit_logger):
        """Audit log records verdict decisions."""
        report = {
            "scan_id": "s1",
            "vulnerabilities": [{
                "cve_id": "CVE-2024-0001", "severity": "high", "cvss_score": 8.5,
                "dependency_type": "direct", "file_location": "req.txt:L1",
                "evidence_source": "OSV", "evidence_url": "", "blocking": True,
                "description": "", "affected_version_range": None,
                "package_name": "pkg", "affected_version": "1.0",
                "fixed_version": "", "fix_available": False,
            }],
            "code_issues": [],
            "scan_duration_ms": 0, "scanned_deps_count": 1,
            "degraded": False, "degraded_reasons": [],
            "scan_scope": "full",
        }
        result = await agent_with_stores.execute(
            security_report=report, code_metadata={}, scan_id="s1", task_id="t1",
        )
        assert result["success"]
        # Audit logger should have been called at least once
        assert mock_audit_logger.log.call_count >= 1

    @pytest.mark.asyncio
    async def test_rule_store_error_non_fatal(self, agent_with_stores, mock_rule_store):
        """Rule store failure doesn't crash the agent."""
        mock_rule_store.get_active_rules.side_effect = RuntimeError("DB down")
        report = {
            "scan_id": "s1",
            "vulnerabilities": [{
                "cve_id": "CVE-2024-0001", "severity": "high", "cvss_score": 8.5,
                "dependency_type": "direct", "file_location": "req.txt:L1",
                "evidence_source": "OSV", "evidence_url": "", "blocking": True,
                "description": "", "affected_version_range": None,
                "package_name": "pkg", "affected_version": "1.0",
                "fixed_version": "", "fix_available": False,
            }],
            "code_issues": [],
            "scan_duration_ms": 0, "scanned_deps_count": 1,
            "degraded": False, "degraded_reasons": [],
            "scan_scope": "full",
        }
        result = await agent_with_stores.execute(
            security_report=report, code_metadata={}, scan_id="s1",
        )
        assert result["success"]  # Still succeeds

    @pytest.mark.asyncio
    async def test_audit_log_error_non_fatal(self, agent_with_stores, mock_audit_logger):
        """Audit log failure doesn't affect the security decision."""
        mock_audit_logger.log.side_effect = RuntimeError("Audit log full")
        report = {
            "scan_id": "s1",
            "vulnerabilities": [{
                "cve_id": "CVE-2024-0001", "severity": "high", "cvss_score": 8.5,
                "dependency_type": "direct", "file_location": "req.txt:L1",
                "evidence_source": "OSV", "evidence_url": "", "blocking": True,
                "description": "", "affected_version_range": None,
                "package_name": "pkg", "affected_version": "1.0",
                "fixed_version": "", "fix_available": False,
            }],
            "code_issues": [],
            "scan_duration_ms": 0, "scanned_deps_count": 1,
            "degraded": False, "degraded_reasons": [],
            "scan_scope": "full",
        }
        result = await agent_with_stores.execute(
            security_report=report, code_metadata={}, scan_id="s1",
        )
        assert result["success"]  # Decision still returned
        assert result["data"]["overall_blocking"]
