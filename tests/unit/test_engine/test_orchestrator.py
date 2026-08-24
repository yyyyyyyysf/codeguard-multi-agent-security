"""Tests for the Orchestrator — agent registry + full pipeline wiring."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.models import ScanScope
from src.engine.orchestrator import Orchestrator


class TestOrchestrator:
    def _make_agent(self, name, data):
        agent = MagicMock()
        agent.agent_id = name
        result = {"data": data}
        agent.execute = AsyncMock(return_value=result)
        return agent

    @pytest.mark.asyncio
    async def test_register_and_get_agent(self):
        orch = Orchestrator()
        agent = MagicMock()
        orch.register_agent("security", agent)
        assert orch.get_agent("security") is agent
        assert orch.get_agent("missing") is None

    @pytest.mark.asyncio
    async def test_run_analysis_full_pipeline(self):
        orch = Orchestrator(redis_client=None)
        security = self._make_agent(
            "security",
            {"vulnerabilities": [{"cve_id": "CVE-1", "blocking": True}]},
        )
        conflict = self._make_agent("conflict", {"overall_blocking": True})
        migration = self._make_agent("migration", {"framework": "fastapi"})
        reporter = self._make_agent(
            "reporter",
            {"summary": {"blocking_count": 1}, "pr_comment_markdown": "## ok"},
        )
        for name, agent in [
            ("security", security),
            ("conflict", conflict),
            ("migration", migration),
            ("reporter", reporter),
        ]:
            orch.register_agent(name, agent)

        report = await orch.run_analysis(
            task_id="t1",
            scan_id="t1",
            repo_url="https://github.com/x/y",
            code_metadata={"dependencies": [], "changed_files": []},
            scan_scope=ScanScope.FULL,
            target_version={"framework": "fastapi", "from_version": "1", "to_version": "2"},
            scan_config={"block_severity": "high"},
        )

        assert report["status"] == "completed"
        assert report["aggregated"]["summary"]["blocking_count"] == 1
        security.execute.assert_awaited_once()
        conflict.execute.assert_awaited_once()
        migration.execute.assert_awaited_once()
        reporter.execute.assert_awaited_once()

        # scan_config must be forwarded to the security agent.
        security_kwargs = security.execute.await_args.kwargs
        assert security_kwargs["scan_config"] == {"block_severity": "high"}

    @pytest.mark.asyncio
    async def test_run_analysis_missing_agents_errors(self):
        orch = Orchestrator()
        report = await orch.run_analysis(
            task_id="t1",
            scan_id="t1",
            repo_url="https://github.com/x/y",
            code_metadata={},
        )
        assert "error" in report
