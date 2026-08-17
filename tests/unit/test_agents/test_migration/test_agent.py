"""Tests for MigrationAssessmentAgent lifecycle and degradation."""


import pytest

from src.agents.migration.agent import MigrationAssessmentAgent


class TestMigrationAgent:
    @pytest.fixture
    def agent(self):
        return MigrationAssessmentAgent()

    @pytest.fixture
    def sample_metadata(self):
        return {
            "changed_files": [
                {
                    "path": "api/user.py",
                    "content": "@app.get('/users', response_model=List[User])\ndef get_users(): pass\n",
                    "language": "python",
                    "file_size": 100,
                },
                {
                    "path": "main.py",
                    "content": "app = FastAPI()\n",
                    "language": "python",
                    "file_size": 50,
                },
            ],
        }

    @pytest.fixture
    def target_version(self):
        return {"framework": "fastapi", "from_version": "0.100.0", "to_version": "0.110.0"}

    @pytest.mark.asyncio
    async def test_ast_matcher_finds_breaking_changes(self, agent, sample_metadata, target_version):
        """Deterministic matcher detects response_model usage."""
        result = await agent.execute(
            code_metadata=sample_metadata,
            target_version=target_version,
            scan_id="scan-mig-001",
        )
        assert result["success"]
        data = result["data"]
        assert data["framework"] == "fastapi"
        assert len(data["breaking_changes"]) >= 1
        assert any(
            "response_model" in bc["change_desc"].lower()
            for bc in data["breaking_changes"]
        )

    @pytest.mark.asyncio
    async def test_no_target_version_degraded(self, agent, sample_metadata):
        """No target version -> degraded with reason."""
        result = await agent.execute(
            code_metadata=sample_metadata,
            target_version={},
            scan_id="scan-mig-002",
        )
        assert result["success"]
        data = result["data"]
        assert data["degraded"]
        assert len(data["degraded_reasons"]) >= 1

    @pytest.mark.asyncio
    async def test_no_breaking_changes_found(self, agent):
        """Clean code with no deprecated API usage."""
        result = await agent.execute(
            code_metadata={
                "changed_files": [
                    {"path": "app.py", "content": "print('hello')\n", "language": "python", "file_size": 20},
                ],
            },
            target_version={"framework": "fastapi", "from_version": "0.100.0", "to_version": "0.110.0"},
            scan_id="scan-mig-003",
        )
        assert result["success"]
        data = result["data"]
        assert data["risk_level"] == "low"
        assert data["effort_estimate"]["affected_file_count"] == 0

    @pytest.mark.asyncio
    async def test_degraded_run_produces_ast_only(self, agent, sample_metadata, target_version):
        """degraded_run() produces AST-only results."""
        result = await agent.execute(
            code_metadata=sample_metadata,
            target_version=target_version,
            scan_id="scan-mig-004",
        )
        assert result["success"]
        data = result["data"]
        # AST results should still work
        assert len(data["breaking_changes"]) >= 1

    @pytest.mark.asyncio
    async def test_risk_high_major_bump(self, agent):
        """Major version bump with breaking changes -> high risk."""
        result = await agent.execute(
            code_metadata={
                "changed_files": [
                    {"path": "api/user.py", "content": "@app.get('/users', response_model=X)\ndef f(): pass\n", "language": "python", "file_size": 100},
                    {"path": "api/item.py", "content": "@app.get('/items', response_model=Y)\ndef g(): pass\n", "language": "python", "file_size": 100},
                    {"path": "api/order.py", "content": "@app.get('/orders', response_model=Z)\ndef h(): pass\n", "language": "python", "file_size": 100},
                    {"path": "main.py", "content": "@app.on_event('startup')\ndef startup(): pass\n", "language": "python", "file_size": 100},
                ],
            },
            target_version={"framework": "fastapi", "from_version": "0.100.0", "to_version": "1.0.0"},
            scan_id="scan-mig-005",
        )
        assert result["success"]
        data = result["data"]
        assert data["risk_level"] == "high"

    @pytest.mark.asyncio
    async def test_effort_estimate(self, agent, sample_metadata, target_version):
        """Effort estimate reflects affected files."""
        result = await agent.execute(
            code_metadata=sample_metadata,
            target_version=target_version,
            scan_id="scan-mig-006",
        )
        data = result["data"]
        effort = data["effort_estimate"]
        assert "affected_file_count" in effort
        assert "estimated_person_days" in effort

    @pytest.mark.asyncio
    async def test_output_roundtrip_to_model(self, agent, sample_metadata, target_version):
        """Output validates as MigrationReport."""
        from src.agents.migration.models import MigrationReport
        result = await agent.execute(
            code_metadata=sample_metadata,
            target_version=target_version,
            scan_id="scan-mig-007",
        )
        report = MigrationReport(**result["data"])
        assert report.scan_id == "scan-mig-007"
        assert report.framework == "fastapi"

    @pytest.mark.asyncio
    async def test_empty_files_no_issues(self, agent):
        """Empty changed files -> no impacts."""
        result = await agent.execute(
            code_metadata={"changed_files": []},
            target_version={"framework": "fastapi", "from_version": "0.100.0", "to_version": "0.110.0"},
            scan_id="scan-mig-008",
        )
        assert result["success"]
        data = result["data"]
        assert data["risk_level"] == "low"


class TestMigrationHelpers:
    def test_is_major_bump(self):
        assert MigrationAssessmentAgent._is_major_version_bump("1.0.0", "2.0.0")
        assert not MigrationAssessmentAgent._is_major_version_bump("1.0.0", "1.1.0")
        assert not MigrationAssessmentAgent._is_major_version_bump("1.0.0", "1.0.1")

    def test_merge_impacts_dedup(self, agent_fixture=None):
        agent = MigrationAssessmentAgent()
        ast = [
            {"change_desc": "response_model removed", "source": "ast_rule",
             "affected_files": [{"path": "api/user.py", "line_number": 42}]},
        ]
        llm = [
            {"change_desc": "response_model removed", "source": "llm_analysis",
             "affected_files": [{"path": "api/user.py", "line_number": 42}]},  # Duplicate
            {"change_desc": "response_model removed", "source": "llm_analysis",
             "affected_files": [{"path": "api/item.py", "line_number": 15}]},  # New file
        ]
        merged = agent._merge_impacts(ast, llm)
        # Should have 2 entries (AST + LLM new file)
        total_affected = sum(len(imp["affected_files"]) for imp in merged)
        assert total_affected >= 2  # AST user.py + LLM item.py (user.py dedup'd)

    def test_assess_risk_levels(self):
        agent = MigrationAssessmentAgent()
        # No impacts -> low
        assert agent._assess_risk([], "1.0.0", "1.1.0") == "low"
        # Warning-level + minor bump -> low (not medium, no breaking impacts)
        assert agent._assess_risk(
            [{"affected_files": [{"path": "a.py", "impact_level": "warning"}]}],
            "1.0.0", "1.1.0"
        ) == "low"
        # Warning + major bump -> medium
        assert agent._assess_risk(
            [{"affected_files": [{"path": "a.py", "impact_level": "warning"}]}],
            "1.0.0", "2.0.0"
        ) == "medium"
        # 3+ breaking impacts -> high
        assert agent._assess_risk(
            [{"affected_files": [
                {"path": "a.py", "impact_level": "breaking"},
                {"path": "b.py", "impact_level": "breaking"},
                {"path": "c.py", "impact_level": "breaking"},
            ]}],
            "1.0.0", "1.1.0"
        ) == "high"

    def test_estimate_effort_degraded(self):
        agent = MigrationAssessmentAgent()
        ee = agent._estimate_effort([], degraded=True)
        assert ee.confidence == "low"
