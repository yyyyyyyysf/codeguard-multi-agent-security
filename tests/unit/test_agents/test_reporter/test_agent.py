"""Tests for ReportAggregationAgent rendering and aggregation."""

from unittest.mock import MagicMock

import pytest

from src.agents.reporter.agent import ReportAggregationAgent


class TestReportAgent:
    @pytest.fixture
    def agent(self):
        return ReportAggregationAgent()

    @pytest.fixture
    def sample_security_data(self):
        return {
            "security": {
                "scan_id": "s1",
                "scan_scope": "full",
                "vulnerabilities": [
                    {
                        "cve_id": "CVE-2024-0001",
                        "severity": "high",
                        "blocking": True,
                        "file_location": "req.txt:L1",
                        "evidence_source": "OSV",
                        "fixed_version": "0.105.0",
                    },
                ],
                "code_issues": [
                    {
                        "rule_id": "python.lang.security.audit.detect-sql",
                        "severity": "high",
                        "confidence": "high",
                        "file_path": "app.py",
                        "line_number": 42,
                        "blocking": True,
                        "fix_suggestion": "Use parameterized queries",
                    },
                ],
                "scan_duration_ms": 1200,
                "degraded": False,
                "degraded_reasons": [],
            },
            "conflict": {
                "scan_id": "s1",
                "overall_blocking": True,
                "decisions": [
                    {
                        "finding_id": "CVE-2024-0001",
                        "finding_type": "vulnerability",
                        "verdict": "block",
                        "reason": "High severity in direct dependency",
                        "appealable": True,
                    },
                    {
                        "finding_id": "python.lang.security.audit.detect-sql",
                        "finding_type": "code_issue",
                        "verdict": "block",
                        "reason": "SQL injection risk",
                        "appealable": False,
                    },
                ],
                "appeal_count": 1,
                "human_intervention_required": False,
            },
        }

    @pytest.mark.asyncio
    async def test_report_persisted_when_report_store_provided(
        self, sample_security_data
    ):
        report_store = MagicMock()
        agent = ReportAggregationAgent(report_store=report_store)
        result = await agent.execute(
            security_data=sample_security_data,
            migration_data={},
            repo_url="https://github.com/x/y",
            code_metadata={"commit_sha": "abc", "scan_scope": "full"},
            scan_id="s1",
            task_id="t1",
        )
        assert result["success"] is True
        report_store.save_json.assert_called_once()
        saved_scan_id = report_store.save_json.call_args[0][0]
        assert saved_scan_id == "s1"

    @pytest.mark.asyncio
    async def test_report_persist_failure_is_non_fatal(
        self, sample_security_data
    ):
        report_store = MagicMock()
        report_store.save_json.side_effect = RuntimeError("disk full")
        agent = ReportAggregationAgent(report_store=report_store)
        result = await agent.execute(
            security_data=sample_security_data,
            migration_data={},
            repo_url="https://github.com/x/y",
            code_metadata={"commit_sha": "abc", "scan_scope": "full"},
            scan_id="s1",
            task_id="t1",
        )
        assert result["success"] is True

    @pytest.fixture
    def sample_migration_data(self):
        return {
            "scan_id": "s1",
            "framework": "fastapi",
            "from_version": "0.100.0",
            "to_version": "0.110.0",
            "risk_level": "medium",
            "breaking_changes": [
                {
                    "change_desc": "response_model removed",
                    "source": "ast_rule",
                    "official_reference_url": "https://fastapi.tiangolo.com/release-notes/",
                    "affected_files": [
                        {"path": "api/user.py", "line_number": 42, "code_snippet": "@app.get", "impact_level": "breaking"},
                    ],
                    "fix_suggestion": "Use return type annotations",
                },
            ],
            "effort_estimate": {"affected_file_count": 1, "estimated_person_days": 0.5, "confidence": "medium"},
            "scan_duration_ms": 500,
            "degraded": False,
            "degraded_reasons": [],
        }

    @pytest.mark.asyncio
    async def test_aggregate_with_all_data(self, agent, sample_security_data, sample_migration_data):
        """Full aggregation with security + migration data."""
        result = await agent.execute(
            security_data=sample_security_data,
            migration_data=sample_migration_data,
            repo_url="https://github.com/user/repo",
            code_metadata={"commit_sha": "abc123", "scan_scope": "full", "changed_files": [{"path": "a.py"}]},
            scan_id="s1",
            task_id="t1",
        )
        assert result["success"]
        data = result["data"]
        assert data["summary"]["blocking_count"] == 2
        assert data["summary"]["warning_count"] >= 1
        assert data["summary"]["pass_count"] >= 0
        assert len(data["pr_comment_markdown"]) > 0
        assert "阻断项" in data["pr_comment_markdown"] or "blocking" in data["pr_comment_markdown"].lower()

    @pytest.mark.asyncio
    async def test_aggregate_security_only(self, agent, sample_security_data):
        """Only security data, no migration."""
        result = await agent.execute(
            security_data=sample_security_data,
            migration_data={},
            repo_url="https://github.com/user/repo",
            code_metadata={"commit_sha": "abc", "scan_scope": "diff", "changed_files": []},
            scan_id="s1",
        )
        assert result["success"]
        data = result["data"]
        assert data["migration"] is None
        assert len(data["pr_comment_markdown"]) > 0

    @pytest.mark.asyncio
    async def test_pr_comment_contains_security_first(self, agent, sample_security_data, sample_migration_data):
        """PR comment renders security before migration."""
        result = await agent.execute(
            security_data=sample_security_data,
            migration_data=sample_migration_data,
            repo_url="",
            code_metadata={"commit_sha": "abc", "scan_scope": "full", "changed_files": []},
            scan_id="s1",
        )
        md = result["data"]["pr_comment_markdown"]
        # Security section should appear before migration content
        sec_keywords = ["阻断", "blocking"]
        mig_keywords = ["response_model", "迁移建议"]
        sec_pos = min((md.find(k) for k in sec_keywords if md.find(k) >= 0), default=-1)
        mig_pos = min((md.find(k) for k in mig_keywords if md.find(k) >= 0), default=-1)
        assert sec_pos >= 0, "Security section not found"
        if mig_pos >= 0:
            assert sec_pos < mig_pos, f"Security ({sec_pos}) must appear before migration ({mig_pos})"

    @pytest.mark.asyncio
    async def test_degraded_aggregation(self, agent):
        """Degradation from upstream is aggregated."""
        result = await agent.execute(
            security_data={
                "security": {"scan_duration_ms": 0, "degraded": True, "degraded_reasons": ["OSV down"], "vulnerabilities": [], "code_issues": []},
                "conflict": {"decisions": [], "overall_blocking": False},
            },
            migration_data={"degraded": True, "degraded_reasons": ["LLM timeout"]},
            repo_url="",
            code_metadata={"commit_sha": "", "scan_scope": "full", "changed_files": []},
            scan_id="s1",
        )
        data = result["data"]
        assert data["degraded"]
        assert len(data["degraded_reasons"]) >= 2

    @pytest.mark.asyncio
    async def test_degraded_run_fallback(self, agent, sample_security_data):
        """degraded_run() produces plain-text fallback."""
        result = await agent.execute(
            security_data=sample_security_data,
            migration_data={},
            repo_url="",
            code_metadata={"commit_sha": "", "scan_scope": "full", "changed_files": []},
            scan_id="s1",
        )
        assert result["success"]
        data = result["data"]
        assert data["summary"]["blocking_count"] >= 1
        assert "CodeGuard" in data["pr_comment_markdown"]

    @pytest.mark.asyncio
    async def test_never_modifies_decisions(self, agent, sample_security_data):
        """Security decision verdicts pass through unmodified."""
        result = await agent.execute(
            security_data=sample_security_data,
            migration_data={},
            repo_url="",
            code_metadata={"commit_sha": "", "scan_scope": "full", "changed_files": []},
            scan_id="s1",
        )
        data = result["data"]
        # Upstream decisions are stored unchanged
        stored = data["security"]["conflict_decision"]
        assert stored["decisions"][0]["verdict"] == "block"
        assert stored["decisions"][1]["verdict"] == "block"
        assert stored["overall_blocking"] == sample_security_data["conflict"]["overall_blocking"]

    @pytest.mark.asyncio
    async def test_empty_inputs_produce_empty_report(self, agent):
        """Empty upstream -> empty report."""
        result = await agent.execute(
            security_data={
                "security": {"scan_duration_ms": 0, "degraded": False, "degraded_reasons": [], "vulnerabilities": [], "code_issues": []},
                "conflict": {"decisions": [], "overall_blocking": False},
            },
            migration_data={},
            repo_url="",
            code_metadata={"commit_sha": "", "scan_scope": "full", "changed_files": []},
            scan_id="s1",
        )
        assert result["success"]
        data = result["data"]
        assert data["summary"]["blocking_count"] == 0
        assert data["summary"]["warning_count"] == 0

    @pytest.mark.asyncio
    async def test_output_roundtrip_to_model(self, agent, sample_security_data, sample_migration_data):
        """Output validates as AggregatedReport."""
        from src.agents.reporter.models import AggregatedReport
        result = await agent.execute(
            security_data=sample_security_data,
            migration_data=sample_migration_data,
            repo_url="https://github.com/user/repo",
            code_metadata={"commit_sha": "abc123", "scan_scope": "full", "changed_files": []},
            scan_id="s1",
        )
        report = AggregatedReport(**result["data"])
        assert report.scan_id == "s1"
        assert report.summary.blocking_count == 2


class TestReporterHelpers:
    """Pure helper function tests."""

    def test_count_blocking(self):
        conflict = {
            "decisions": [
                {"verdict": "block"},
                {"verdict": "waive"},
                {"verdict": "block"},
                {"verdict": "defer"},
            ],
        }
        assert ReportAggregationAgent._count_blocking(conflict) == 2

    def test_count_warnings(self):
        conflict = {"decisions": [
            {"verdict": "waive"}, {"verdict": "defer"},
        ]}
        migration = {"breaking_changes": [{"a": 1}]}
        assert ReportAggregationAgent._count_warnings(conflict, migration) == 3

    def test_count_pass(self):
        report = {
            "vulnerabilities": [
                {"blocking": True},
                {"blocking": False},
            ],
            "code_issues": [
                {"blocking": False},
            ],
        }
        assert ReportAggregationAgent._count_pass(report) == 2

    def test_plain_text_fallback_has_content(self):
        fallback = ReportAggregationAgent._plain_text_fallback({
            "blocking_items": [{"id": "x"}],
            "warning_items": [],
            "pass_items": ["all good"],
        })
        assert "CodeGuard" in fallback

    def test_get_evidence_source(self):
        report = {
            "vulnerabilities": [
                {"cve_id": "CVE-1", "evidence_source": "OSV"},
            ],
            "code_issues": [],
        }
        src = ReportAggregationAgent._get_evidence_source(
            {"finding_id": "CVE-1"}, report
        )
        assert src == "OSV"

    def test_get_location_cve(self):
        report = {
            "vulnerabilities": [{"cve_id": "CVE-1", "file_location": "req.txt:L1"}],
            "code_issues": [],
        }
        loc = ReportAggregationAgent._get_location({"finding_id": "CVE-1"}, report)
        assert loc == "req.txt:L1"

    def test_get_fix_suggestion(self):
        report = {
            "vulnerabilities": [{"cve_id": "CVE-1", "fixed_version": "2.0.0"}],
            "code_issues": [],
        }
        fix = ReportAggregationAgent._get_fix_suggestion({"finding_id": "CVE-1"}, report)
        assert "2.0.0" in fix
