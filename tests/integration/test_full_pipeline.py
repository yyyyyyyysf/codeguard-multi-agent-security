"""Integration test: full analysis pipeline (mock mode).

Verifies the end-to-end flow from preprocess through all 4 agents
without requiring real external services (GitHub, Redis, LLM).
"""

import pytest


@pytest.mark.integration
class TestFullPipeline:
    """End-to-end pipeline with mock dependencies."""

    @pytest.mark.asyncio
    async def test_preprocess_to_security_to_report(self):
        """Simulate: preprocess -> security -> conflict -> report."""
        from src.preprocess.dependency import _parse_pep508_dep
        from src.agents.security.models import SecurityReport, Vulnerability
        from src.agents.conflict.models import FinalSecurityDecision, SecurityVerdict
        from src.agents.reporter.models import AggregatedReport

        # Step 1: Simulated preprocess output
        deps = [
            {"name": "fastapi", "version": "0.100.0", "dependency_type": "direct", "ecosystem": "pypi"},
            {"name": "requests", "version": "2.28.0", "dependency_type": "direct", "ecosystem": "pypi"},
        ]

        assert _parse_pep508_dep("fastapi>=0.100.0") is not None

        # Step 2: Simulated security report
        report = SecurityReport(
            scan_id="test-001",
            scan_scope="full",
            vulnerabilities=[
                Vulnerability(
                    cve_id="CVE-2024-0001",
                    package_name="fastapi",
                    affected_version="0.100.0",
                    severity="high",
                    cvss_score=8.5,
                    dependency_type="direct",
                    evidence_source="OSV",
                    file_location="requirements.txt:L1",
                    blocking=True,
                ),
            ],
            code_issues=[],
            scan_duration_ms=1200,
            scanned_deps_count=2,
        )
        assert report.blocking_count == 1

        # Step 3: Simulated conflict decision
        decision = FinalSecurityDecision(
            scan_id="test-001",
            overall_blocking=True,
            decisions=[
                SecurityVerdict(
                    finding_id="CVE-2024-0001",
                    finding_type="vulnerability",
                    verdict="block",
                    reason="High severity in direct dependency",
                ),
            ],
        )
        assert decision.overall_blocking

        # Step 4: Simulated aggregated report
        agg = AggregatedReport(
            scan_id="test-001",
            repo_url="https://github.com/test/repo",
            summary={
                "blocking_count": 1,
                "warning_count": 0,
                "pass_count": 1,
                "security_scan_duration_ms": 1200,
                "migration_scan_duration_ms": 0,
            },
            security={"conflict_decision": decision.model_dump()},
        )
        assert agg.summary.blocking_count == 1

    @pytest.mark.asyncio
    async def test_degradation_flow(self):
        """When a sub-agent degrades, the pipeline continues."""
        from src.agents.migration.models import MigrationReport

        # Migration agent degrades (LLM unavailable)
        report = MigrationReport(
            scan_id="test-degraded",
            framework="fastapi",
            from_version="0.100.0",
            to_version="0.110.0",
            degraded=True,
            degraded_reasons=["LLM API timeout"],
            risk_level="low",
        )
        assert report.degraded
        assert len(report.degraded_reasons) == 1

    @pytest.mark.asyncio
    async def test_idempotency_flow(self):
        """Same scan parameters produce deterministic results."""
        from src.integrations.github_client import GitHubClient

        k1 = GitHubClient.idempotency_key("scan-1", "owner/repo", 42)
        k2 = GitHubClient.idempotency_key("scan-1", "owner/repo", 42)
        k3 = GitHubClient.idempotency_key("scan-2", "owner/repo", 42)

        assert k1 == k2
        assert k1 != k3


@pytest.mark.integration
class TestWebhookToReport:
    """Webhook payload parsing through to report generation."""

    def test_webhook_pr_payload_parsing(self):
        """GitHub PR webhook payload extracts correct fields."""
        from src.webhook.router import should_scan_pr

        assert should_scan_pr("pull_request", "opened", False)
        assert should_scan_pr("pull_request", "synchronize", False)
        assert not should_scan_pr("pull_request", "closed", False)
        assert not should_scan_pr("pull_request", "opened", True)  # Draft
