"""Tests for Migration Assessment Agent data models."""

import pytest
from src.agents.migration.models import (
    AffectedFile,
    BreakingChangeImpact,
    EffortEstimate,
    MigrationReport,
)


class TestAffectedFile:
    def test_minimal(self):
        af = AffectedFile(path="src/main.py", line_number=42)
        assert af.path == "src/main.py"
        assert af.impact_level == "warning"  # Default


class TestBreakingChangeImpact:
    def test_ast_rule_source(self):
        bc = BreakingChangeImpact(
            change_desc="response_model removed",
            source="ast_rule",
            official_reference_url="https://fastapi.tiangolo.com/release-notes/",
            affected_files=[AffectedFile(path="api/user.py", line_number=42)],
            fix_suggestion="Use return type annotations",
        )
        assert bc.source == "ast_rule"

    def test_llm_analysis_source(self):
        bc = BreakingChangeImpact(
            change_desc="on_event deprecated",
            source="llm_analysis",
            affected_files=[],
        )
        assert bc.source == "llm_analysis"


class TestEffortEstimate:
    def test_defaults(self):
        ee = EffortEstimate()
        assert ee.affected_file_count == 0
        assert ee.estimated_person_days == 0.0
        assert ee.confidence == "medium"


class TestMigrationReport:
    def test_empty_report(self):
        report = MigrationReport(
            scan_id="s1",
            framework="fastapi",
            from_version="0.100.0",
            to_version="0.110.0",
        )
        assert report.risk_level == "low"
        assert report.total_affected_files == 0
        assert report.ast_rule_count == 0
        assert report.llm_analysis_count == 0

    def test_mixed_sources(self):
        report = MigrationReport(
            scan_id="s1",
            framework="fastapi",
            from_version="0.100.0",
            to_version="0.110.0",
            breaking_changes=[
                BreakingChangeImpact(
                    change_desc="response_model removed",
                    source="ast_rule",
                    affected_files=[AffectedFile(path="api/user.py", line_number=42)],
                ),
                BreakingChangeImpact(
                    change_desc="on_event deprecated",
                    source="llm_analysis",
                    affected_files=[AffectedFile(path="main.py", line_number=10)],
                ),
            ],
        )
        assert report.ast_rule_count == 1
        assert report.llm_analysis_count == 1
        assert report.total_affected_files == 2
