"""Tests for Report Aggregation Agent data models."""

import pytest
from src.agents.reporter.models import AggregatedReport, ReportSummary


class TestReportSummary:
    def test_defaults(self):
        s = ReportSummary()
        assert s.blocking_count == 0
        assert s.warning_count == 0
        assert s.pass_count == 0


class TestAggregatedReport:
    def test_empty_report(self):
        report = AggregatedReport(scan_id="s1")
        assert report.scan_id == "s1"
        assert report.summary.blocking_count == 0
        assert report.security is None
        assert report.migration is None
        assert report.pr_comment_markdown == ""

    def test_with_security_data(self):
        report = AggregatedReport(
            scan_id="s1",
            security={"conflict_decision": {"overall_blocking": True}},
            pr_comment_markdown="## Report\nblocked",
        )
        assert report.security is not None
        assert report.pr_comment_markdown == "## Report\nblocked"
