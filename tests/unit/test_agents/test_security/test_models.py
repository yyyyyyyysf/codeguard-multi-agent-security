"""Tests for Security Audit Agent data models."""

import pytest
from pydantic import ValidationError

from src.agents.security.models import (
    CodeIssue,
    SecurityReport,
    SecurityScanConfig,
    Vulnerability,
)


class TestVulnerability:
    def test_minimal_vulnerability(self):
        v = Vulnerability(
            cve_id="CVE-2024-0001",
            package_name="fastapi",
            affected_version="0.100.0",
            severity="high",
            cvss_score=8.5,
            dependency_type="direct",
            evidence_source="OSV",
            file_location="requirements.txt:L15",
        )
        assert v.cve_id == "CVE-2024-0001"
        assert v.blocking is False  # Default
        assert v.fix_available is False  # Default

    def test_blocking_direct_high_cvss(self):
        v = Vulnerability(
            cve_id="CVE-2024-0001",
            package_name="requests",
            affected_version="2.28.0",
            severity="critical",
            cvss_score=9.8,
            dependency_type="direct",
            evidence_source="OSV",
            file_location="requirements.txt:L5",
            blocking=True,
            fix_available=True,
            fixed_version="2.31.0",
        )
        assert v.blocking
        assert v.fix_available
        assert v.fixed_version == "2.31.0"

    def test_cvss_validation(self):
        with pytest.raises(ValidationError):  # Pydantic validation
            Vulnerability(
                cve_id="CVE-2024-0001",
                package_name="test",
                affected_version="1.0",
                severity="high",
                cvss_score=11.0,  # > 10.0
                dependency_type="direct",
                evidence_source="OSV",
                file_location="x:L1",
            )

    def test_null_cvss(self):
        v = Vulnerability(
            cve_id="CVE-2024-0001",
            package_name="test",
            affected_version="1.0",
            severity="high",
            cvss_score=None,
            dependency_type="direct",
            evidence_source="OSV",
            file_location="x:L1",
        )
        assert v.cvss_score is None


class TestCodeIssue:
    def test_minimal_code_issue(self):
        ci = CodeIssue(
            rule_id="python.lang.security.audit.detect-sql-injection",
            severity="high",
            file_path="src/app.py",
            line_number=42,
            code_snippet='query = f"SELECT * FROM users WHERE id={user_id}"',
            message="Possible SQL injection",
            fix_suggestion="Use parameterized queries",
        )
        assert ci.confidence == "medium"  # Default
        assert ci.blocking is False  # Default

    def test_secret_detection_blocking(self):
        ci = CodeIssue(
            rule_id="generic.secrets.security.detected-private-key",
            severity="critical",
            confidence="high",
            file_path="config.py",
            line_number=10,
            code_snippet="PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----'",
            message="Private key detected in source code",
            blocking=True,
        )
        assert ci.blocking


class TestSecurityReport:
    def test_empty_report(self):
        report = SecurityReport(scan_id="scan-001", scan_scope="full")
        assert report.total_findings == 0
        assert report.blocking_count == 0

    def test_report_with_findings(self):
        report = SecurityReport(
            scan_id="scan-001",
            scan_scope="diff",
            vulnerabilities=[
                Vulnerability(
                    cve_id="CVE-2024-0001",
                    package_name="pkg",
                    affected_version="1.0",
                    severity="critical",
                    cvss_score=9.0,
                    dependency_type="direct",
                    evidence_source="OSV",
                    file_location="req.txt:L1",
                    blocking=True,
                ),
            ],
            code_issues=[
                CodeIssue(
                    rule_id="r1",
                    severity="high",
                    file_path="a.py",
                    line_number=1,
                    code_snippet="x",
                    message="m",
                    blocking=True,
                ),
            ],
            scan_duration_ms=1500,
            scanned_deps_count=42,
            degraded=True,
            degraded_reasons=["OSV API timeout"],
        )
        assert report.total_findings == 2
        assert report.blocking_count == 2
        assert report.degraded
        assert len(report.degraded_reasons) == 1


class TestSecurityScanConfig:
    def test_default_config(self):
        config = SecurityScanConfig()
        assert config.enable_cve_scan
        assert config.enable_code_scan
        assert config.block_severity == "high"

    def test_custom_config(self):
        config = SecurityScanConfig(
            enable_cve_scan=False,
            block_severity="critical",
        )
        assert not config.enable_cve_scan
        assert config.block_severity == "critical"
