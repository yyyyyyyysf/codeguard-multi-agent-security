"""Tests for AutoResolver — all 5 core rules, edge cases, error paths."""

import pytest

from src.agents.conflict.auto_resolver import AutoResolver


@pytest.fixture
def sample_rules():
    return [
        {
            "rule_id": "rule-001",
            "rule_type": "cve_whitelist",
            "pattern": "CVE-2023-9999",
            "reason": "Test whitelist",
            "scope": "global",
            "enabled": True,
        },
        {
            "rule_id": "rule-002",
            "rule_type": "path_whitelist",
            "pattern": "tests/**",
            "reason": "Test files exempt",
            "scope": "global",
            "enabled": True,
        },
    ]


@pytest.fixture
def resolver(sample_rules):
    return AutoResolver(sample_rules)


class TestRule1CVEWhitelist:
    """Rule 1: CVE in exemption whitelist -> waive."""

    def test_whitelisted_cve_waived(self, resolver):
        vulns = [{
            "cve_id": "CVE-2023-9999",
            "severity": "critical",
            "cvss_score": 9.8,
            "dependency_type": "direct",
            "file_location": "requirements.txt:L1",
            "evidence_url": "https://osv.dev/CVE-2023-9999",
        }]
        resolved, unresolved = resolver.resolve(vulns, [])
        assert len(resolved) == 1
        assert resolved[0]["verdict"] == "waive"
        assert len(unresolved) == 0

    def test_non_whitelisted_cve_not_waived(self, resolver):
        vulns = [{
            "cve_id": "CVE-2024-NEW",
            "severity": "high",
            "cvss_score": 8.0,
            "dependency_type": "direct",
            "file_location": "req.txt:L1",
        }]
        resolved, _ = resolver.resolve(vulns, [])
        assert resolved[0]["verdict"] == "block"  # High + direct -> block


class TestRule2PathWhitelist:
    """Rule 2: File in path whitelist -> waive."""

    def test_test_file_waived(self, resolver):
        vulns = [{
            "cve_id": "CVE-2024-0001",
            "severity": "high",
            "cvss_score": 7.5,
            "dependency_type": "direct",
            "file_location": "tests/test_main.py:L5",
        }]
        resolved, _ = resolver.resolve(vulns, [])
        assert resolved[0]["verdict"] == "waive"
        assert "tests/**" in resolved[0]["reason"]

    def test_src_file_not_waived(self, resolver):
        vulns = [{
            "cve_id": "CVE-2024-0001",
            "severity": "high",
            "cvss_score": 7.5,
            "dependency_type": "direct",
            "file_location": "src/main.py:L10",
        }]
        resolved, _ = resolver.resolve(vulns, [])
        assert resolved[0]["verdict"] == "block"


class TestRule3UpgradeAutofix:
    """Rule 3: Upgrade fixes the CVE -> waive (only for framework upgrade PRs)."""

    def test_upgrade_fixes_cve(self, resolver):
        vulns = [{
            "cve_id": "CVE-2024-0001",
            "severity": "high",
            "cvss_score": 8.0,
            "dependency_type": "direct",
            "fixed_version": "0.105.0",
            "file_location": "req.txt:L1",
        }]
        resolved, _ = resolver.resolve(
            vulns, [],
            is_framework_upgrade=True,
            target_version={
                "framework": "fastapi",
                "from_version": "0.100.0",
                "to_version": "0.110.0",
            },
        )
        assert resolved[0]["verdict"] == "waive"
        assert "upgrade_autofix" in resolved[0]["rule_id"]

    def test_upgrade_does_not_fix_cve(self, resolver):
        """Upgrade target version is lower than fixed version -> still block."""
        vulns = [{
            "cve_id": "CVE-2024-0001",
            "severity": "high",
            "cvss_score": 8.0,
            "dependency_type": "direct",
            "fixed_version": "0.120.0",  # Higher than target
            "file_location": "req.txt:L1",
        }]
        resolved, _ = resolver.resolve(
            vulns, [],
            is_framework_upgrade=True,
            target_version={
                "framework": "fastapi",
                "from_version": "0.100.0",
                "to_version": "0.110.0",
            },
        )
        assert resolved[0]["verdict"] == "block"

    def test_upgrade_autofix_only_for_upgrade_pr(self, resolver):
        """Not a framework upgrade -> rule 3 does not apply."""
        vulns = [{
            "cve_id": "CVE-2024-0001",
            "severity": "high",
            "cvss_score": 8.0,
            "dependency_type": "direct",
            "fixed_version": "0.105.0",
            "file_location": "req.txt:L1",
        }]
        resolved, _ = resolver.resolve(vulns, [], is_framework_upgrade=False)
        assert resolved[0]["verdict"] == "block"


class TestRule4CriticalBlock:
    """Rule 4: Critical (CVSS >= 9.0) -> block, even if other rules could waive."""

    def test_critical_blocks(self, resolver):
        vulns = [{
            "cve_id": "CVE-2024-CRITICAL",
            "severity": "critical",
            "cvss_score": 9.8,
            "dependency_type": "transitive",
            "file_location": "req.txt:L1",
        }]
        resolved, _ = resolver.resolve(vulns, [])
        assert resolved[0]["verdict"] == "block"

    def test_critical_in_whitelist_still_waived(self, resolver):
        """Rule 1 (CVE whitelist) takes priority over Rule 4."""
        vulns = [{
            "cve_id": "CVE-2023-9999",  # In whitelist
            "severity": "critical",
            "cvss_score": 9.8,
            "dependency_type": "direct",
            "file_location": "req.txt:L1",
        }]
        resolved, _ = resolver.resolve(vulns, [])
        assert resolved[0]["verdict"] == "waive"  # Whitelist wins


class TestRule5HighSeverityBlock:
    """Rule 5: High severity + no whitelist -> block."""

    def test_high_direct_blocks(self, resolver):
        vulns = [{
            "cve_id": "CVE-2024-HIGH",
            "severity": "high",
            "cvss_score": 8.5,
            "dependency_type": "direct",
            "file_location": "req.txt:L1",
        }]
        resolved, _ = resolver.resolve(vulns, [])
        assert resolved[0]["verdict"] == "block"

    def test_medium_direct_blocks(self, resolver):
        """Medium severity direct dep still blocks (Rule 7 default)."""
        vulns = [{
            "cve_id": "CVE-2024-MED",
            "severity": "medium",
            "cvss_score": 5.0,
            "dependency_type": "direct",
            "file_location": "req.txt:L1",
        }]
        resolved, _ = resolver.resolve(vulns, [])
        assert resolved[0]["verdict"] == "block"  # Default: direct dep blocks

    def test_medium_transitive_waives(self, resolver):
        vulns = [{
            "cve_id": "CVE-2024-MED",
            "severity": "medium",
            "cvss_score": 5.0,
            "dependency_type": "transitive",
            "file_location": "poetry.lock:L100",
        }]
        resolved, _ = resolver.resolve(vulns, [])
        assert resolved[0]["verdict"] == "waive"  # Transitive + medium = waived


class TestCodeIssueResolution:
    """Tests for code issue resolution (confidence-based + always-blocking)."""

    def test_always_blocking_rule(self, resolver):
        issues = [{
            "rule_id": "generic.secrets.security.detected-private-key",
            "severity": "critical",
            "confidence": "high",
            "file_path": "config.py",
            "line_number": 1,
            "code_snippet": "PRIVATE_KEY = '...'",
        }]
        resolved, _ = resolver.resolve([], issues)
        assert resolved[0]["verdict"] == "block"
        assert "always_blocking" in resolved[0]["rule_id"]

    def test_low_confidence_auto_waive(self, resolver):
        issues = [{
            "rule_id": "some.experimental.rule",
            "severity": "high",
            "confidence": "low",
            "file_path": "src/app.py",
        }]
        resolved, _ = resolver.resolve([], issues)
        assert resolved[0]["verdict"] == "waive"

    def test_high_confidence_high_severity_blocks(self, resolver):
        issues = [{
            "rule_id": "python.lang.security.audit.detect-sql-injection",
            "severity": "high",
            "confidence": "high",
            "file_path": "src/app.py",
        }]
        resolved, _ = resolver.resolve([], issues)
        assert resolved[0]["verdict"] == "block"

    def test_medium_confidence_waives(self, resolver):
        issues = [{
            "rule_id": "python.lang.security.audit.some-rule",
            "severity": "medium",
            "confidence": "medium",
            "file_path": "src/app.py",
        }]
        resolved, _ = resolver.resolve([], issues)
        assert resolved[0]["verdict"] == "waive"


class TestEmptyInput:
    def test_empty_vulns_and_issues(self, resolver):
        resolved, unresolved = resolver.resolve([], [])
        assert resolved == []
        assert unresolved == []


class TestVersionComparison:
    def test_version_gte(self, resolver):
        assert resolver._version_gte("0.110.0", "0.105.0")
        assert not resolver._version_gte("0.100.0", "0.105.0")
        assert resolver._version_gte("2.0.0", "1.9.9")
        assert resolver._version_gte("1.0.0", "1.0.0")

    def test_v_prefixed_versions(self, resolver):
        assert resolver._version_gte("v2.1.0", "v2.0.0")


class TestPathMatching:
    def test_match_path(self, resolver):
        assert resolver._match_path("tests/test_app.py", "tests/**")
        assert resolver._match_path("tests/integration/test.py", "tests/**")
        assert resolver._match_path("tests", "tests/**")
        assert not resolver._match_path("src/test.py", "tests/**")

    def test_match_exact_path(self, resolver):
        assert resolver._match_path("src/config.py", "src/config.py")
        assert not resolver._match_path("src/main.py", "src/config.py")
