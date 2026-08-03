"""Data models for Security Audit Agent.

All models use Pydantic for validation.
SecurityReport is the primary output contract.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class Vulnerability(BaseModel):
    """A single vulnerability finding from CVE scanning.

    Every field that constitutes an evidence claim must be traceable
    to an authoritative source (OSV, GitHub Advisory, local cache).
    """

    cve_id: str = Field(..., description="CVE identifier, e.g. CVE-2024-3842")
    package_name: str = Field(..., description="Affected package name")
    affected_version: str = Field(..., description="Currently installed version")
    affected_version_range: str | None = Field(
        None, description="Human-readable version range, e.g. '< 2.17.1'"
    )
    fixed_version: str | None = Field(
        None, description="First version that contains the fix"
    )
    fix_available: bool = Field(
        default=False, description="Whether an official fix has been released"
    )
    severity: str = Field(
        ..., description="critical | high | medium | low"
    )
    cvss_score: float | None = Field(
        None, description="CVSS v3.1 score (0.0-10.0)", ge=0.0, le=10.0
    )
    dependency_type: str = Field(
        ..., description="direct | transitive"
    )
    evidence_source: str = Field(
        ..., description="OSV | GitHub Advisory | local_cache"
    )
    evidence_url: str = Field(
        default="", description="URL to the authoritative advisory"
    )
    file_location: str = Field(
        ..., description="Dependency manifest and line, e.g. requirements.txt:L15"
    )
    blocking: bool = Field(
        default=False,
        description="Whether this vulnerability should block the PR",
    )
    description: str = Field(
        default="", description="Human-readable summary of the vulnerability"
    )


class CodeIssue(BaseModel):
    """A static-analysis code issue from Semgrep rule matching.

    Differs from Vulnerability: CodeIssues come from code-pattern rules
    (e.g., hardcoded secrets, SQL injection), not from CVE databases.
    """

    rule_id: str = Field(
        ..., description="Semgrep rule ID, e.g. python.lang.security.audit.detect-sql-injection"
    )
    severity: str = Field(..., description="critical | high | medium | low")
    confidence: str = Field(
        default="medium", description="high | medium | low"
    )
    file_path: str = Field(..., description="Relative file path")
    line_number: int = Field(..., description="1-indexed line number", ge=1)
    code_snippet: str = Field(
        ..., description="The matched code fragment (max 200 chars)"
    )
    message: str = Field(..., description="Human-readable issue description")
    fix_suggestion: str = Field(
        default="", description="Suggested remediation"
    )
    blocking: bool = Field(
        default=False,
        description="Whether this issue should block the PR",
    )


class SecurityReport(BaseModel):
    """Complete output of the Security Audit Agent.

    This is the canonical input for the Conflict Resolution Agent.
    Every field required for evidence tracing and audit is included.
    """

    scan_id: str = Field(..., description="Unique scan identifier (UUID)")
    scan_scope: str = Field(..., description="full | diff")
    rule_set_version: str = Field(
        default="0.1.0", description="Semgrep ruleset version used"
    )
    cve_db_version: str = Field(
        default="", description="CVE database version/snapshot timestamp"
    )
    vulnerabilities: list[Vulnerability] = Field(
        default_factory=list, description="CVEs found during dependency scanning"
    )
    code_issues: list[CodeIssue] = Field(
        default_factory=list, description="Code-pattern issues from Semgrep"
    )
    scan_duration_ms: int = Field(
        default=0, description="Total scan wall-clock time in milliseconds"
    )
    scanned_deps_count: int = Field(
        default=0, description="Number of dependencies checked"
    )
    degraded: bool = Field(
        default=False,
        description="True if any scan step was degraded (e.g., OSV API unavailable)",
    )
    degraded_reasons: list[str] = Field(
        default_factory=list,
        description="Per-step degradation reasons (never silently degraded)",
    )

    @property
    def blocking_count(self) -> int:
        """Number of findings with blocking=True."""
        return (
            sum(1 for v in self.vulnerabilities if v.blocking)
            + sum(1 for i in self.code_issues if i.blocking)
        )

    @property
    def total_findings(self) -> int:
        """Total number of findings (blocking + non-blocking)."""
        return len(self.vulnerabilities) + len(self.code_issues)


class SecurityScanConfig(BaseModel):
    """Runtime configuration for a security scan.

    Allows per-scan overrides of global settings without
    modifying the persistent rule configuration.
    """

    enable_cve_scan: bool = Field(default=True, description="Run CVE dependency scan")
    enable_code_scan: bool = Field(default=True, description="Run Semgrep code scan")
    block_severity: str = Field(
        default="high", description="Minimum severity for blocking: high | critical"
    )
    file_blacklist: list[str] = Field(
        default_factory=lambda: ["test/", "tests/", "docs/"],
        description="Path patterns to exclude from code scanning",
    )
