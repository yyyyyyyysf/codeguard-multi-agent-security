"""Common data models and enumerations for CodeGuard.

These are the foundational types used across all layers.
Business-specific models (SecurityReport, MigrationReport, etc.)
live in their respective agent packages, NOT here.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal


# ============================================================
# Severity enums
# ============================================================

class Severity(str, Enum):
    """Vulnerability severity aligned with CVSS v3.1."""
    CRITICAL = "critical"   # CVSS 9.0-10.0
    HIGH = "high"           # CVSS 7.0-8.9
    MEDIUM = "medium"       # CVSS 4.0-6.9
    LOW = "low"             # CVSS 0.1-3.9

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        return cls.LOW

    @property
    def is_blocking(self) -> bool:
        """Default blocking threshold: HIGH and above block."""
        return self in (Severity.CRITICAL, Severity.HIGH)


class Confidence(str, Enum):
    """Confidence level for a finding."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ============================================================
# Scan enums
# ============================================================

class ScanScope(str, Enum):
    """Whether a scan covers the full repo or only the PR diff."""
    FULL = "full"
    DIFF = "diff"


class ScanStatus(str, Enum):
    """Lifecycle status of an analysis task."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanStage(str, Enum):
    """Current execution stage within a running task."""
    PREPROCESS = "preprocess"
    SECURITY = "security"
    CONFLICT = "conflict"
    MIGRATION = "migration"
    REPORT = "report"


# ============================================================
# Security enums
# ============================================================

class Verdict(str, Enum):
    """Final decision on a security finding."""
    BLOCK = "block"     # Must be fixed before merge
    WAIVE = "waive"     # Approved exemption
    DEFER = "defer"     # Deferred for later (not blocking now)


class FindingType(str, Enum):
    """Type of a security finding."""
    VULNERABILITY = "vulnerability"
    CODE_ISSUE = "code_issue"


# ============================================================
# Migration enums
# ============================================================

class RiskLevel(str, Enum):
    """Overall migration risk level."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ImpactLevel(str, Enum):
    """Per-file impact severity."""
    BREAKING = "breaking"
    WARNING = "warning"


class AnalysisSource(str, Enum):
    """How a migration finding was produced."""
    AST_RULE = "ast_rule"       # Deterministic Tree-sitter rule match
    LLM_ANALYSIS = "llm_analysis"  # LLM-assisted analysis


# ============================================================
# Dependency enums
# ============================================================

class DependencyType(str, Enum):
    """Whether a dependency is direct or transitive."""
    DIRECT = "direct"
    TRANSITIVE = "transitive"


class Ecosystem(str, Enum):
    """Package ecosystem for vulnerability lookups."""
    PYPI = "pypi"
    NPM = "npm"
    MAVEN = "maven"
    GO = "go"
    CARGO = "cargo"


# ============================================================
# Evidence source
# ============================================================

class EvidenceSource(str, Enum):
    """Origin of a vulnerability finding."""
    OSV = "OSV"
    GITHUB_ADVISORY = "GitHub Advisory"
    LOCAL_CACHE = "local_cache"
    SEMGREP = "Semgrep"


# ============================================================
# Rule enums
# ============================================================

class RuleType(str, Enum):
    """Type of an exemption rule."""
    CVE_WHITELIST = "cve_whitelist"
    PATH_WHITELIST = "path_whitelist"
    SEVERITY_DOWNGRADE = "severity_downgrade"


class RuleScope(str, Enum):
    """Scope of an exemption rule."""
    GLOBAL = "global"
    # Future: REPO, PATH


# ============================================================
# File change enums
# ============================================================

class ChangeType(str, Enum):
    """Type of file change in a diff."""
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"


# ============================================================
# Operator identifier
# ============================================================

Operator = str  # "system" or "human:{user_id}"


# ============================================================
# Type aliases
# ============================================================

JsonDict = dict[str, Any]
TaskID = str
ScanID = str
RuleID = str
FindingID = str
