"""Auto-resolver engine for conflict resolution.

Deterministic rule matching against exemption rules and severity-based policies.
Zero LLM — all decisions are traceable to specific rule IDs.

Rule priority (higher = evaluated first):
1. CVE in whitelist -> waive (with appropriate downgrade)
2. File path in whitelist -> waive (e.g., test/ directory)
3. CVE fix version <= target upgrade -> waive (upgrade-autofix, only for framework upgrade PRs)
4. Critical (CVSS >= 9.0) -> block (cannot be waived unless rule 1/2 match)
5. High severity + no whitelist -> block
6. Low confidence -> waive (info-only)
7. Default -> block for direct dependency, waive for transitive
"""

from __future__ import annotations

from typing import Any

from src.core.constants import CRITICAL_CVSS_THRESHOLD
from src.core.models import Severity, Verdict


class AutoResolver:
    """Deterministic rule engine for security verdict decisions.

    Usage:
        resolver = AutoResolver(exemption_rules)
        verdicts, unresolved = resolver.resolve(security_report, context)
    """

    def __init__(self, exemption_rules: list[dict[str, Any]] | None = None) -> None:
        self._rules = exemption_rules or []
        # Index rules by type for fast lookup
        self._cve_whitelist: set[str] = set()
        self._path_whitelist: list[str] = []
        self._severity_downgrades: dict[str, str] = {}
        self._index_rules()

    def reload_rules(self, rules: list[dict[str, Any]]) -> None:
        """Reload exemption rules (e.g., after config change)."""
        self._rules = rules
        self._cve_whitelist.clear()
        self._path_whitelist.clear()
        self._severity_downgrades.clear()
        self._index_rules()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def resolve(
        self,
        vulnerabilities: list[dict[str, Any]],
        code_issues: list[dict[str, Any]],
        *,
        is_framework_upgrade: bool = False,
        target_version: dict[str, str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Resolve all findings to verdicts.

        Args:
            vulnerabilities: List of Vulnerability-like dicts from SecurityReport.
            code_issues: List of CodeIssue-like dicts from SecurityReport.
            is_framework_upgrade: Whether this PR is a framework upgrade.
            target_version: Migration target {framework, from_version, to_version}.
            config: ResolutionConfig overrides.

        Returns:
            (resolved, unresolved) tuple.
            resolved: Findings with automatic verdicts.
            unresolved: Findings requiring human input.
        """
        cfg = config or {}
        resolved: list[dict[str, Any]] = []
        unresolved: list[dict[str, Any]] = []

        # Process vulnerabilities
        for vuln in vulnerabilities:
            verdict = self._resolve_vulnerability(
                vuln, is_framework_upgrade, target_version, cfg
            )
            if verdict:
                resolved.append(verdict)
            else:
                unresolved.append(vuln)

        # Process code issues
        for issue in code_issues:
            verdict = self._resolve_code_issue(issue, cfg)
            if verdict:
                resolved.append(verdict)
            else:
                unresolved.append(issue)

        return resolved, unresolved

    @staticmethod
    def _findings_needs_human(finding: dict[str, Any]) -> str | None:
        # Return a reason when a finding lacks the data needed for a reliable
        # auto-verdict. Such edge cases go to human review (returning None from
        # _resolve_* routes them to unresolved -> human_review) instead of being
        # decided from incomplete or ambiguous data.
        severity_str = finding.get("severity", "medium")
        try:
            Severity(severity_str)
        except ValueError:
            return f"unparsable severity: {severity_str!r}"
        # cvss_score only exists for vulnerabilities; never gate code issues on it.
        if "cve_id" in finding:
            cvss = finding.get("cvss_score")
            if cvss is None and severity_str in ("critical", "high"):
                return "high/critical severity without a cvss_score"
        conf = finding.get("confidence")
        if conf is not None and conf not in ("low", "medium", "high"):
            return f"unparsable confidence: {conf!r}"
        return None

    # ------------------------------------------------------------------
    # Per-finding resolution
    # ------------------------------------------------------------------

    def _resolve_vulnerability(
        self,
        vuln: dict[str, Any],
        is_framework_upgrade: bool,
        target_version: dict[str, str] | None,
        cfg: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Resolve a single vulnerability. Returns None if human input needed."""
        cve_id = vuln.get("cve_id", "")
        severity_str = vuln.get("severity", "medium")
        file_path = vuln.get("file_location", "")
        fixed_ver = vuln.get("fixed_version", "")
        dep_type = vuln.get("dependency_type", "direct")

        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.MEDIUM

        cvss = vuln.get("cvss_score")

        # Edge case: if the finding lacks enough data to auto-decide reliably,
        # route it to human review instead of guessing a verdict from bad data.
        insufficient = self._findings_needs_human(vuln)
        if insufficient:
            return None  # -> unresolved -> human_review

        # Rule 1: CVE whitelist
        if cve_id in self._cve_whitelist:
            return self._make_verdict(
                vuln, Verdict.WAIVE,
                reason=f"CVE {cve_id} is in exemption whitelist",
                rule_id=self._find_rule_id("cve_whitelist", cve_id),
            )

        # Rule 2: Path whitelist
        for pattern in self._path_whitelist:
            if self._match_path(file_path, pattern):
                return self._make_verdict(
                    vuln, Verdict.WAIVE,
                    reason=f"File {file_path} matches whitelist pattern '{pattern}'",
                    rule_id=self._find_rule_id("path_whitelist", pattern),
                )

        # Rule 3: Upgrade-autofix (only for framework upgrade PRs)
        if is_framework_upgrade and fixed_ver and target_version:
            to_ver = target_version.get("to_version", "")
            if self._version_gte(to_ver, fixed_ver):
                return self._make_verdict(
                    vuln, Verdict.WAIVE,
                    reason=f"Upgrade to {to_ver} fixes CVE {cve_id} (fixed in {fixed_ver})",
                    rule_id="auto:upgrade_autofix",
                )

        # Rule 4: Critical cannot be waived by auto-resolver
        if cvss and float(cvss) >= CRITICAL_CVSS_THRESHOLD:
            critical_cannot_waive = cfg.get("critical_cannot_waive", True)
            if critical_cannot_waive:
                # Critical always blocks unless human overrides
                # Mark as unresolved for human review (cannot auto-waive)
                return self._make_verdict(
                    vuln, Verdict.BLOCK,
                    reason=f"Critical severity (CVSS {cvss}) — blocked by default",
                    rule_id="auto:critical_block",
                )

        # Rule 5: High severity -> block
        if severity.is_blocking:
            return self._make_verdict(
                vuln, Verdict.BLOCK,
                reason=f"{severity.value} severity vulnerability in {dep_type} dependency",
                rule_id="auto:high_severity_block",
            )

        # Rule 7: Default — block direct, waive transitive
        if dep_type == "direct":
            return self._make_verdict(
                vuln, Verdict.BLOCK,
                reason=f"Direct dependency with {severity.value} severity",
                rule_id="auto:default_direct_block",
            )

        return self._make_verdict(
            vuln, Verdict.WAIVE,
            reason=f"Transitive dependency with {severity.value} severity — waived by default",
            rule_id="auto:default_transitive_waive",
        )

    def _resolve_code_issue(
        self, issue: dict[str, Any], cfg: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Resolve a single code issue. Returns None if human input needed."""
        file_path = issue.get("file_path", "")
        confidence = issue.get("confidence", "medium")
        severity_str = issue.get("severity", "medium")
        rule_id = issue.get("rule_id", "")

        # Edge case: route to human review when the field data is invalid/ambiguous.
        insufficient = self._findings_needs_human(issue)
        if insufficient:
            return None  # -> unresolved -> human_review

        # Rule 2: Path whitelist
        for pattern in self._path_whitelist:
            if self._match_path(file_path, pattern):
                return self._make_verdict(
                    issue, Verdict.WAIVE,
                    reason=f"File {file_path} matches whitelist pattern '{pattern}'",
                    rule_id=self._find_rule_id("path_whitelist", pattern),
                )

        # Rule 5 (code variant): Always-blocking rules
        if rule_id in ALWAYS_BLOCKING_RULES:
            return self._make_verdict(
                issue, Verdict.BLOCK,
                reason=f"Always-blocking rule: {rule_id}",
                rule_id="auto:always_blocking_rule",
            )

        # Rule 6: Low confidence auto-waive
        auto_waive = cfg.get("auto_waive_low_confidence", True)
        if confidence == "low" and auto_waive:
            return self._make_verdict(
                issue, Verdict.WAIVE,
                reason="Low confidence finding — waived automatically",
                rule_id="auto:low_confidence_waive",
            )

        # High confidence + critical/high severity -> block
        if confidence == "high" and severity_str in ("critical", "high"):
            return self._make_verdict(
                issue, Verdict.BLOCK,
                reason=f"High-confidence {severity_str} severity code issue",
                rule_id="auto:high_confidence_block",
            )

        # Medium confidence — let through as warning
        return self._make_verdict(
            issue, Verdict.WAIVE,
            reason="Medium confidence — waived, review recommended",
            rule_id="auto:medium_confidence_waive",
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_verdict(
        self,
        finding: dict[str, Any],
        verdict: Verdict,
        *,
        reason: str,
        rule_id: str,
        operator: str = "auto",
    ) -> dict[str, Any]:
        """Build a verdict dict from a finding and resolution."""
        is_vuln = "cve_id" in finding
        finding_id = finding.get("cve_id") or finding.get("rule_id", "")

        return {
            "finding_id": finding_id,
            "finding_type": "vulnerability" if is_vuln else "code_issue",
            "verdict": verdict.value,
            "reason": reason,
            "rule_id": rule_id,
            "operator": operator,
            "evidence_link": finding.get("evidence_url", ""),
            "appealable": self._is_appealable(finding, verdict),
            # Carry forward original finding data for audit
            "_original_severity": finding.get("severity", ""),
            "_original_blocking": finding.get("blocking", False),
            "_file_location": finding.get("file_location", "")
                   or finding.get("file_path", ""),
        }

    @staticmethod
    def _is_appealable(finding: dict[str, Any], verdict: Verdict) -> bool:
        """Determine if a finding can be appealed by the developer.

        Critical CVEs are not appealable. Blocked high-severity is appealable.
        """
        if verdict == Verdict.WAIVE:
            return False  # Already waived — nothing to appeal
        severity = finding.get("severity", "")
        if severity == "critical":
            cvss = finding.get("cvss_score", 0)
            if cvss and float(cvss) >= CRITICAL_CVSS_THRESHOLD:
                return False  # Critical cannot be waived by anyone
        return True

    @staticmethod
    def _version_gte(version_a: str, version_b: str) -> bool:
        """Compare two semver-like version strings. Returns True if a >= b."""
        try:
            parts_a = [int(x) for x in version_a.replace("v", "").split(".")]
            parts_b = [int(x) for x in version_b.replace("v", "").split(".")]
            # Pad to same length
            while len(parts_a) < len(parts_b):
                parts_a.append(0)
            while len(parts_b) < len(parts_a):
                parts_b.append(0)
            return parts_a >= parts_b
        except (ValueError, AttributeError):
            return version_a >= version_b

    @staticmethod
    def _match_path(file_path: str, pattern: str) -> bool:
        """Simple glob-like path matching.

        pattern "test/**" matches "test/test_app.py", "tests/integration/test_x.py", etc.
        """
        # Strip trailing /**
        prefix = pattern.rstrip("/").rstrip("*").rstrip("/")
        if pattern.endswith("**"):
            return file_path.startswith(prefix + "/") or file_path.startswith(prefix)
        if pattern.endswith("*"):
            return file_path.startswith(prefix)
        return file_path == pattern

    # ------------------------------------------------------------------
    # Rule index
    # ------------------------------------------------------------------

    def _index_rules(self) -> None:
        """Index exemption rules for O(1) lookup."""
        for rule in self._rules:
            if not rule.get("enabled", True):
                continue
            rule_type = rule.get("rule_type", "")
            pattern = rule.get("pattern", "")

            if rule_type == "cve_whitelist":
                self._cve_whitelist.add(pattern.upper())
            elif rule_type == "path_whitelist":
                self._path_whitelist.append(pattern)
            elif rule_type == "severity_downgrade":
                self._severity_downgrades[pattern] = rule.get("rule_id", "")

    def _find_rule_id(self, rule_type: str, pattern: str) -> str:
        """Find the rule_id for a matching exemption rule."""
        for rule in self._rules:
            if rule.get("rule_type") == rule_type and rule.get("pattern") == pattern:
                return rule.get("rule_id", f"auto:{rule_type}")
        return f"auto:{rule_type}"


# Always-blocking Semgrep rules (never waived automatically)
ALWAYS_BLOCKING_RULES: set[str] = {
    "generic.secrets.security.detected-private-key",
    "generic.secrets.security.detected-aws-access-key",
    "generic.secrets.security.detected-google-api-key",
}
