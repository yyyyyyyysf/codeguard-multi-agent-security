"""Report Aggregation Agent — Merge, sort, render. NO business decisions.

Orchestrates:
1. Receive FinalSecurityDecision + MigrationReport from upstream agents.
2. Merge, deduplicate, sort by severity (blocking first).
3. Render PR comment (Jinja2 Markdown) and full report (JSON/HTML).
4. Security-first: security results render immediately, migration async appends.

Design invariants:
- NEVER modifies upstream conclusions (blocking status, severity, risk level).
- NEVER adds new risk rules or business logic.
- Content generation only; publishing is done by integrations layer.
- Degradation: template rendering errors -> fallback to plain-text summary.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from jinja2 import BaseLoader, Environment

from src.agents.reporter.models import AggregatedReport, ReportSummary
from src.engine.base_agent import BaseAgent
from src.utils.id_gen import generate_id
from src.utils.logging import get_logger

logger = get_logger(__name__)

# Inline templates as fallback when filesystem templates aren't available
PR_COMMENT_TEMPLATE = """## CodeGuard 安全分析报告
> 本次扫描：{{ scan_scope }} · {{ file_count }} 个文件 · 安全扫描耗时 {{ security_duration_ms }}ms{% if migration_duration_ms %} · 迁移评估耗时 {{ migration_duration_ms }}ms{% endif %}
{% if degraded %}
> 扫描降级：{{ degraded_reasons | join('; ') }}
{% endif %}

{% if blocking_items %}
### 阻断项 ({{ blocking_items | length }})
| 严重度 | 问题 | 位置 | 修复方案 |
|--------|------|------|----------|
{% for item in blocking_items %}
| {{ item.severity }} | {{ item.id }} {{ item.description }} [{{ item.source }}] | {{ item.location }} | {{ item.fix }}{% if item.appealable %} · [申请豁免]{% endif %} |
{% endfor %}
{% endif %}

{% if warning_items %}
### 建议项 ({{ warning_items | length }})
{% if security_warnings %}
#### 安全建议
{% for item in security_warnings %}
- {{ item.message }}
{% endfor %}
{% endif %}
{% if migration_warnings %}
#### 迁移建议
{% for item in migration_warnings %}
- {{ item.change_desc }}：影响 {{ item.location }}
{% endfor %}
{% endif %}
{% endif %}

{% if pass_items %}
### 通过项
{% for item in pass_items %}
- {{ item }}
{% endfor %}
{% endif %}

---
[查看完整报告]({{ full_report_url }}) · [管理豁免规则]({{ rules_url }})
"""


class ReportAggregationAgent(BaseAgent):
    """Report aggregation agent: merge upstream results, render templates.

    Input:  security_data (FinalSecurityDecision + context),
            migration_data (MigrationReport + context)
    Output: AggregatedReport with rendered PR comment and full report paths.
    """

    agent_id = "report_aggregation"
    description = (
        "Merges security and migration results, renders PR comments and full "
        "reports via Jinja2 templates. NEVER modifies business conclusions."
    )

    def __init__(
        self,
        template_dir: str | None = None,
        report_store: Any | None = None,
    ) -> None:
        super().__init__()
        self._template_dir = template_dir or "src/agents/reporter/templates"
        self._report_store = report_store
        self._jinja = Environment(
            loader=BaseLoader(),
            autoescape=False,
        )

    # ------------------------------------------------------------------
    # Core logic
    # ------------------------------------------------------------------

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        """Aggregate upstream results and render templates.

        Args:
            security_data: Dict with 'security' (SecurityReport) and
                          'conflict' (FinalSecurityDecision).
            migration_data: MigrationReport dict.
            repo_url: Repository URL.
            code_metadata: CodeMetadata with commit info.

        Returns:
            AggregatedReport as dict.
        """
        security_data = kwargs.get("security_data", {})
        migration_data = kwargs.get("migration_data", {})
        repo_url = kwargs.get("repo_url", "")
        code_metadata = kwargs.get("code_metadata", {})
        scan_id = kwargs.get("scan_id", generate_id())
        task_id = kwargs.get("task_id", "")

        conflict = security_data.get("conflict", {})
        security_report = security_data.get("security", {})
        migration = migration_data if migration_data else {}

        # --- Step 1: Build summary ---
        blocking_count = self._count_blocking(conflict)
        warning_count = self._count_warnings(conflict, migration)
        pass_count = self._count_pass(security_report)

        summary = ReportSummary(
            blocking_count=blocking_count,
            warning_count=warning_count,
            pass_count=pass_count,
            security_scan_duration_ms=security_report.get("scan_duration_ms", 0),
            migration_scan_duration_ms=migration.get("scan_duration_ms", 0),
        )

        # --- Step 2: Collect degradation info ---
        degraded = (
            security_report.get("degraded", False)
            or conflict.get("degraded", False)
            or migration.get("degraded", False)
        )
        degraded_reasons = []
        for src in [security_report, migration]:
            degraded_reasons.extend(src.get("degraded_reasons", []))

        # --- Step 3: Render PR comment ---
        pr_vars = self._build_pr_template_vars(
            conflict=conflict,
            security_report=security_report,
            migration=migration,
            code_metadata=code_metadata,
            degraded=degraded,
            degraded_reasons=degraded_reasons,
            scan_id=scan_id,
            task_id=task_id,
        )
        pr_comment = self._render_pr_comment(pr_vars)

        # --- Step 4: Assemble report ---
        now = datetime.now(UTC).isoformat()

        report = AggregatedReport(
            scan_id=scan_id,
            repo_url=repo_url,
            commit_sha=code_metadata.get("commit_sha", ""),
            scan_scope=code_metadata.get("scan_scope", "full"),
            generated_at=now,
            summary=summary,
            security={
                "security_report": security_report,
                "conflict_decision": conflict,
            },
            migration=migration if migration.get("framework") else None,
            pr_comment_markdown=pr_comment,
            degraded=degraded,
            degraded_reasons=degraded_reasons,
            appeal_count=conflict.get("appeal_count", 0),
            human_intervention_required=conflict.get("human_intervention_required", False),
        )

        logger.info(
            "report_aggregation_complete",
            scan_id=scan_id,
            blocking=blocking_count,
            warnings=warning_count,
            degraded=degraded,
        )

        report_dict = report.model_dump()
        if self._report_store:
            try:
                self._report_store.save_json(scan_id, report_dict)
            except Exception as exc:
                logger.warning(
                    "report_store_save_failed",
                    scan_id=scan_id,
                    error=str(exc)[:100],
                )

        return report_dict

    # ------------------------------------------------------------------
    # Degradation
    # ------------------------------------------------------------------

    async def degraded_run(
        self, original_error: Exception, **kwargs: Any
    ) -> dict[str, Any]:
        """Fallback: plain-text summary when template rendering fails."""
        security_data = kwargs.get("security_data", {})
        conflict = security_data.get("conflict", {})
        scan_id = kwargs.get("scan_id", generate_id())
        repo_url = kwargs.get("repo_url", "")
        code_metadata = kwargs.get("code_metadata", {})

        blocking_count = self._count_blocking(conflict)
        now = datetime.now(UTC).isoformat()

        # Plain-text fallback comment
        fallback = (
            f"## CodeGuard 分析报告\n\n"
            f"**阻断项**: {blocking_count}\n\n"
            f"> 扫描时间: {now}\n\n"
            f"报告生成异常: {str(original_error)[:200]}\n"
        )

        report = AggregatedReport(
            scan_id=scan_id,
            repo_url=repo_url,
            commit_sha=code_metadata.get("commit_sha", ""),
            generated_at=now,
            summary=ReportSummary(blocking_count=blocking_count),
            security={"conflict_decision": conflict},
            pr_comment_markdown=fallback,
            degraded=True,
            degraded_reasons=[f"Reporter degraded: {str(original_error)[:200]}"],
        )

        report_dict = report.model_dump()
        if self._report_store:
            try:
                self._report_store.save_json(scan_id, report_dict)
            except Exception as exc:
                logger.warning(
                    "report_store_save_failed",
                    scan_id=scan_id,
                    error=str(exc)[:100],
                )

        return report_dict

    # ------------------------------------------------------------------
    # Template rendering
    # ------------------------------------------------------------------

    def _render_pr_comment(self, variables: dict[str, Any]) -> str:
        """Render the PR comment from Jinja2 template.

        Falls back to plain-text if template rendering fails.
        """
        try:
            template = self._jinja.from_string(PR_COMMENT_TEMPLATE)
            return template.render(**variables).strip()
        except Exception as e:
            logger.error("pr_comment_render_failed", error=str(e))
            return self._plain_text_fallback(variables)

    def _render_full_report_html(self, variables: dict[str, Any]) -> str:
        """Render the full HTML report."""
        try:
            with open(f"{self._template_dir}/full_report.html", encoding="utf-8") as f:
                template_str = f.read()
            template = self._jinja.from_string(template_str)
            return template.render(**variables)
        except Exception as e:
            logger.error("html_report_render_failed", error=str(e))
            return f"<html><body><h1>Report Error</h1><p>{e}</p></body></html>"

    @staticmethod
    def _md_safe(value: object) -> str:
        # Render untrusted external text as a Markdown inline-code span.
        # Injected link syntax ([Click](http://evil.com)) would render as a
        # clickable link under Markdown; HTML autoescape does not help here.
        # Wrapping in a code span makes it literal text. Existing backticks
        # widen the delimiter; a pipe '|' becomes full-width so it cannot
        # inject extra columns into the Markdown table.
        text = str(value or "")
        text = text.replace('|', '\uff5c')
        if '`' in text:
            return '``' + text + '``'
        return '`' + text + '`'

    # ------------------------------------------------------------------
    # Template variables
    # ------------------------------------------------------------------

    def _build_pr_template_vars(
        self,
        conflict: dict[str, Any],
        security_report: dict[str, Any],
        migration: dict[str, Any],
        code_metadata: dict[str, Any],
        degraded: bool,
        degraded_reasons: list[str],
        scan_id: str,
        task_id: str,
    ) -> dict[str, Any]:
        """Build the variable context for PR comment template rendering."""

        # Blocking items
        blocking_items = []
        for d in conflict.get("decisions", []):
            if d.get("verdict") == "block":
                blocking_items.append({
                    "severity": "Critical",
                    "id": self._md_safe(d.get("finding_id", "")),
                    "description": self._md_safe(d.get("reason", "")[:120]),
                    "source": self._md_safe(self._get_evidence_source(d, security_report)),
                    "location": self._md_safe(self._get_location(d, security_report)),
                    "fix": self._md_safe(self._get_fix_suggestion(d, security_report)),
                    "appealable": d.get("appealable", False),
                })

        # Warning items
        security_warnings = []
        for d in conflict.get("decisions", []):
            if d.get("verdict") != "block":
                security_warnings.append({
                    "message": self._md_safe(
                        f"{d.get('finding_id')}: {d.get('reason', '')[:150]}"
                    ),
                })

        migration_warnings = []
        for bc in migration.get("breaking_changes", []):
            for af in bc.get("affected_files", []):
                migration_warnings.append({
                    "change_desc": self._md_safe(bc.get("change_desc", "")),
                    "location": self._md_safe(
                        f"{af.get('path', '')}:L{af.get('line_number', 0)}"
                    ),
                })

        # Pass items
        pass_items = []
        vuln_count = len(security_report.get("vulnerabilities", []))
        code_issue_count = len(security_report.get("code_issues", []))
        if vuln_count:
            passed_deps = vuln_count - len(blocking_items)
            if passed_deps > 0:
                pass_items.append(f"依赖漏洞扫描: {passed_deps}/{vuln_count} 无高危漏洞")
        if code_issue_count:
            pass_items.append(f"代码安全规则扫描: {code_issue_count} 项检查通过")

        return {
            "scan_scope": code_metadata.get("scan_scope", "full"),
            "file_count": len(code_metadata.get("changed_files", [])),
            "security_duration_ms": security_report.get("scan_duration_ms", 0),
            "migration_duration_ms": migration.get("scan_duration_ms", 0),
            "degraded": degraded,
            "degraded_reasons": degraded_reasons,
            "blocking_items": blocking_items,
            "warning_items": security_warnings + migration_warnings,
            "security_warnings": security_warnings,
            "migration_warnings": migration_warnings,
            "pass_items": pass_items,
            "full_report_url": f"/api/v1/tasks/{task_id}/report?format=html",
            "rules_url": "#",
        }

    # ------------------------------------------------------------------
    # Counting helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _count_blocking(conflict: dict[str, Any]) -> int:
        return sum(
            1 for d in conflict.get("decisions", [])
            if d.get("verdict") == "block"
        )

    @staticmethod
    def _count_warnings(conflict: dict[str, Any], migration: dict[str, Any]) -> int:
        security_warnings = sum(
            1 for d in conflict.get("decisions", [])
            if d.get("verdict") != "block"
        )
        migration_warnings = len(migration.get("breaking_changes", []))
        return security_warnings + migration_warnings

    @staticmethod
    def _count_pass(security_report: dict[str, Any]) -> int:
        vulns = security_report.get("vulnerabilities", [])
        issues = security_report.get("code_issues", [])
        non_blocking = sum(
            1 for v in vulns if not v.get("blocking", False)
        ) + sum(
            1 for i in issues if not i.get("blocking", False)
        )
        return non_blocking

    # ------------------------------------------------------------------
    # Evidence extraction (from security_report, not modified)
    # ------------------------------------------------------------------

    @staticmethod
    def _get_evidence_source(
        decision: dict[str, Any], security_report: dict[str, Any]
    ) -> str:
        finding_id = decision.get("finding_id", "")
        for v in security_report.get("vulnerabilities", []):
            if v.get("cve_id") == finding_id:
                return v.get("evidence_source", "unknown")
        for ci in security_report.get("code_issues", []):
            if ci.get("rule_id") == finding_id:
                return "Semgrep"
        return "unknown"

    @staticmethod
    def _get_location(
        decision: dict[str, Any], security_report: dict[str, Any]
    ) -> str:
        finding_id = decision.get("finding_id", "")
        for v in security_report.get("vulnerabilities", []):
            if v.get("cve_id") == finding_id:
                return v.get("file_location", "unknown")
        for ci in security_report.get("code_issues", []):
            if ci.get("rule_id") == finding_id:
                return f"{ci.get('file_path', '')}:L{ci.get('line_number', 0)}"
        return "unknown"

    @staticmethod
    def _get_fix_suggestion(
        decision: dict[str, Any], security_report: dict[str, Any]
    ) -> str:
        finding_id = decision.get("finding_id", "")
        for v in security_report.get("vulnerabilities", []):
            if v.get("cve_id") == finding_id:
                fv = v.get("fixed_version", "")
                return f"升级至 >= {fv}" if fv else "暂无修复版本"
        for ci in security_report.get("code_issues", []):
            if ci.get("rule_id") == finding_id:
                return ci.get("fix_suggestion", "") or "请参考规则文档修复"
        return ""

    # ------------------------------------------------------------------
    # Plain-text fallback
    # ------------------------------------------------------------------

    @staticmethod
    def _plain_text_fallback(variables: dict[str, Any]) -> str:
        """Minimal plain-text report when template rendering fails."""
        lines = [
            "## CodeGuard 安全分析报告",
            "",
            f"**阻断项**: {len(variables.get('blocking_items', []))}",
            f"**建议项**: {len(variables.get('warning_items', []))}",
            f"**通过项**: {len(variables.get('pass_items', []))}",
            "",
            "> 报告生成异常，以上为精简摘要。",
        ]
        return "\n".join(lines)
