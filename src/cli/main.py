"""CodeGuard CLI — local pre-check tool for developers.

Usage:
    codeguard analyze ./my-project
    codeguard analyze ./my-project --target fastapi:0.100.0:0.110.0
    codeguard analyze ./my-project --json --output report.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer

app = typer.Typer(
    name="codeguard",
    help="Multi-Agent Code Repository Security Analysis Platform",
    no_args_is_help=True,
)


@app.command()
def analyze(
    repo_path: str = typer.Argument(..., help="Path to the local repository"),
    target: Optional[str] = typer.Option(
        None, "--target", "-t",
        help="Migration target: framework:from_version:to_version (e.g., fastapi:0.100.0:0.110.0)",
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Save report to file (JSON format)"
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Output raw JSON instead of Markdown"
    ),
    scan_type: str = typer.Option(
        "full", "--scan-type", "-s", help="Scan type: full or diff"
    ),
    branch: str = typer.Option("main", "--branch", "-b", help="Target branch"),
    no_migration: bool = typer.Option(
        False, "--no-migration", help="Skip migration assessment"
    ),
    severity: str = typer.Option(
        "high", "--block-severity", help="Blocking threshold: high or critical"
    ),
) -> None:
    """Run a local security analysis on a repository.

    This runs the full analysis pipeline locally without needing
    a GitHub webhook or API server. Results are printed to stdout
    and optionally saved to a JSON file.
    """
    repo = Path(repo_path).resolve()

    if not repo.exists():
        typer.echo(f"Error: Repository path does not exist: {repo_path}", err=True)
        raise typer.Exit(code=1)

    if not (repo / ".git").exists():
        typer.echo(f"Error: Not a git repository: {repo_path}", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"CodeGuard v0.1 — Analyzing {repo.name}...\n")

    # Parse target
    target_version = None
    if target and not no_migration:
        parts = target.split(":")
        if len(parts) == 3:
            target_version = {
                "framework": parts[0],
                "from_version": parts[1],
                "to_version": parts[2],
            }
            typer.echo(f"  Migration target: {parts[0]} {parts[1]} -> {parts[2]}")
        else:
            typer.echo("  Warning: Invalid target format. Use framework:from:to", err=True)

    # Phase 1: Preprocess
    typer.echo("  [1/4] Preprocessing...")
    import asyncio

    async def run_analysis():
        # Preprocess
        from src.preprocess.metadata import run_preprocessing
        from src.utils.id_gen import generate_task_id

        task_id = generate_task_id()
        from src.core.models import ScanScope
        scan_scope_enum = ScanScope.FULL if scan_type == "full" else ScanScope.DIFF
        metadata = run_preprocessing(
            repo_url=f"file://{repo}",
            work_dir=str(repo),
            task_id=task_id,
            scan_id=task_id,
            scan_scope=scan_scope_enum,
            branch=branch,
        )
        dep_count = len(metadata.get("dependencies", []))
        file_count = len(metadata.get("changed_files", []))
        typer.echo(f"       Found {dep_count} dependencies, {file_count} files ({metadata.get('language', 'unknown')})")

        # Phase 2: Security
        typer.echo("  [2/4] Security audit...")
        from src.agents.security.agent import SecurityAuditAgent

        security_agent = SecurityAuditAgent()
        security_result = await security_agent.execute(
            code_metadata=metadata,
            scan_scope=scan_type,
            scan_id=task_id,
            scan_config={"block_severity": severity},
        )
        security_data = security_result.get("data", {})
        vuln_count = len(security_data.get("vulnerabilities", []))
        issue_count = len(security_data.get("code_issues", []))
        blocking = sum(
            1 for v in security_data.get("vulnerabilities", []) if v.get("blocking")
        ) + sum(1 for i in security_data.get("code_issues", []) if i.get("blocking"))

        # Phase 2b: Conflict resolution
        typer.echo("  [2/4] Resolving conflicts...")
        from src.agents.conflict.agent import ConflictResolutionAgent

        conflict_agent = ConflictResolutionAgent()
        conflict_result = await conflict_agent.execute(
            security_report=security_data,
            code_metadata=metadata,
            task_id=task_id,
            scan_id=task_id,
        )
        conflict_data = conflict_result.get("data", {})
        overall_blocking = conflict_data.get("overall_blocking", False)

        # Phase 3: Migration (optional)
        migration_data = {}
        if target_version:
            typer.echo("  [3/4] Migration assessment...")
            from src.agents.migration.agent import MigrationAssessmentAgent

            mig_agent = MigrationAssessmentAgent()
            mig_result = await mig_agent.execute(
                code_metadata=metadata,
                target_version=target_version,
                scan_id=task_id,
            )
            migration_data = mig_result.get("data", {})

        # Phase 4: Report
        typer.echo("  [4/4] Generating report...")
        from src.agents.reporter.agent import ReportAggregationAgent

        reporter = ReportAggregationAgent()
        report_result = await reporter.execute(
            security_data={"security": security_data, "conflict": conflict_data},
            migration_data=migration_data,
            repo_url=str(repo),
            code_metadata=metadata,
            scan_id=task_id,
            task_id=task_id,
        )

        return report_result.get("data", {}), overall_blocking, vuln_count, issue_count

    report, overall_blocking, vuln_count, issue_count = asyncio.run(run_analysis())

    # Output
    typer.echo("")
    if json_output:
        typer.echo(json.dumps(report, indent=2, default=str, ensure_ascii=False))
    else:
        # Print summary
        summary = report.get("summary", {})
        typer.echo("=" * 56)
        typer.echo("  CodeGuard Analysis Complete")
        typer.echo("=" * 56)
        typer.echo(f"  Blocking:  {summary.get('blocking_count', '?')}")
        typer.echo(f"  Warnings:  {summary.get('warning_count', '?')}")
        typer.echo(f"  Passed:    {summary.get('pass_count', '?')}")
        typer.echo("=" * 56)

        if overall_blocking:
            typer.echo("\n  MERGE BLOCKED — fix the issues above before merging.")

        # Print PR comment
        pr_md = report.get("pr_comment_markdown", "")
        if pr_md:
            typer.echo(f"\n{pr_md}")

    # Save to file
    if output:
        output_path = Path(output)
        output_path.write_text(
            json.dumps(report, indent=2, default=str, ensure_ascii=False),
            encoding="utf-8",
        )
        typer.echo(f"\n  Report saved to: {output_path}")

    if overall_blocking:
        raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Print CodeGuard version."""
    typer.echo("CodeGuard v0.1.0")


if __name__ == "__main__":
    app()
