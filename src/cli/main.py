"""CodeGuard CLI — local pre-check tool for developers.

Usage:
    codeguard analyze ./my-project
    codeguard analyze ./my-project --target fastapi:0.100.0:0.110.0
    codeguard analyze ./my-project --json --output report.json
"""

from __future__ import annotations

import json
from pathlib import Path

import typer

app = typer.Typer(
    name="codeguard",
    help="Multi-Agent Code Repository Security Analysis Platform",
    no_args_is_help=True,
)


@app.command()
def analyze(
    repo_path: str = typer.Argument(..., help="Path to the local repository"),
    target: str | None = typer.Option(
        None, "--target", "-t",
        help="Migration target: framework:from_version:to_version (e.g., fastapi:0.100.0:0.110.0)",
    ),
    output: str | None = typer.Option(
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
        from src.core.models import ScanScope
        from src.engine.event_bus import EventBus
        from src.engine.orchestrator import Orchestrator
        from src.preprocess.metadata import run_preprocessing
        from src.utils.id_gen import generate_task_id

        task_id = generate_task_id()
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
        lang = metadata.get("language", "unknown")
        typer.echo(
            f"       Found {dep_count} dependencies, {file_count} files ({lang})"
        )

        # Register agents with the in-process orchestrator
        from src.agents.conflict.agent import ConflictResolutionAgent
        from src.agents.migration.agent import MigrationAssessmentAgent
        from src.agents.reporter.agent import ReportAggregationAgent
        from src.agents.security.agent import SecurityAuditAgent

        orchestrator = Orchestrator(redis_client=None, event_bus=EventBus())
        orchestrator.register_agent("security", SecurityAuditAgent())
        orchestrator.register_agent("conflict", ConflictResolutionAgent())
        orchestrator.register_agent("migration", MigrationAssessmentAgent())
        orchestrator.register_agent("reporter", ReportAggregationAgent())

        typer.echo("  [2/4] Security audit + conflict resolution...")
        report_data = await orchestrator.run_analysis(
            task_id=task_id,
            scan_id=task_id,
            repo_url=str(repo),
            code_metadata=metadata,
            scan_scope=scan_scope_enum,
            target_version=target_version,
            scan_config={"block_severity": severity},
        )

        report = report_data.get("aggregated", {})
        overall_blocking = report_data.get("security", {}).get(
            "overall_blocking", False
        )
        security_report = report.get("security", {}).get("security_report", {})
        vuln_count = len(security_report.get("vulnerabilities", []))
        issue_count = len(security_report.get("code_issues", []))

        return report, overall_blocking, vuln_count, issue_count, task_id

    report, overall_blocking, vuln_count, issue_count, task_id = asyncio.run(
        run_analysis()
    )

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

    # Persist to report storage (same layout as API/Celery mode):
    # {REPORT_STORAGE_DIR}/{scan_id}/report.json + pr_comment.md
    try:
        from src.storage.report_store import LocalFileReportStorage

        storage = LocalFileReportStorage()
        storage.save_json(task_id, report)
        storage.save_markdown(
            task_id, report.get("pr_comment_markdown", ""), filename="pr_comment.md"
        )
        typer.echo(f"\n  Report persisted to: {storage._base / task_id}")
    except Exception as exc:  # non-fatal: persistence must not break the scan
        typer.echo(f"\n  (report persistence skipped: {exc})")

    if overall_blocking:
        raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Print CodeGuard version."""
    typer.echo("CodeGuard v0.1.0")


if __name__ == "__main__":
    app()
