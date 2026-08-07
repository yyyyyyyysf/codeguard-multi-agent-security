"""CodeMetadata assembler.

Orchestrates the preprocessing pipeline:
1. Clone/pull repo -> get changed files
2. Parse dependencies
3. Parse AST for changed files (or all files for full scan)
4. Detect language/tech stack
5. Assemble CodeMetadata (the canonical input for all Agents)

This is a pure orchestrator: it calls repo.py, dependency.py, parser.py
and assembles their output. NO LLM, NO external API calls.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from git import Repo

from src.core.constants import DEFAULT_BRANCH
from src.core.errors import ASTParseFailedError, RepoCloneFailedError
from src.core.models import ScanScope
from src.preprocess.dependency import parse_dependencies
from src.preprocess.parser import detect_language, parse_files_batch
from src.preprocess.repo import (
    clone_or_pull,
    get_commit_info,
    get_diff_files,
    get_file_content,
    list_all_files,
)


def run_preprocessing(
    repo_url: str,
    work_dir: str | Path,
    *,
    task_id: str,
    scan_id: str,
    scan_scope: ScanScope = ScanScope.FULL,
    base_sha: str | None = None,
    head_sha: str | None = None,
    branch: str = DEFAULT_BRANCH,
) -> dict[str, Any]:
    """Run the full preprocessing pipeline.

    Args:
        repo_url: Repository URL to analyze.
        work_dir: Working directory for repo clone.
        task_id: Associated task ID for tracing.
        scan_id: Associated scan ID for tracing.
        scan_scope: FULL or DIFF.
        base_sha: Base commit SHA (required for DIFF mode).
        head_sha: Head commit SHA (required for DIFF mode).
        branch: Target branch.

    Returns:
        CodeMetadata dict (the canonical input for all Agents).

    Raises:
        RepoCloneFailedError: If repo operations fail.
        ASTParseFailedError: If AST parsing fails for critical files.
    """
    # Step 1: Clone or pull repository
    repo = clone_or_pull(repo_url, work_dir, branch=branch, head_sha=head_sha)

    # Step 2: Get commit info
    commit_info = get_commit_info(repo)

    # Step 3: Determine changed files
    if scan_scope == ScanScope.DIFF and base_sha and head_sha:
        changed = get_diff_files(repo, base_sha, head_sha)
        file_paths = [f["path"] for f in changed]
    else:
        file_paths = list_all_files(repo)

    # Step 4: Detect primary language
    language = _detect_primary_language(file_paths)

    # Step 5: Parse dependencies
    direct_deps, transitive_deps = parse_dependencies(str(work_dir), language)

    # Step 6: Parse AST for relevant files
    ast_results = parse_files_batch(work_dir, file_paths)

    # Step 7: Build file metadata list
    files_meta = _build_files_meta(repo, file_paths, scan_scope, base_sha, head_sha)

    # Step 8: Assemble CodeMetadata
    metadata: dict[str, Any] = {
        "task_id": task_id,
        "scan_id": scan_id,
        "repo_url": repo_url,
        "repo_path": repo.working_dir,
        "commit_sha": commit_info.get("sha", ""),
        "base_commit_sha": base_sha,
        "head_commit_sha": head_sha,
        "scan_scope": scan_scope.value,
        "language": language,
        "commit_message": commit_info.get("message", ""),
        "commit_author": commit_info.get("author", ""),
        "committed_at": commit_info.get("committed_at", ""),
        "dependencies": direct_deps,
        "transitive_deps": transitive_deps,
        "changed_files": files_meta,
        "ast_trees": ast_results,
    }

    return metadata


def _detect_primary_language(file_paths: list[str]) -> str:
    """Detect the primary language of the repository.

    Uses a simple majority vote based on file extensions.
    """
    counts: dict[str, int] = {}
    for fpath in file_paths:
        lang = detect_language(fpath)
        if lang:
            counts[lang] = counts.get(lang, 0) + 1

    if not counts:
        return "unknown"

    return max(counts, key=counts.get)  # type: ignore[arg-type]


def _build_files_meta(
    repo: Repo,
    file_paths: list[str],
    scan_scope: ScanScope,
    base_sha: str | None = None,
    head_sha: str | None = None,
) -> list[dict[str, Any]]:
    """Build file metadata list for changed/all files."""
    from src.core.models import ChangeType

    files_meta = []

    for fpath in file_paths:
        # Get file size
        try:
            file_size = (Path(repo.working_dir) / fpath).stat().st_size
        except OSError:
            file_size = 0

        # Get language
        language = detect_language(fpath)

        # Get content
        content = get_file_content(repo, fpath)

        meta: dict[str, Any] = {
            "path": fpath,
            "change_type": ChangeType.MODIFIED.value,
            "diff_lines": None,
            "content": content,
            "language": language,
            "file_size": file_size,
        }

        if scan_scope == ScanScope.DIFF and base_sha and head_sha:
            try:
                meta["diff_lines"] = repo.git.diff(base_sha, head_sha, "--", fpath)
            except Exception:
                meta["diff_lines"] = ""

        files_meta.append(meta)

    return files_meta
