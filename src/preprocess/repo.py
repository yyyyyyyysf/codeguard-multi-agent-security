"""Repository operations for preprocessing.

Handles cloning, pulling, diff extraction, and working directory management.
All operations are synchronous (called from Celery worker, not async context).
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from git import GitCommandError, Repo
from git.exc import GitError

from src.core.constants import DEFAULT_BRANCH, GIT_CLONE_DEPTH, GIT_CLONE_TIMEOUT
from src.core.errors import RepoCloneFailedError
from src.core.models import ChangeType


def clone_or_pull(
    repo_url: str,
    work_dir: str | Path,
    *,
    branch: str = DEFAULT_BRANCH,
    depth: int = GIT_CLONE_DEPTH,
    head_branch: str | None = None,
) -> Repo:
    """Clone repo if not present, otherwise pull latest.

    In DIFF mode the shallow clone only has the base branch commits.
    When *head_branch* is provided (the PR source branch name),
    ``git fetch origin <head_branch>`` pulls the missing commits so
    ``repo.commit(head_sha)`` succeeds during diff extraction.

    Note: GitHub prohibits fetching unadvertised bare SHA hashes
    (``Server does not allow request for unadvertised object``),
    so we must fetch by branch/tag name, not SHA.

    Args:
        repo_url: Remote repository URL.
        work_dir: Local working directory path.
        branch: Target branch to checkout (base branch for PRs).
        depth: Shallow clone depth (default 50).
        head_branch: Optional PR source branch name to fetch.

    Returns:
        GitPython Repo object.

    Raises:
        RepoCloneFailedError: If clone, pull, or fetch fails.
    """
    target = Path(work_dir)

    if target.exists() and (target / ".git").exists():
        try:
            repo = Repo(str(target))
            if hasattr(repo.remotes, 'origin'):
                origin = repo.remotes.origin
                origin.fetch()
                repo.git.checkout(branch)
                origin.pull(branch)
            if head_branch:
                _fetch_branch(repo, head_branch)
            return repo
        except GitError as e:
            raise RepoCloneFailedError(
                f"Failed to pull repo: {str(e)}", retryable=True
            ) from e

    # Fresh clone
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        repo = Repo.clone_from(
            repo_url,
            str(target),
            branch=branch,
            depth=depth,
        )
        if head_branch:
            _fetch_branch(repo, head_branch)
        return repo
    except GitCommandError as e:
        raise RepoCloneFailedError(
            f"Clone failed: {e.stderr.strip() if e.stderr else str(e)}",
            retryable=True,
        ) from e


def _fetch_branch(repo: Repo, branch_name: str) -> None:
    """Fetch a remote branch to pull in commits missing from shallow clone.

    GitHub prohibits ``git fetch origin <bare-sha>`` (unadvertised
    object), so we fetch by branch name instead.  Non-fatal: diff
    extraction will produce a clear error downstream if the branch
    name is wrong.
    """
    try:
        origin = repo.remotes.origin
        origin.fetch(branch_name)
    except GitError:
        pass


def get_diff_files(
    repo: Repo,
    base_sha: str,
    head_sha: str,
) -> list[dict[str, str]]:
    """Get list of changed files between two commits.

    Returns:
        List of dicts with keys: path, change_type, diff_content.
    """
    base = repo.commit(base_sha)
    head = repo.commit(head_sha)
    diff_index = base.diff(head)

    files = []
    for change in diff_index:
        change_type = _map_change_type(change.change_type)
        path = change.b_path or change.a_path

        try:
            diff_content = repo.git.diff(base_sha, head_sha, "--", path)
        except GitError:
            diff_content = ""

        files.append({
            "path": path,
            "change_type": change_type,
            "diff_content": diff_content,
        })

    return files


def get_file_content(repo: Repo, file_path: str, ref: str = "HEAD") -> str | None:
    """Get file content at a specific ref.

    Returns None if the file doesn't exist or is binary.
    """
    try:
        content = repo.git.show(f"{ref}:{file_path}")
        return content
    except GitError:
        return None


def list_all_files(repo: Repo) -> list[str]:
    """List all tracked files in the repository."""
    try:
        return repo.git.ls_files().splitlines()
    except GitError:
        return []


def get_commit_info(repo: Repo) -> dict[str, str]:
    """Get basic commit info for HEAD."""
    head = repo.head.commit
    return {
        "sha": head.hexsha,
        "message": head.message.strip(),
        "author": str(head.author),
        "committed_at": head.committed_datetime.isoformat(),
    }


def cleanup_work_dir(work_dir: str | Path) -> None:
    """Remove a working directory and all its contents."""
    target = Path(work_dir)
    if target.exists():
        shutil.rmtree(str(target), ignore_errors=True)


def _map_change_type(git_change_type: str) -> str:
    """Map GitPython change type to our ChangeType enum values."""
    mapping = {"A": ChangeType.ADDED.value, "M": ChangeType.MODIFIED.value, "D": ChangeType.DELETED.value}
    return mapping.get(git_change_type, ChangeType.MODIFIED.value)
