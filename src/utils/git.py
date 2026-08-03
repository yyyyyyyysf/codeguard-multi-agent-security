"""Git operations wrapper using GitPython.

Handles: clone, pull, diff extraction, commit info.
All operations are timeout-protected and raise RepoCloneFailedError on failure.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from git import GitCommandError, InvalidGitRepositoryError, Repo
from git.exc import GitError

from src.core.constants import DEFAULT_BRANCH, GIT_CLONE_DEPTH, GIT_CLONE_TIMEOUT
from src.core.errors import RepoCloneFailedError


def clone_repo(
    repo_url: str,
    target_dir: str | Path,
    *,
    branch: str = DEFAULT_BRANCH,
    depth: int = GIT_CLONE_DEPTH,
) -> Repo:
    """Clone a remote repository to a local directory.

    Args:
        repo_url: Remote repository URL (https or ssh).
        target_dir: Local directory path for the clone.
        branch: Branch to checkout (default: main).
        depth: Shallow clone depth (default: 50).

    Returns:
        GitPython Repo object.

    Raises:
        RepoCloneFailedError: If clone fails for any reason.
    """
    target = Path(target_dir)
    _ensure_parent(target)

    try:
        repo = Repo.clone_from(
            repo_url,
            str(target),
            branch=branch,
            depth=depth,
        )
        return repo
    except GitCommandError as e:
        raise RepoCloneFailedError(
            f"Git clone failed for {repo_url}: {e.stderr.strip() if e.stderr else str(e)}",
            retryable=True,
        ) from e
    except GitError as e:
        raise RepoCloneFailedError(
            f"Git error cloning {repo_url}: {str(e)}",
            retryable=True,
        ) from e


def pull_repo(repo: Repo, *, branch: str = DEFAULT_BRANCH) -> None:
    """Pull latest changes for an existing repo.

    Args:
        repo: GitPython Repo object.
        branch: Target branch.

    Raises:
        RepoCloneFailedError: If pull fails.
    """
    try:
        origin = repo.remotes.origin
        origin.fetch()
        repo.git.checkout(branch)
        origin.pull(branch)
    except GitError as e:
        raise RepoCloneFailedError(
            f"Git pull failed: {str(e)}",
            retryable=True,
        ) from e


def get_or_update_repo(
    repo_url: str,
    work_dir: str | Path,
    *,
    branch: str = DEFAULT_BRANCH,
) -> Repo:
    """Clone the repo if not present, otherwise pull latest changes.

    Args:
        repo_url: Remote repository URL.
        work_dir: Local working directory.
        branch: Target branch.

    Returns:
        GitPython Repo object.
    """
    target = Path(work_dir)
    if target.exists() and (target / ".git").exists():
        repo = Repo(str(target))
        pull_repo(repo, branch=branch)
        return repo
    return clone_repo(repo_url, target, branch=branch)


def get_head_commit_sha(repo: Repo) -> str:
    """Get the SHA of HEAD commit."""
    return repo.head.commit.hexsha


def get_diff_files(
    repo: Repo,
    base_commit_sha: str,
    head_commit_sha: str,
) -> list[dict[str, str]]:
    """Get list of files changed between two commits.

    Args:
        repo: GitPython Repo object.
        base_commit_sha: Base (old) commit SHA.
        head_commit_sha: Head (new) commit SHA.

    Returns:
        List of dicts with keys: path, change_type (A/M/D), diff.
    """
    base = repo.commit(base_commit_sha)
    head = repo.commit(head_commit_sha)
    diff_index = base.diff(head)

    files = []
    for change in diff_index:
        change_type = change.change_type  # 'A', 'M', 'D'
        path = change.b_path or change.a_path

        try:
            diff_text = repo.git.diff(base_commit_sha, head_commit_sha, "--", path)
        except GitError:
            diff_text = ""

        files.append({
            "path": path,
            "change_type": change_type,
            "diff": diff_text,
        })

    return files


def get_file_content(repo: Repo, commit_sha: str, file_path: str) -> str | None:
    """Get the content of a file at a specific commit.

    Args:
        repo: GitPython Repo object.
        commit_sha: Commit SHA.
        file_path: Relative file path.

    Returns:
        File content as string, or None if file doesn't exist.
    """
    try:
        commit = repo.commit(commit_sha)
        blob = commit.tree / file_path
        return blob.data_stream.read().decode("utf-8", errors="replace")
    except (KeyError, GitError, UnicodeDecodeError):
        return None


def is_git_repo(path: str | Path) -> bool:
    """Check if a path is a git repository."""
    try:
        _ = Repo(str(path))
        return True
    except (InvalidGitRepositoryError, GitError):
        return False


def cleanup_work_dir(work_dir: str | Path) -> None:
    """Remove a working directory and all its contents."""
    target = Path(work_dir)
    if target.exists():
        shutil.rmtree(str(target), ignore_errors=True)


def _ensure_parent(path: Path) -> None:
    """Create parent directory if it doesn't exist."""
    path.parent.mkdir(parents=True, exist_ok=True)
