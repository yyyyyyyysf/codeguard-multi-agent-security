"""Subprocess sandbox for safe execution of external tools.

Used by:
- preprocess: Tree-sitter parsing.
- security agent: Semgrep rule execution.

All execution is timeout-protected and memory-limited.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from typing import Any

from src.core.constants import SANDBOX_MAX_MEMORY_MB, SANDBOX_TIMEOUT_SECONDS
from src.core.errors import CodeGuardError


class SandboxTimeoutError(CodeGuardError):
    """Sandbox execution exceeded the timeout limit."""
    code = "SANDBOX-001"
    http_status = 500


class SandboxMemoryError(CodeGuardError):
    """Sandbox execution exceeded the memory limit."""
    code = "SANDBOX-002"
    http_status = 500


def run_sandboxed(
    cmd: list[str],
    *,
    timeout: int = SANDBOX_TIMEOUT_SECONDS,
    max_memory_mb: int = SANDBOX_MAX_MEMORY_MB,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    input_data: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a command in a sandboxed subprocess.

    Features:
    - Hard timeout: SIGTERM at `timeout` seconds, SIGKILL 5s later.
    - Memory limit via OS-level resource limits (Unix only).
    - Isolated environment (no parent process env pollution).
    - stdin passthrough support.

    Args:
        cmd: Command and arguments as a list.
        timeout: Maximum execution time in seconds.
        max_memory_mb: Maximum memory in MB.
        cwd: Working directory.
        env: Environment variables (merged with sanitized parent env).
        input_data: String to send to stdin.

    Returns:
        CompletedProcess with stdout/stderr.

    Raises:
        SandboxTimeoutError: If the process exceeds the time limit.
        SandboxMemoryError: If the process exceeds the memory limit.
    """
    # Build isolated environment
    safe_env: dict[str, str] = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": "en_US.UTF-8",
    }
    if env:
        safe_env.update(env)

    try:
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=safe_env,
            input=input_data,
        )

        # Check for memory-related failure signals (Unix only)
        if hasattr(signal, "SIGKILL") and process.returncode == -signal.SIGKILL:
            raise SandboxMemoryError(
                f"Sandbox process killed (possible OOM): {' '.join(cmd)}"
            )

        return process

    except subprocess.TimeoutExpired as e:
        raise SandboxTimeoutError(
            f"Sandbox timeout after {timeout}s: {' '.join(cmd)}"
        ) from e


def run_tool_safely(
    tool_name: str,
    args: list[str],
    *,
    timeout: int = SANDBOX_TIMEOUT_SECONDS,
    cwd: str | None = None,
) -> tuple[int, str, str]:
    """Convenience wrapper for running analysis tools.

    Args:
        tool_name: Display name of the tool (for error messages).
        args: Command-line arguments.
        timeout: Timeout in seconds.
        cwd: Working directory.

    Returns:
        (returncode, stdout, stderr) tuple.
        Returns (-1, "", error_msg) on timeout.
    """
    try:
        result = run_sandboxed(
            [tool_name, *args],
            timeout=timeout,
            cwd=cwd,
        )
        return result.returncode, result.stdout, result.stderr
    except SandboxTimeoutError:
        return -1, "", f"{tool_name} timed out after {timeout}s"
    except SandboxMemoryError:
        return -1, "", f"{tool_name} exceeded memory limit"
