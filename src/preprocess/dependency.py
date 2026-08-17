"""Dependency manifest parser.

Extracts direct and transitive dependencies from:
- requirements.txt (pip freeze format)
- pyproject.toml (PEP 621 / Poetry)
- package.json (npm) - for future multi-language support

Output: list[Dependency] with name, version, type (direct/transitive), ecosystem.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from src.core.errors import CodeGuardError
from src.core.models import DependencyType, Ecosystem


class DependencyParseError(CodeGuardError):
    """Failed to parse dependency file."""
    code = "ANALYSIS-004"
    http_status = 500


def parse_dependencies(
    repo_path: str | Path,
    language: str = "python",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Parse all dependency files in a repository.

    Args:
        repo_path: Path to the repository root.
        language: Programming language (default: python).

    Returns:
        (direct_deps, transitive_deps) tuple.
        Each dep: {name, version, dependency_type, ecosystem}
    """
    repo = Path(repo_path)
    direct: list[dict[str, Any]] = []
    transitive: list[dict[str, Any]] = []

    if language == "python":
        # Try pyproject.toml first
        pyproject = repo / "pyproject.toml"
        if pyproject.exists():
            direct = _parse_pyproject_toml(pyproject)
        else:
            # Fall back to requirements.txt
            req_file = repo / "requirements.txt"
            if req_file.exists():
                direct = _parse_requirements_txt(req_file)

        # Lock files for transitive deps
        lock_file = repo / "poetry.lock"
        if lock_file.exists():
            transitive = _parse_poetry_lock(lock_file)

    elif language == "javascript":
        pkg_json = repo / "package.json"
        if pkg_json.exists():
            direct = _parse_package_json(pkg_json)

    return direct, transitive


def _parse_requirements_txt(filepath: Path) -> list[dict[str, Any]]:
    """Parse pip-style requirements.txt."""
    deps = []
    with open(filepath, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Parse "package==version" or "package>=version" etc.
            match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([><=!~]+\s*[\d.*]+(?:\s*,\s*[><=!~]+\s*[\d.*]+)*)?", line)  # noqa: E501
            if match:
                name = match.group(1).lower()
                version = match.group(2).strip() if match.group(2) else "latest"
                # Clean up version string
                version = re.sub(r"\s*,\s*", ",", version)
                deps.append({
                    "name": name,
                    "version": version,
                    "dependency_type": DependencyType.DIRECT.value,
                    "ecosystem": Ecosystem.PYPI.value,
                })

    return deps


def _parse_pyproject_toml(filepath: Path) -> list[dict[str, Any]]:
    """Parse PEP 621 pyproject.toml dependencies."""
    deps = []
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        import tomli as tomllib  # type: ignore[no-redef]

    try:
        with open(filepath, "rb") as f:
            data = tomllib.load(f)
    except Exception:
        return deps

    # PEP 621: [project].dependencies
    project = data.get("project", {})
    raw_deps = project.get("dependencies", [])

    for dep_str in raw_deps:
        parsed = _parse_pep508_dep(dep_str)
        if parsed:
            deps.append({
                "name": parsed["name"],
                "version": parsed["version"],
                "dependency_type": DependencyType.DIRECT.value,
                "ecosystem": Ecosystem.PYPI.value,
            })

    # Optional dependency groups
    optional = project.get("optional-dependencies", {})
    for _, group_deps in optional.items():
        for dep_str in group_deps:
            parsed = _parse_pep508_dep(dep_str)
            if parsed:
                deps.append({
                    "name": parsed["name"],
                    "version": parsed["version"],
                    "dependency_type": DependencyType.DIRECT.value,
                    "ecosystem": Ecosystem.PYPI.value,
                })

    return deps


def _parse_pep508_dep(dep_str: str) -> dict[str, str] | None:
    """Parse a single PEP 508 dependency string.
    e.g., 'fastapi>=0.110.0,<1.0.0' -> {name: 'fastapi', version: '>=0.110.0,<1.0.0'}
    """
    match = re.match(r"^([a-zA-Z0-9_.-]+)\s*(.*)$", dep_str.strip())
    if not match:
        return None
    return {
        "name": match.group(1).lower(),
        "version": match.group(2).strip() or "latest",
    }


def _parse_poetry_lock(filepath: Path) -> list[dict[str, Any]]:
    """Parse poetry.lock for transitive dependency info."""
    deps = []
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore[no-redef]

    try:
        with open(filepath, "rb") as f:
            data = tomllib.load(f)
    except Exception:
        return deps

    packages = data.get("package", [])
    for pkg in packages:
        name = pkg.get("name", "").lower()
        version = pkg.get("version", "")
        if name and version:
            deps.append({
                "name": name,
                "version": version,
                "dependency_type": DependencyType.TRANSITIVE.value,
                "ecosystem": Ecosystem.PYPI.value,
            })

    return deps


def _parse_package_json(filepath: Path) -> list[dict[str, Any]]:
    """Parse package.json for JavaScript/TypeScript dependencies."""
    import json

    deps = []
    try:
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return deps

    for section in ("dependencies", "devDependencies"):
        for name, version in data.get(section, {}).items():
            deps.append({
                "name": name,
                "version": version.lstrip("^~"),
                "dependency_type": DependencyType.DIRECT.value,
                "ecosystem": Ecosystem.NPM.value,
            })

    return deps
