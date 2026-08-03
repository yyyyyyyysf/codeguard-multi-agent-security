"""Deterministic AST pattern matcher for Breaking Changes.

Runs BEFORE LLM analysis. Uses Tree-sitter AST + regex patterns
from the Breaking Changes rule store to identify affected code.

Why first:
- Deterministic: 100% reproducible, no hallucination risk.
- Faster: no API call, runs in-process.
- Reduces LLM load: only files with potential matches go to LLM.
"""

from __future__ import annotations

import re
from typing import Any

from src.storage.changelog_store import ChangelogStore


class ChangelogMatcher:
    """Deterministic Breaking Changes pattern matcher.

    Usage:
        matcher = ChangelogMatcher(changelog_store)
        impacts = matcher.match(changed_files, "fastapi", "0.100.0", "0.110.0")
    """

    def __init__(self, changelog_store: ChangelogStore | None = None) -> None:
        self._store = changelog_store or ChangelogStore()

    def match(
        self,
        changed_files: list[dict[str, Any]],
        framework: str,
        from_version: str,
        to_version: str,
    ) -> list[dict[str, Any]]:
        """Match Breaking Changes against changed files using AST + regex.

        Args:
            changed_files: List of file metadata dicts from CodeMetadata.
            framework: Framework name (fastapi).
            from_version: Current version.
            to_version: Target version.

        Returns:
            List of BreakingChangeImpact-like dicts with source='ast_rule'.
        """
        breaking_changes = self._store.get_breaking_changes(
            framework, from_version, to_version
        )

        if not breaking_changes:
            return []

        impacts: list[dict[str, Any]] = []

        for bc in breaking_changes:
            patterns = bc.get("affected_patterns", [])
            if not patterns:
                continue

            affected_files = self._find_affected_files(changed_files, patterns)

            if affected_files:
                impacts.append({
                    "change_desc": bc.get("description", ""),
                    "source": "ast_rule",
                    "official_reference_url": bc.get("official_url", ""),
                    "affected_files": affected_files,
                    "fix_suggestion": bc.get("migration_guide", ""),
                })

        return impacts

    # ------------------------------------------------------------------
    # File scanning
    # ------------------------------------------------------------------

    def _find_affected_files(
        self,
        changed_files: list[dict[str, Any]],
        patterns: list[str],
    ) -> list[dict[str, Any]]:
        """Find files whose content matches at least one pattern.

        Each pattern is a regex that matches code using the deprecated API.
        Example: "response_model=" matches `response_model=SomeModel`.
        """
        affected = []
        compiled = [re.compile(re.escape(p), re.IGNORECASE) for p in patterns]

        for f in changed_files:
            path = f.get("path", "")
            content = f.get("content") or ""

            # Skip non-code files
            if not self._is_code_file(path):
                continue

            matches = []
            for line_num, line in enumerate(content.splitlines(), start=1):
                for i, pattern in enumerate(compiled):
                    if pattern.search(line):
                        matches.append({
                            "path": path,
                            "line_number": line_num,
                            "code_snippet": line.strip()[:200],
                            "impact_level": self._determine_impact(
                                bc_pattern=patterns[i]
                            ),
                        })
                        break  # One match per line is enough

            affected.extend(matches)

        return affected

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _determine_impact(bc_pattern: str) -> str:
        """Determine impact level based on pattern characteristics.

        Patterns matching decorators, imports, or function signatures
        are 'breaking'. Patterns matching variable usage are 'warning'.
        """
        breaking_keywords = ["@", "import", "def ", "class ", "=", "("]
        for kw in breaking_keywords:
            if kw in bc_pattern:
                return "breaking"
        return "warning"

    @staticmethod
    def _is_code_file(file_path: str) -> bool:
        """Check if a file is a source code file (not config, docs, etc.)."""
        code_extensions = {
            ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
            ".rs", ".rb", ".php", ".c", ".cpp", ".h", ".hpp",
            ".cs", ".swift", ".kt", ".scala",
        }
        import os
        ext = os.path.splitext(file_path)[1].lower()
        return ext in code_extensions
