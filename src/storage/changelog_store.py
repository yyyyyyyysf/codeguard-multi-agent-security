"""Breaking Changes rule store.

Loads and queries framework-specific Breaking Changes rules
from local YAML files. These rules are deterministic and curated
from official changelogs.

MVP: FastAPI rules only. v0.2+: Django, Flask, etc.

Rule file format (YAML):
    framework: fastapi
    from_version: "0.100.0"
    to_version: "0.110.0"
    breaking_changes:
      - id: "BC-001"
        description: "response_model parameter removed"
        severity: high
        deprecated_api: "response_model"
        affected_patterns:
          - "response_model="
        official_url: "https://fastapi.tiangolo.com/release-notes/"
        migration_guide: "Use return type annotations instead."
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class ChangelogStore:
    """Framework Breaking Changes rule store.

    Usage:
        store = ChangelogStore("config/breaking_changes")
        changes = store.get_breaking_changes("fastapi", "0.100.0", "0.110.0")
    """

    def __init__(self, rules_dir: str | None = None) -> None:
        self._rules_dir = Path(rules_dir or "config/breaking_changes")
        self._cache: dict[str, list[dict[str, Any]]] = {}

    def get_breaking_changes(
        self,
        framework: str,
        from_version: str,
        to_version: str,
    ) -> list[dict[str, Any]]:
        """Get Breaking Changes for a version upgrade.

        Args:
            framework: Framework name ("fastapi", "django", etc.).
            from_version: Current version.
            to_version: Target version.

        Returns:
            List of Breaking Change dicts. Empty if no rules found.
        """
        cache_key = f"{framework}:{from_version}->{to_version}"

        if cache_key in self._cache:
            return self._cache[cache_key]

        # Try exact match file first
        rule_file = self._rules_dir / f"{framework}_{from_version}_{to_version}.yaml"
        if not rule_file.exists():
            # Try partial match (any file for this framework)
            candidates = list(self._rules_dir.glob(f"{framework}_*.yaml"))
            if candidates:
                rule_file = candidates[0]

        if not rule_file.exists():
            self._cache[cache_key] = []
            return []

        try:
            with open(rule_file, encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception:
            self._cache[cache_key] = []
            return []

        changes = self._parse_rules(data)
        self._cache[cache_key] = changes
        return changes

    def list_frameworks(self) -> list[str]:
        """List all frameworks with rules available."""
        frameworks: set[str] = set()
        for rule_file in self._rules_dir.glob("*.yaml"):
            name = rule_file.stem
            # Format: {framework}_{from}_{to}
            parts = name.split("_")
            if parts:
                frameworks.add(parts[0])
        return sorted(frameworks)

    def reload(self) -> None:
        """Clear cache and reload rules from disk on next query."""
        self._cache.clear()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_rules(data: dict[str, Any] | None) -> list[dict[str, Any]]:
        if not data:
            return []

        changes = data.get("breaking_changes", [])
        parsed = []
        for bc in changes:
            parsed.append({
                "id": bc.get("id", ""),
                "description": bc.get("description", ""),
                "severity": bc.get("severity", "high"),
                "deprecated_api": bc.get("deprecated_api", ""),
                "affected_patterns": bc.get("affected_patterns", []),
                "official_url": bc.get("official_url", ""),
                "migration_guide": bc.get("migration_guide", ""),
            })
        return parsed
