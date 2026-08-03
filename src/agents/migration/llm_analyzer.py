"""LLM-assisted code impact analyzer.

STRICT BOUNDARY: LLM is ONLY used to map known Breaking Changes
(from official changelogs) to specific code lines in changed files.

The LLM does NOT:
- Discover new breaking changes (that's the changelog store's job)
- Make security decisions
- Participate in any safety-critical path

If the LLM is unavailable, this module degrades gracefully and
returns empty results. The deterministic ChangelogMatcher always
runs first and provides the baseline.
"""

from __future__ import annotations

import json
import os
from typing import Any

from src.core.constants import LLM_API_TIMEOUT
from src.core.errors import LLMTimeoutError
from src.storage.changelog_store import ChangelogStore


class LLMAnalyzer:
    """LLM-assisted code impact analysis for migration assessment.

    Usage:
        analyzer = LLMAnalyzer(api_key="...", model="deepseek-coder")
        impacts = await analyzer.analyze(
            changed_files=[...],
            breaking_changes=[...],
            framework="fastapi",
        )
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        timeout: int = LLM_API_TIMEOUT,
    ) -> None:
        self._api_key = api_key or os.getenv("LLM_API_KEY", "")
        self._model = model or os.getenv("LLM_MODEL", "deepseek-coder")
        self._base_url = base_url or os.getenv("LLM_BASE_URL", "https://api.deepseek.com")
        self._timeout = timeout

    async def analyze(
        self,
        changed_files: list[dict[str, Any]],
        breaking_changes: list[dict[str, Any]],
        *,
        framework: str = "",
        from_version: str = "",
        to_version: str = "",
    ) -> list[dict[str, Any]]:
        """LLM-assisted analysis of breaking change impact.

        Takes deterministic breaking changes from the rule store and
        asks the LLM to identify which specific code lines are affected.

        Args:
            changed_files: File metadata with content.
            breaking_changes: Breaking change rules from ChangelogStore.
            framework: Framework name.
            from_version: Current version.
            to_version: Target version.

        Returns:
            List of BreakingChangeImpact-like dicts with source='llm_analysis'.
            Empty list if LLM is unavailable or returns unusable output.
        """
        if not self._api_key or not breaking_changes:
            return []

        # Build a focused prompt: only ask about known breaking changes
        prompt = self._build_prompt(
            changed_files, breaking_changes, framework, from_version, to_version
        )

        try:
            response = await self._call_llm(prompt)
            return self._parse_response(response, breaking_changes)
        except (LLMTimeoutError, Exception):
            return []  # Degrade gracefully: no LLM results

    # ------------------------------------------------------------------
    # Prompt engineering
    # ------------------------------------------------------------------

    def _build_prompt(
        self,
        changed_files: list[dict[str, Any]],
        breaking_changes: list[dict[str, Any]],
        framework: str,
        from_version: str,
        to_version: str,
    ) -> str:
        """Build a structured prompt for the LLM.

        The prompt strictly constrains the LLM to only identify
        code affected by the KNOWN breaking changes below.
        """

        # Summarize breaking changes (limit to what the LLM needs)
        bc_summary = []
        for bc in breaking_changes:
            bc_summary.append(
                f"- {bc.get('id', '')}: {bc.get('description', '')}\n"
                f"  Deprecated API: {bc.get('deprecated_api', '')}\n"
                f"  Patterns to look for: {', '.join(bc.get('affected_patterns', []))}\n"
                f"  Fix: {bc.get('migration_guide', '')}"
            )

        # Include relevant file contents (truncated)
        file_summaries = []
        for f in changed_files[:50]:  # Max 50 files to stay within context
            content = (f.get("content") or f.get("diff_lines") or "")[:2000]
            if content.strip():
                file_summaries.append(
                    f"### {f.get('path', '')}\n```\n{content}\n```"
                )

        prompt = f"""You are analyzing code for a {framework} upgrade from {from_version} to {to_version}.

## Known Breaking Changes
{chr(10).join(bc_summary)}

## Changed Files
{chr(10).join(file_summaries) if file_summaries else '(no code files to analyze)'}

## Task
For each breaking change above, identify which files and line numbers are affected.
Only report findings for the KNOWN breaking changes listed above.
Do NOT invent new breaking changes.

Return JSON:
{{
  "findings": [
    {{
      "change_id": "<breaking change id from the list>",
      "affected_files": [
        {{"path": "src/file.py", "line_number": 42, "impact_level": "breaking"}}
      ]
    }}
  ]
}}
"""
        return prompt

    # ------------------------------------------------------------------
    # LLM call
    # ------------------------------------------------------------------

    async def _call_llm(self, prompt: str) -> str:
        """Call the LLM API with timeout and error handling."""
        import httpx

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self._model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,  # Low temp for deterministic analysis
            "max_tokens": 4096,
            "stream": False,
        }

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(self._timeout)) as client:
                response = await client.post(
                    f"{self._base_url}/v1/chat/completions",
                    headers=headers,
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
                return data["choices"][0]["message"]["content"]
        except httpx.TimeoutException as e:
            raise LLMTimeoutError(
                f"LLM analysis timed out after {self._timeout}s",
                retryable=True,
            ) from e
        except httpx.HTTPStatusError as e:
            raise Exception(f"LLM API error {e.response.status_code}") from e

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_response(
        self,
        raw_response: str,
        breaking_changes: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Parse LLM JSON response into BreakingChangeImpact dicts.

        Validates that the LLM only returns findings for known breaking changes.
        """
        # Extract JSON from response (may be wrapped in markdown)
        json_str = raw_response
        if "```json" in raw_response:
            json_str = raw_response.split("```json")[1].split("```")[0]
        elif "```" in raw_response:
            json_str = raw_response.split("```")[1].split("```")[0]

        try:
            data = json.loads(json_str.strip())
        except json.JSONDecodeError:
            return []  # Unparseable LLM output -> degrade

        findings = data.get("findings", [])
        if not isinstance(findings, list):
            return []

        # Index breaking changes by ID for validation
        bc_map = {bc.get("id", ""): bc for bc in breaking_changes}

        impacts = []
        for finding in findings:
            change_id = finding.get("change_id", "")
            bc = bc_map.get(change_id)
            if not bc:
                continue  # Skip LLM-invented changes

            affected = []
            for af in finding.get("affected_files", []):
                affected.append({
                    "path": af.get("path", ""),
                    "line_number": af.get("line_number", 0),
                    "code_snippet": "",
                    "impact_level": af.get("impact_level", "warning"),
                })

            if affected:
                impacts.append({
                    "change_desc": bc.get("description", ""),
                    "source": "llm_analysis",
                    "official_reference_url": bc.get("official_url", ""),
                    "affected_files": affected,
                    "fix_suggestion": bc.get("migration_guide", ""),
                })

        return impacts
