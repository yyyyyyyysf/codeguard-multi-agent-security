"""Migration Assessment Agent — Deterministic rules + LLM-assisted analysis.

Orchestrates:
1. ChangelogMatcher: AST/regex deterministic matching (ALWAYS runs first).
2. LLMAnalyzer: Maps breaking changes to code lines (LLM-assisted, optional).
3. Risk + effort assessment: Aggregates results into MigrationReport.

Design invariants:
- LLM NEVER discovers new breaking changes (that's the changelog store's job).
- This agent's output NEVER enters the security decision pipeline.
- All LLM findings are marked source='llm_analysis' for traceability.
- Degradation: LLM unavailable -> AST-only results, confidence=low.
"""

from __future__ import annotations

import time
from typing import Any

from src.agents.migration.changelog_matcher import ChangelogMatcher
from src.agents.migration.llm_analyzer import LLMAnalyzer
from src.agents.migration.models import (
    AffectedFile,
    BreakingChangeImpact,
    EffortEstimate,
    MigrationReport,
)
from src.engine.base_agent import BaseAgent
from src.utils.id_gen import generate_id
from src.utils.logging import get_logger

logger = get_logger(__name__)


class MigrationAssessmentAgent(BaseAgent):
    """Migration assessment agent: deterministic rules + LLM-assisted analysis.

    Input:  CodeMetadata (changed_files) + target_version info
    Output: MigrationReport (breaking changes + affected files + risk level)
    """

    agent_id = "migration_assessment"
    description = (
        "Analyzes framework/package upgrade impact using deterministic "
        "breaking-change rules and LLM-assisted code mapping. Advisory only."
    )

    def __init__(
        self,
        llm_api_key: str | None = None,
        llm_model: str | None = None,
        changelog_store_path: str | None = None,
    ) -> None:
        super().__init__()
        self._matcher = ChangelogMatcher()
        self._llm = LLMAnalyzer(
            api_key=llm_api_key,
            model=llm_model,
        )

    # ------------------------------------------------------------------
    # Core logic
    # ------------------------------------------------------------------

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        """Execute migration assessment.

        Args:
            code_metadata: CodeMetadata dict with changed_files.
            target_version: {framework, from_version, to_version} dict.
            scan_id: Associated scan ID.

        Returns:
            MigrationReport as dict.
        """
        code_metadata = kwargs.get("code_metadata", {})
        target_version = kwargs.get("target_version", {})
        scan_id = kwargs.get("scan_id", generate_id())
        started = time.monotonic()

        framework = target_version.get("framework", "")
        from_ver = target_version.get("from_version", "")
        to_ver = target_version.get("to_version", "")

        changed_files = code_metadata.get("changed_files", [])
        degraded = False
        degraded_reasons: list[str] = []

        # --- Step 1: AST/regex deterministic matching (ALWAYS runs) ---
        ast_impacts: list[dict[str, Any]] = []
        if framework and from_ver and to_ver:
            ast_impacts = self._matcher.match(
                changed_files, framework, from_ver, to_ver
            )
        else:
            degraded = True
            degraded_reasons.append("No target version specified; skipping migration analysis")

        # --- Step 2: LLM-assisted analysis (optional, can degrade) ---
        llm_impacts: list[dict[str, Any]] = []
        if framework:
            # Get breaking changes for LLM context
            from src.storage.changelog_store import ChangelogStore
            store = ChangelogStore()
            breaking_changes = store.get_breaking_changes(framework, from_ver, to_ver)

            if breaking_changes:
                try:
                    llm_impacts = await self._llm.analyze(
                        changed_files=changed_files,
                        breaking_changes=breaking_changes,
                        framework=framework,
                        from_version=from_ver,
                        to_version=to_ver,
                    )
                except Exception as e:
                    degraded = True
                    degraded_reasons.append(f"LLM analysis failed: {str(e)[:200]}")
                    logger.warning("llm_analysis_degraded", reason=str(e)[:200])

        # --- Step 3: Merge and deduplicate ---
        all_impacts = self._merge_impacts(ast_impacts, llm_impacts)

        # --- Step 4: Risk assessment ---
        risk_level = self._assess_risk(all_impacts, from_ver, to_ver)
        effort = self._estimate_effort(all_impacts, degraded)

        # --- Step 5: Assemble report ---
        duration_ms = int((time.monotonic() - started) * 1000)

        impacts = []
        for imp in all_impacts:
            affected = []
            for af in imp.get("affected_files", []):
                affected.append(AffectedFile(
                    path=af.get("path", ""),
                    line_number=af.get("line_number", 0),
                    code_snippet=af.get("code_snippet", "")[:200],
                    impact_level=af.get("impact_level", "warning"),
                ))
            impacts.append(BreakingChangeImpact(
                change_desc=imp.get("change_desc", ""),
                source=imp.get("source", "ast_rule"),
                official_reference_url=imp.get("official_reference_url"),
                affected_files=affected,
                fix_suggestion=imp.get("fix_suggestion", ""),
            ))

        report = MigrationReport(
            scan_id=scan_id,
            framework=framework,
            from_version=from_ver,
            to_version=to_ver,
            breaking_changes=impacts,
            risk_level=risk_level,
            effort_estimate=effort,
            degraded=degraded,
            degraded_reasons=degraded_reasons,
            scan_duration_ms=duration_ms,
        )

        logger.info(
            "migration_assessment_complete",
            scan_id=scan_id,
            framework=framework,
            total_impacts=len(impacts),
            ast_count=report.ast_rule_count,
            llm_count=report.llm_analysis_count,
            risk_level=risk_level,
            degraded=degraded,
        )

        return report.model_dump()

    # ------------------------------------------------------------------
    # Degradation
    # ------------------------------------------------------------------

    async def degraded_run(
        self, original_error: Exception, **kwargs: Any
    ) -> dict[str, Any]:
        """Fallback: AST-only matching, no LLM."""
        code_metadata = kwargs.get("code_metadata", {})
        target_version = kwargs.get("target_version", {})
        scan_id = kwargs.get("scan_id", generate_id())

        framework = target_version.get("framework", "")
        from_ver = target_version.get("from_version", "")
        to_ver = target_version.get("to_version", "")

        changed_files = code_metadata.get("changed_files", [])
        ast_impacts = self._matcher.match(changed_files, framework, from_ver, to_ver) if framework else []

        all_impacts = self._merge_impacts(ast_impacts, [])
        risk_level = self._assess_risk(all_impacts, from_ver, to_ver)

        report = MigrationReport(
            scan_id=scan_id,
            framework=framework,
            from_version=from_ver,
            to_version=to_ver,
            breaking_changes=[
                BreakingChangeImpact(
                    change_desc=imp.get("change_desc", ""),
                    source=imp.get("source", "ast_rule"),
                    official_reference_url=imp.get("official_reference_url"),
                    affected_files=[
                        AffectedFile(**af) for af in imp.get("affected_files", [])
                    ],
                    fix_suggestion=imp.get("fix_suggestion", ""),
                )
                for imp in all_impacts
            ],
            risk_level=risk_level,
            effort_estimate=self._estimate_effort(all_impacts, degraded=True),
            degraded=True,
            degraded_reasons=[f"Agent degraded: {str(original_error)[:200]}"],
        )

        return report.model_dump()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _merge_impacts(
        self, ast_impacts: list[dict[str, Any]], llm_impacts: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Merge AST and LLM impacts, deduplicating by change_desc + file path.

        AST findings take priority over LLM findings for the same file+change.
        """
        seen: set[tuple[str, str]] = set()
        merged: list[dict[str, Any]] = []

        # AST first (authoritative)
        for imp in ast_impacts:
            desc = imp.get("change_desc", "")
            for af in imp.get("affected_files", []):
                key = (desc, af.get("path", ""))
                if key not in seen:
                    seen.add(key)
            merged.append(imp)

        # LLM second (supplemental)
        for imp in llm_impacts:
            desc = imp.get("change_desc", "")
            new_affected = []
            for af in imp.get("affected_files", []):
                key = (desc, af.get("path", ""))
                if key not in seen:
                    seen.add(key)
                    new_affected.append(af)
            if new_affected:
                merged.append({**imp, "affected_files": new_affected})

        return merged

    def _assess_risk(
        self,
        impacts: list[dict[str, Any]],
        from_version: str,
        to_version: str,
    ) -> str:
        """Assess overall migration risk level.

        - high: Breaking changes found + major version bump.
        - medium: Breaking changes found or major version bump.
        - low: No breaking changes found, minor/patch bump.
        """
        if not impacts:
            return "low"

        breaking_count = sum(
            1 for imp in impacts
            for af in imp.get("affected_files", [])
            if af.get("impact_level") == "breaking"
        )

        is_major_bump = self._is_major_version_bump(from_version, to_version)

        if breaking_count >= 3 or (breaking_count > 0 and is_major_bump):
            return "high"
        if breaking_count > 0 or is_major_bump:
            return "medium"
        return "low"

    def _estimate_effort(
        self,
        impacts: list[dict[str, Any]],
        degraded: bool = False,
    ) -> EffortEstimate:
        """Estimate migration effort based on affected files and impact severity."""
        affected_files: set[str] = set()
        breaking_count = 0

        for imp in impacts:
            for af in imp.get("affected_files", []):
                affected_files.add(af.get("path", ""))
                if af.get("impact_level") == "breaking":
                    breaking_count += 1

        file_count = len(affected_files)
        # Rough heuristic: 0.5 person-day per affected file
        person_days = round(file_count * 0.5 + breaking_count * 0.5, 1)

        confidence = "low" if degraded else (
            "high" if file_count == 0 else "medium"
        )

        return EffortEstimate(
            affected_file_count=file_count,
            estimated_person_days=person_days,
            confidence=confidence,
        )

    @staticmethod
    def _is_major_version_bump(from_ver: str, to_ver: str) -> bool:
        """Check if the version bump is a major version change (semver)."""
        try:
            from_parts = [int(x) for x in from_ver.replace("v", "").split(".")]
            to_parts = [int(x) for x in to_ver.replace("v", "").split(".")]
            return len(to_parts) > 0 and len(from_parts) > 0 and to_parts[0] > from_parts[0]
        except (ValueError, IndexError):
            return False
