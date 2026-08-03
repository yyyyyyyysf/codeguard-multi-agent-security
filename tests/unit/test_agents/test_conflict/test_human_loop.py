"""Tests for HumanLoopManager and its LangGraph state machine."""

import pytest
import time
from unittest.mock import MagicMock, patch
from src.agents.conflict.human_loop import (
    HumanLoopManager,
    HumanLoopState,
    HumanLoopStateData,
)


class TestHumanLoopManager:
    @pytest.fixture
    def manager(self):
        return HumanLoopManager(timeout_hours=1, fail_safe_blocking=True)

    @pytest.mark.asyncio
    async def test_request_input_pauses(self, manager):
        """Requesting human input returns pending state."""
        unresolved = [
            {"cve_id": "CVE-2024-0001", "severity": "high"},
            {"rule_id": "rule-abc", "severity": "medium"},
        ]
        state = await manager.request_human_input(
            unresolved, task_id="t1", scan_id="s1"
        )
        assert "pending_items" in state
        assert len(state["pending_items"]) == 2

    @pytest.mark.asyncio
    async def test_resume_with_input(self, manager):
        """After human provides decisions, state resolves."""
        unresolved = [
            {"cve_id": "CVE-2024-0001", "severity": "high"},
        ]
        await manager.request_human_input(unresolved, task_id="t1", scan_id="s1")
        state = await manager.resume_with_human_input(
            {"CVE-2024-0001": "waive"}
        )
        assert "resolved_items" in state or "status" in state

    @pytest.mark.asyncio
    async def test_timeout_detection(self, manager):
        """Timeout check works correctly."""
        unresolved = [{"cve_id": "CVE-1"}]
        # Set a timeout in the past
        with patch.object(manager, '_current_state', {
            "status": "waiting_for_human",
            "pending_items": unresolved,
            "resolved_items": [],
            "human_decisions": {},
            "timeout_at": time.time() - 10,  # Already timed out
            "error": "",
        }):
            assert manager.check_timeout()

    @pytest.mark.asyncio
    async def test_no_timeout_when_empty(self, manager):
        """No timeout when there's no pending state."""
        manager._current_state = None
        assert not manager.check_timeout()

    @pytest.mark.asyncio
    async def test_timeout_fallback_all_block(self, manager):
        """Timeout fallback returns 'block' for all pending items."""
        unresolved = [
            {"cve_id": "CVE-2024-0001", "finding_id": "CVE-2024-0001"},
        ]
        manager._current_state = {
            "status": "waiting",
            "pending_items": unresolved,
            "resolved_items": [],
            "human_decisions": {},
            "timeout_at": time.time() - 10,
            "error": "",
        }
        verdicts = manager.get_timeout_fallback_verdicts()
        assert "CVE-2024-0001" in verdicts
        assert verdicts["CVE-2024-0001"] == "block"

    @pytest.mark.asyncio
    async def test_empty_pending_skips(self, manager):
        """Empty pending list -> resolves immediately."""
        state = await manager.request_human_input([], task_id="t1", scan_id="s1")
        assert len(state.get("pending_items", [])) == 0

    @pytest.mark.asyncio
    async def test_resume_without_request_errors(self, manager):
        """Resuming without a prior request returns error."""
        manager._current_state = None
        state = await manager.resume_with_human_input({"x": "block"})
        assert state.get("status") == "error"


class TestHumanLoopNodes:
    """Test individual LangGraph node functions."""

    def test_validate_with_items(self):
        from src.agents.conflict.human_loop import HumanLoopManager
        state: HumanLoopStateData = {
            "status": "",
            "pending_items": [{"cve_id": "CVE-1"}],
            "resolved_items": [],
            "human_decisions": {},
            "timeout_at": time.time() + 3600,
            "error": "",
        }
        result = HumanLoopManager._validate_node(state)
        assert result["status"] == HumanLoopState.IDLE.value

    def test_validate_empty(self):
        from src.agents.conflict.human_loop import HumanLoopManager
        state: HumanLoopStateData = {
            "status": "",
            "pending_items": [],
            "resolved_items": [],
            "human_decisions": {},
            "timeout_at": time.time() + 3600,
            "error": "",
        }
        result = HumanLoopManager._validate_node(state)
        assert result["status"] == HumanLoopState.RESOLVED.value

    def test_human_review_waiting(self):
        from src.agents.conflict.human_loop import HumanLoopManager
        state: HumanLoopStateData = {
            "status": "",
            "pending_items": [{"cve_id": "CVE-1"}],
            "resolved_items": [],
            "human_decisions": {},
            "timeout_at": time.time() + 3600,
            "error": "",
        }
        result = HumanLoopManager._human_review_node(state)
        assert result["status"] == HumanLoopState.WAITING_FOR_HUMAN.value

    def test_human_review_timeout(self):
        from src.agents.conflict.human_loop import HumanLoopManager
        state: HumanLoopStateData = {
            "status": "",
            "pending_items": [{"cve_id": "CVE-1"}],
            "resolved_items": [],
            "human_decisions": {},
            "timeout_at": time.time() - 10,  # Past
            "error": "",
        }
        result = HumanLoopManager._human_review_node(state)
        assert result["status"] == HumanLoopState.TIMEOUT.value

    def test_apply_decisions(self):
        from src.agents.conflict.human_loop import HumanLoopManager
        state: HumanLoopStateData = {
            "status": "",
            "pending_items": [
                {"cve_id": "CVE-1", "severity": "high"},
                {"cve_id": "CVE-2", "severity": "medium"},
            ],
            "resolved_items": [],
            "human_decisions": {"CVE-1": "waive", "CVE-2": "block"},
            "timeout_at": time.time() + 3600,
            "error": "",
        }
        result = HumanLoopManager._apply_decisions_node(state)
        assert len(result["resolved_items"]) == 2
        assert result["resolved_items"][0]["verdict"] == "waive"
        assert result["resolved_items"][1]["verdict"] == "block"
        assert result["status"] == HumanLoopState.RESOLVED.value

    def test_timeout_handler(self):
        from src.agents.conflict.human_loop import HumanLoopManager
        state: HumanLoopStateData = {
            "status": "",
            "pending_items": [{"cve_id": "CVE-1"}, {"rule_id": "r1"}],
            "resolved_items": [],
            "human_decisions": {},
            "timeout_at": time.time() - 10,
            "error": "",
        }
        result = HumanLoopManager._timeout_handler_node(state)
        assert len(result["resolved_items"]) == 2
        assert all(r["verdict"] == "block" for r in result["resolved_items"])
        assert result["status"] == HumanLoopState.RESOLVED.value

    def test_after_human_review_routes(self):
        from src.agents.conflict.human_loop import HumanLoopManager
        state: HumanLoopStateData = {
            "status": HumanLoopState.HUMAN_RESPONDED.value,
            "pending_items": [],
            "resolved_items": [],
            "human_decisions": {"x": "block"},
            "timeout_at": 0,
            "error": "",
        }
        assert HumanLoopManager._after_human_review(state) == "apply"

        state["status"] = HumanLoopState.TIMEOUT.value
        assert HumanLoopManager._after_human_review(state) == "timeout"

        state["status"] = HumanLoopState.WAITING_FOR_HUMAN.value
        assert HumanLoopManager._after_human_review(state) == "wait"

    def test_config_defaults(self):
        manager = HumanLoopManager()
        assert manager._timeout_hours == 24
        assert manager._fail_safe_blocking

        manager2 = HumanLoopManager(timeout_hours=48, fail_safe_blocking=False)
        assert manager2._timeout_hours == 48
        assert not manager2._fail_safe_blocking
