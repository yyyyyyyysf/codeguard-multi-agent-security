"""Tests for appeal_resume_task — human-in-the-loop continuation."""

import json
from unittest.mock import MagicMock, patch

import pytest


class TestAppealResumeTask:
    @pytest.fixture(autouse=True)
    def mock_redis(self):
        mock_redis = MagicMock()
        mock_redis.from_url.return_value = mock_redis
        with patch("src.tasks.appeal._redis_module", mock_redis):
            yield mock_redis

    def _mock_agent(self, pending, final_decision):
        mock_agent = MagicMock()

        async def fake_get_pending(*args, **kwargs):
            return pending

        mock_agent.get_pending_human_items.side_effect = fake_get_pending

        async def fake_resume(**kwargs):
            return final_decision

        mock_agent.resume_with_human_input.side_effect = fake_resume
        return mock_agent

    def test_resolves_appeal(self, mock_redis):
        from src.tasks.appeal import appeal_resume_task

        final = {"overall_blocking": False, "decisions": []}
        mock_agent = self._mock_agent(["CVE-2024-0001"], final)
        mock_audit = MagicMock()
        mock_rule_store = MagicMock()

        with patch("src.agents.conflict.agent.ConflictResolutionAgent", return_value=mock_agent), \
             patch("src.storage.audit_log.AuditLogger", return_value=mock_audit), \
             patch("src.storage.rule_store.RuleStore", return_value=mock_rule_store):
            result = appeal_resume_task(
                appeal_id="a1",
                task_id="t1",
                finding_id="CVE-2024-0001",
                decision="waive",
                reason="edge case",
            )

        assert result["status"] == "resolved"
        assert result["decision"] == "waive"
        mock_agent.resume_with_human_input.assert_called_once()
        mock_audit.log.assert_called_once()

        # Appeal status + security cache both updated in Redis.
        setex_keys = [call.args[0] for call in mock_redis.setex.call_args_list]
        assert any("codeguard:appeal:a1" in k for k in setex_keys)
        assert any("codeguard:task:t1:security" in k for k in setex_keys)

    def test_no_pending_state_fails_safe(self, mock_redis):
        from src.tasks.appeal import appeal_resume_task

        mock_agent = self._mock_agent([], {})
        mock_audit = MagicMock()

        with patch("src.agents.conflict.agent.ConflictResolutionAgent", return_value=mock_agent), \
             patch("src.storage.audit_log.AuditLogger", return_value=mock_audit), \
             patch("src.storage.rule_store.RuleStore", return_value=MagicMock()):
            result = appeal_resume_task(
                appeal_id="a2",
                task_id="t2",
                finding_id="CVE-2024-0001",
            )

        assert result["status"] == "failed"
        assert result["error"] == "no_pending_human_state"
        mock_agent.resume_with_human_input.assert_not_called()

    def test_finding_not_pending_fails_safe(self, mock_redis):
        from src.tasks.appeal import appeal_resume_task

        mock_agent = self._mock_agent(["CVE-OTHER"], {})
        with patch("src.agents.conflict.agent.ConflictResolutionAgent", return_value=mock_agent), \
             patch("src.storage.audit_log.AuditLogger", return_value=MagicMock()), \
             patch("src.storage.rule_store.RuleStore", return_value=MagicMock()):
            result = appeal_resume_task(
                appeal_id="a3",
                task_id="t3",
                finding_id="CVE-2024-0001",
            )

        assert result["status"] == "failed"
        assert result["error"] == "finding_not_pending"
        mock_agent.resume_with_human_input.assert_not_called()


class TestAppealRedisHelpers:
    def test_mark_appeal_status_preserves_record(self):
        from src.tasks.appeal import _mark_appeal_status

        mock_redis = MagicMock()
        mock_redis.from_url.return_value = mock_redis
        mock_redis.get.return_value = json.dumps({"appeal_id": "a1", "status": "pending_review"})
        with patch("src.tasks.appeal._redis_module", mock_redis):
            _mark_appeal_status("a1", "resolved")

        stored = json.loads(mock_redis.setex.call_args[0][2])
        assert stored["status"] == "resolved"

    def test_mark_appeal_status_redis_down(self):
        from src.tasks.appeal import _mark_appeal_status

        mock_redis = MagicMock()
        mock_redis.from_url.side_effect = Exception("Connection refused")
        with patch("src.tasks.appeal._redis_module", mock_redis):
            _mark_appeal_status("a1", "resolved")  # Must not raise

    def test_update_security_cache_replaces_conflict(self):
        from src.tasks.appeal import _update_security_cache

        mock_redis = MagicMock()
        mock_redis.from_url.return_value = mock_redis
        mock_redis.get.return_value = json.dumps(
            {"conflict": {"overall_blocking": True}, "security": {}}
        )
        with patch("src.tasks.appeal._redis_module", mock_redis):
            _update_security_cache("t1", {"overall_blocking": False})

        stored = json.loads(mock_redis.setex.call_args[0][2])
        assert stored["conflict"]["overall_blocking"] is False
