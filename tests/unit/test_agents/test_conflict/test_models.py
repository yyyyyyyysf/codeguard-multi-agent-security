"""Tests for Conflict Resolution Agent data models."""

from src.agents.conflict.models import (
    AuditEntry,
    AuditTrail,
    FinalSecurityDecision,
    ResolutionConfig,
    SecurityVerdict,
)


class TestSecurityVerdict:
    def test_block_verdict(self):
        v = SecurityVerdict(
            finding_id="CVE-2024-0001",
            finding_type="vulnerability",
            verdict="block",
            reason="High severity in direct dependency",
            rule_id="auto:high_severity_block",
            operator="auto",
            appealable=True,
        )
        assert v.verdict == "block"
        assert v.appealable

    def test_waive_verdict(self):
        v = SecurityVerdict(
            finding_id="CVE-2024-0001",
            finding_type="vulnerability",
            verdict="waive",
            reason="CVE in exemption whitelist",
            rule_id="exempt-001",
            operator="auto",
        )
        assert v.verdict == "waive"

    def test_default_operator(self):
        v = SecurityVerdict(
            finding_id="test",
            finding_type="code_issue",
            verdict="block",
            reason="test",
        )
        assert v.operator is None  # Default


class TestAuditTrail:
    def test_empty_trail(self):
        trail = AuditTrail()
        assert trail.count == 0

    def test_append_entries(self):
        trail = AuditTrail()
        trail.append(AuditEntry(
            timestamp="2024-01-01T00:00:00Z",
            action="verdict_made",
            detail={"finding": "CVE-1", "verdict": "block"},
        ))
        trail.append(AuditEntry(
            timestamp="2024-01-01T00:00:01Z",
            action="appeal_submitted",
            detail={"finding": "CVE-1"},
            operator="human:alice",
        ))
        assert trail.count == 2
        assert trail.entries[0].action == "verdict_made"
        assert trail.entries[1].operator == "human:alice"


class TestFinalSecurityDecision:
    def test_no_findings_no_block(self):
        decision = FinalSecurityDecision(scan_id="s1")
        assert not decision.overall_blocking
        assert decision.blocking_count == 0
        assert decision.waived_count == 0

    def test_mixed_verdicts(self):
        decision = FinalSecurityDecision(
            scan_id="s1",
            overall_blocking=True,
            decisions=[
                SecurityVerdict(
                    finding_id="CVE-1", finding_type="vulnerability",
                    verdict="block", reason="high",
                ),
                SecurityVerdict(
                    finding_id="CVE-2", finding_type="vulnerability",
                    verdict="waive", reason="whitelist",
                ),
                SecurityVerdict(
                    finding_id="rule-1", finding_type="code_issue",
                    verdict="block", reason="hardcoded key",
                ),
            ],
        )
        assert decision.blocking_count == 2
        assert decision.waived_count == 1
        assert decision.deferred_count == 0
        assert decision.overall_blocking

    def test_human_intervention_pending(self):
        decision = FinalSecurityDecision(
            scan_id="s1",
            human_intervention_required=True,
            pending_human_items=["CVE-2024-0001"],
        )
        assert decision.human_intervention_required
        assert len(decision.pending_human_items) == 1


class TestResolutionConfig:
    def test_defaults(self):
        config = ResolutionConfig()
        assert config.human_loop_timeout_hours == 24
        assert config.critical_cannot_waive
        assert config.auto_waive_low_confidence
        assert config.fail_safe_blocking

    def test_custom_timeout(self):
        config = ResolutionConfig(human_loop_timeout_hours=48)
        assert config.human_loop_timeout_hours == 48
