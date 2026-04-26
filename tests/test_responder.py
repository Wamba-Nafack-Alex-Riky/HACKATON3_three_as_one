"""
Tests pour src/responder/ — decision.py et firewall.py
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.responder.decision import decide, decide_batch
from src.responder.firewall import (
    block_ip, unblock_ip, is_blocked, get_blocked_list, apply_decision, DRY_RUN
)


# ── Decision ──────────────────────────────────────────────────────────────────

def _make_record(ip="185.1.2.3", decision_score=0.0, risk_score=0.0,
                 fp_cost=0.0, whitelisted=False, is_external=True, source="apache"):
    return {
        "ip": ip,
        "source": source,
        "decision_score": decision_score,
        "risk_score": risk_score,
        "fp_cost_score": fp_cost,
        "whitelisted": whitelisted,
        "ip_is_external": is_external,
        "agent_malicious": False,
        "path_sqli": False, "path_traversal": False, "path_sensitive": False,
        "rule_triggered": None,
        "behavioral_score": 0,
        "win_10s": 0, "win_1h": 0, "win_24h": 0,
        "late_seconds": 0, "integrity_ok": True,
    }


class TestDecision:
    def test_low_score_is_monitor(self):
        r = _make_record(decision_score=10.0)
        result = decide(r)
        assert result["response_level"] == 1
        assert result["decision"] == "MONITOR"

    def test_medium_score_is_alert(self):
        r = _make_record(decision_score=55.0)
        result = decide(r)
        assert result["response_level"] == 2
        assert result["decision"] == "ALERT"

    def test_high_score_is_slowdown(self):
        r = _make_record(decision_score=68.0)
        result = decide(r)
        assert result["response_level"] == 3
        assert result["decision"] == "SLOWDOWN"

    def test_critical_score_is_block(self):
        r = _make_record(decision_score=85.0)
        result = decide(r)
        assert result["response_level"] == 4
        assert result["decision"] == "BLOCK"

    def test_whitelisted_ip_never_blocked(self):
        r = _make_record(decision_score=95.0, whitelisted=True)
        result = decide(r)
        # Même avec score critique, IP whitelistée → jamais BLOCK
        assert result["decision"] != "BLOCK"
        assert result["response_level"] <= 2

    def test_evidence_list_is_populated(self):
        r = _make_record(decision_score=80.0, is_external=True)
        r["agent_malicious"] = True
        r["path_sqli"] = True
        result = decide(r)
        assert len(result["evidence"]) >= 2

    def test_justification_is_string(self):
        r = _make_record(decision_score=60.0)
        result = decide(r)
        assert isinstance(result["justification"], str)
        assert len(result["justification"]) > 0

    def test_batch_returns_correct_count(self):
        records = [_make_record(decision_score=i * 10) for i in range(5)]
        results = decide_batch(records)
        assert len(results) == 5

    def test_evidence_includes_ssh_rule(self):
        r = _make_record(source="ssh", decision_score=80.0)
        r["rule_triggered"] = "ssh_brute_force_10s"
        result = decide(r)
        assert any("SSH rule" in e for e in result["evidence"])


# ── Firewall (DRY-RUN) ────────────────────────────────────────────────────────

class TestFirewall:
    def setup_method(self):
        """Reset blocked list before each test."""
        from src.responder import firewall
        firewall._blocked.clear()

    def test_dry_run_is_enabled(self):
        assert DRY_RUN is True   # Ne jamais toucher le vrai iptables en test

    def test_block_ip_adds_to_list(self):
        block_ip("185.1.1.1", reason="test")
        assert is_blocked("185.1.1.1")

    def test_unblock_ip_removes_from_list(self):
        block_ip("185.2.2.2", reason="test")
        assert is_blocked("185.2.2.2")
        unblock_ip("185.2.2.2")
        assert not is_blocked("185.2.2.2")

    def test_double_block_idempotent(self):
        block_ip("185.3.3.3", reason="test")
        block_ip("185.3.3.3", reason="test again")
        blocked = get_blocked_list()
        # L'IP ne doit être enregistrée qu'une fois
        assert "185.3.3.3" in blocked

    def test_apply_decision_block_level_4(self):
        r = _make_record(ip="185.4.4.4", decision_score=90.0)
        r["response_level"] = 4
        r["justification"] = "Critical score"
        result = apply_decision(r)
        assert result["firewall_action"] in ("blocked", "block_failed")
        assert is_blocked("185.4.4.4")

    def test_apply_decision_monitor_no_action(self):
        r = _make_record(ip="185.5.5.5", decision_score=10.0)
        r["response_level"] = 1
        r["justification"] = "Low score"
        result = apply_decision(r)
        assert result["firewall_action"] == "none"
        assert not is_blocked("185.5.5.5")
