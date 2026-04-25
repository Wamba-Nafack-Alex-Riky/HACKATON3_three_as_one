"""
Tests pour src/scorer/ — risk_scorer, confidence, cost_scorer
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.scorer.risk_scorer import score, is_whitelisted, compute_fp_cost
from src.scorer.confidence  import compute_confidence
from src.scorer.cost_scorer import compute_fp_cost as cost_scorer_fp


# ── Risk Scorer ───────────────────────────────────────────────────────────────

class TestRiskScorer:
    def _base_record(self, ip="185.1.2.3", is_external=True,
                     detector_score=0.0, behavioral_score=0.0,
                     confidence_penalty=0.0):
        return {
            "ip": ip,
            "ip_is_external": is_external,
            "detector_score": detector_score,
            "behavioral_score": behavioral_score,
            "confidence_penalty": confidence_penalty,
            "user": "",
            "win_24h": 0,
        }

    def test_zero_scores_give_zero_risk(self):
        r = self._base_record(detector_score=0, behavioral_score=0)
        result = score(r)
        assert result["risk_score"] == 0.0

    def test_high_detector_score_gives_high_risk(self):
        r = self._base_record(detector_score=90, behavioral_score=70)
        result = score(r)
        assert result["risk_score"] >= 70.0

    def test_confidence_penalty_reduces_risk(self):
        r_no_penalty = self._base_record(detector_score=80, confidence_penalty=0.0)
        r_with_penalty = self._base_record(detector_score=80, confidence_penalty=0.5)
        res_no = score(r_no_penalty)
        res_with = score(r_with_penalty)
        assert res_with["risk_score"] < res_no["risk_score"]

    def test_risk_score_capped_at_100(self):
        r = self._base_record(detector_score=100, behavioral_score=100)
        result = score(r)
        assert result["risk_score"] <= 100.0

    def test_decision_score_is_risk_minus_fp_cost(self):
        r = self._base_record(ip="10.0.0.5", is_external=False,
                              detector_score=80, behavioral_score=0)
        result = score(r)
        # IP interne a un fp_cost élevé → decision_score < risk_score
        assert result["decision_score"] <= result["risk_score"]

    def test_whitelisted_ip_has_high_fp_cost(self):
        cost = compute_fp_cost({"ip": "10.0.0.11", "ip_is_external": False, "win_24h": 0})
        assert cost >= 60.0  # IP dans whitelist.yaml

    def test_unknown_external_ip_has_low_fp_cost(self):
        cost = compute_fp_cost({"ip": "185.255.1.1", "ip_is_external": True, "win_24h": 0})
        assert cost <= 30.0


class TestWhitelist:
    def test_internal_range_is_whitelisted(self):
        assert is_whitelisted("10.0.0.50") is True

    def test_external_ip_not_whitelisted(self):
        assert is_whitelisted("185.255.255.255") is False

    def test_trusted_ip_is_whitelisted(self):
        # 10.0.0.11 est dans whitelist.yaml
        assert is_whitelisted("10.0.0.11") is True

    def test_trusted_user_is_whitelisted(self):
        assert is_whitelisted("185.1.1.1", user="deploy") is True


# ── Confidence Scorer ─────────────────────────────────────────────────────────

class TestConfidenceScorer:
    def test_fresh_log_high_confidence(self):
        r = {
            "source": "apache", "ip": "185.1.1.1",
            "timestamp_log":  "2026-04-25T10:00:00",
            "timestamp_recv": "2026-04-25T10:00:02",  # 2s de délai
            "integrity_ok": True,
            "method": "GET", "path": "/", "status": 200,
        }
        result = compute_confidence(r)
        assert result["confidence_score"] >= 90.0
        assert result["confidence_penalty"] < 0.10

    def test_late_log_reduced_confidence(self):
        r = {
            "source": "ssh", "ip": "185.1.1.1",
            "timestamp_log":  "2026-04-25T08:00:00",
            "timestamp_recv": "2026-04-25T10:00:00",  # 2h de retard
            "integrity_ok": True,
            "user": "root", "event": "Failed password",
        }
        result = compute_confidence(r)
        assert result["confidence_score"] < 80.0
        assert result["confidence_penalty"] > 0.0

    def test_tampered_log_low_confidence(self):
        r = {
            "source": "apache", "ip": "185.1.1.1",
            "timestamp_log":  "2026-04-25T10:00:00",
            "timestamp_recv": "2026-04-25T10:00:02",
            "integrity_ok": False,  # log falsifié
            "method": "GET", "path": "/", "status": 200,
        }
        result = compute_confidence(r)
        assert result["confidence_score"] < 70.0
        assert result["confidence_penalty"] >= 0.40

    def test_incomplete_record_penalized(self):
        r = {
            "source": "apache", "ip": "185.1.1.1",
            # method et path manquants
            "integrity_ok": True,
        }
        result = compute_confidence(r)
        assert result["missing_fields"] >= 2
        assert result["confidence_penalty"] > 0.0


# ── Cost Scorer ───────────────────────────────────────────────────────────────

class TestCostScorer:
    def test_whitelisted_ip_max_cost(self):
        r = {"ip": "10.0.0.11", "ip_is_external": False, "win_24h": 0,
             "confidence_score": 100.0, "event": ""}
        cost = cost_scorer_fp(r)
        assert cost >= 80.0

    def test_unknown_external_ip_low_cost(self):
        r = {"ip": "185.255.0.1", "ip_is_external": True, "win_24h": 0,
             "confidence_score": 100.0, "event": ""}
        cost = cost_scorer_fp(r)
        assert cost <= 15.0

    def test_accepted_publickey_raises_cost(self):
        r = {"ip": "10.0.0.5", "ip_is_external": False, "win_24h": 0,
             "confidence_score": 100.0, "event": "Accepted publickey"}
        cost = cost_scorer_fp(r)
        assert cost > 50.0

    def test_very_active_ip_higher_cost(self):
        r_normal = {"ip": "185.1.1.1", "ip_is_external": True, "win_24h": 5,
                    "confidence_score": 100.0, "event": ""}
        r_active = {"ip": "185.1.1.1", "ip_is_external": True, "win_24h": 200,
                    "confidence_score": 100.0, "event": ""}
        cost_normal = cost_scorer_fp(r_normal)
        cost_active = cost_scorer_fp(r_active)
        assert cost_active > cost_normal
