"""
Tests pour src/detector/ — ssh_rules, http_classifier, network_anomaly, behavior, time_windows
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.detector.ssh_rules   import SSHAnalyzer
from src.detector.behavior    import BehaviorProfiler
from src.detector.time_windows import WindowTracker
from datetime import datetime, timezone, timedelta


# ── SSH Rules ─────────────────────────────────────────────────────────────────

class TestSSHRules:
    def _make_record(self, ip, event, ts):
        return {
            "source": "ssh", "ip": ip, "event": event,
            "user": "root", "timestamp_log": ts,
            "timestamp_recv": ts, "ip_is_external": True,
            "log_hash": "abc", "integrity_ok": True,
        }

    def test_legitimate_login_no_alert(self):
        analyzer = SSHAnalyzer()
        r = self._make_record("10.0.0.5", "Accepted publickey", "2026-04-25T10:00:00")
        result = analyzer.analyze(r)
        assert result["prediction"] == "legit"
        assert result["detector_score"] == 0

    def test_single_failure_no_alert(self):
        analyzer = SSHAnalyzer()
        r = self._make_record("185.1.2.3", "Failed password", "2026-04-25T10:00:00")
        result = analyzer.analyze(r)
        assert result["detector_score"] < 50   # Pas d'alerte sur 1 seul échec

    def test_brute_force_10s_triggers_alert(self):
        analyzer = SSHAnalyzer(thresholds={"window_10s": 3, "window_1h": 15, "window_24h": 40})
        ip = "185.1.2.3"
        base = datetime(2026, 4, 25, 10, 0, 0, tzinfo=timezone.utc)
        for i in range(4):
            ts = (base + timedelta(seconds=i)).isoformat()
            r = self._make_record(ip, "Failed password", ts)
            result = analyzer.analyze(r)
        # Après 4 échecs en moins de 10s → score élevé
        assert result["detector_score"] >= 80
        assert result["prediction"] == "attack"

    def test_brute_force_batch_sorted(self):
        analyzer = SSHAnalyzer()
        base = datetime(2026, 4, 25, 10, 0, 0, tzinfo=timezone.utc)
        records = [
            {"source": "ssh", "ip": "185.9.9.9", "event": "Failed password",
             "user": "root", "timestamp_log": (base + timedelta(seconds=i)).isoformat(),
             "timestamp_recv": (base + timedelta(seconds=i)).isoformat(),
             "ip_is_external": True, "log_hash": str(i), "integrity_ok": True}
            for i in range(5)
        ]
        results = analyzer.analyze_batch(records)
        assert len(results) == 5
        assert results[-1]["ssh_fail_10s"] >= 4

    def test_internal_ip_with_failures_gets_alert(self):
        """Twist 3 : une IP interne avec des échecs doit alerter sans auto-bloquer."""
        analyzer = SSHAnalyzer(thresholds={"window_10s": 3, "window_1h": 15, "window_24h": 40})
        ip = "10.0.0.50"
        base = datetime(2026, 4, 25, 10, 0, 0, tzinfo=timezone.utc)
        for i in range(4):
            ts = (base + timedelta(seconds=i)).isoformat()
            r = {**self._make_record(ip, "Failed password", ts), "ip_is_external": False}
            result = analyzer.analyze(r)
        # Score élevé détecté même sur IP interne
        assert result["detector_score"] > 0


# ── Behavior Profiler ─────────────────────────────────────────────────────────

class TestBehaviorProfiler:
    def _make_apache_record(self, ip, path="/", method="GET", status=200,
                             agent="Mozilla", is_external=False):
        return {
            "source": "apache", "ip": ip, "method": method,
            "path": path, "status": status, "user_agent": agent,
            "ip_is_external": is_external, "timestamp_log": "2026-04-25T10:00:00",
            "agent_malicious": False, "path_sensitive": False,
            "path_sqli": False, "path_traversal": False,
        }

    def test_first_event_low_score(self):
        profiler = BehaviorProfiler()
        r = self._make_apache_record("10.0.0.1")
        result = profiler.update(r)
        assert result["behavioral_score"] < 30

    def test_malicious_agent_raises_score(self):
        profiler = BehaviorProfiler()
        r = self._make_apache_record("185.1.2.3", agent="nikto", is_external=True)
        r["agent_malicious"] = True
        result = profiler.update(r)
        assert result["behavioral_score"] >= 20

    def test_high_fail_rate_raises_score(self):
        profiler = BehaviorProfiler()
        ip = "185.5.5.5"
        for _ in range(8):
            profiler.update(self._make_apache_record(ip, status=404, is_external=True))
        r = profiler.update(self._make_apache_record(ip, status=404, is_external=True))
        assert r["behavioral_score"] > 30

    def test_sensitive_path_raises_score(self):
        profiler = BehaviorProfiler()
        r = self._make_apache_record("185.1.1.1", path="/.env", is_external=True)
        r["path_sensitive"] = True
        result = profiler.update(r)
        assert result["behavioral_score"] > 10

    def test_internal_ip_lower_score(self):
        profiler = BehaviorProfiler()
        r = self._make_apache_record("10.0.0.5", is_external=False)
        result = profiler.update(r)
        # IP interne, comportement normal → score faible
        assert result["behavioral_score"] < 20


# ── Time Windows ──────────────────────────────────────────────────────────────

class TestWindowTracker:
    def test_counts_within_window(self):
        tracker = WindowTracker()
        base = datetime(2026, 4, 25, 10, 0, 0, tzinfo=timezone.utc)
        for i in range(5):
            tracker.add("185.1.1.1", base + timedelta(seconds=i))
        counts = tracker.counts("185.1.1.1", base + timedelta(seconds=4))
        assert counts["10s"] == 5
        assert counts["1h"]  == 5
        assert counts["24h"] == 5

    def test_old_events_excluded_from_10s_window(self):
        tracker = WindowTracker()
        base = datetime(2026, 4, 25, 10, 0, 0, tzinfo=timezone.utc)
        # Ajouter des événements anciens
        for i in range(3):
            tracker.add("185.1.1.1", base - timedelta(minutes=5 + i))
        # Ajouter des événements récents
        for i in range(2):
            tracker.add("185.1.1.1", base + timedelta(seconds=i))
        counts = tracker.counts("185.1.1.1", base + timedelta(seconds=2))
        assert counts["10s"]  == 2    # Seulement les récents
        assert counts["24h"]  == 5    # Tous

    def test_behavioral_score_ssh_high_frequency(self):
        tracker = WindowTracker()
        base = datetime(2026, 4, 25, 10, 0, 0, tzinfo=timezone.utc)
        for i in range(5):
            tracker.add("185.9.9.9", base + timedelta(seconds=i))
        score = tracker.behavioral_score("185.9.9.9", base + timedelta(seconds=5), source="ssh")
        assert score > 50

    def test_behavioral_score_http_low_frequency(self):
        tracker = WindowTracker()
        base = datetime(2026, 4, 25, 10, 0, 0, tzinfo=timezone.utc)
        tracker.add("10.0.0.1", base)
        score = tracker.behavioral_score("10.0.0.1", base, source="apache")
        assert score < 10   # 1 seul événement = suspicion nulle
