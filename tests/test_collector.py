"""
Tests pour src/collector/ — normalizer.py et integrity.py
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.collector.normalizer import load_apache, load_ssh, load_network
from src.collector.integrity import check_integrity, compute_hash, verify_hash

APACHE_PATH  = "data/sample_logs/apache_access_1.csv"
SSH_PATH     = "data/sample_logs/auth_ssh_1.csv"
NETWORK_PATH = "data/sample_logs/network_flows_1.csv"


# ── Normalizer ────────────────────────────────────────────────────────────────

class TestApacheNormalizer:
    def test_load_returns_list(self):
        records = load_apache(APACHE_PATH)
        assert isinstance(records, list)
        assert len(records) > 0

    def test_record_has_required_fields(self):
        records = load_apache(APACHE_PATH)
        r = records[0]
        for field in ["ip", "method", "path", "status", "label", "log_hash"]:
            assert field in r, f"Champ manquant : {field}"

    def test_labels_are_valid(self):
        records = load_apache(APACHE_PATH)
        valid = {"legit", "attack", "scan"}
        for r in records:
            assert r["label"] in valid, f"Label invalide : {r['label']}"

    def test_ip_is_external_field_exists(self):
        records = load_apache(APACHE_PATH)
        for r in records:
            assert "ip_is_external" in r
            assert isinstance(r["ip_is_external"], bool)

    def test_internal_ips_are_not_external(self):
        records = load_apache(APACHE_PATH)
        for r in records:
            if str(r.get("ip", "")).startswith("10."):
                assert r["ip_is_external"] is False


class TestSSHNormalizer:
    def test_load_returns_list(self):
        records = load_ssh(SSH_PATH)
        assert isinstance(records, list)
        assert len(records) > 0

    def test_record_has_required_fields(self):
        records = load_ssh(SSH_PATH)
        r = records[0]
        for field in ["ip", "user", "event", "log_hash"]:
            assert field in r

    def test_failed_password_label(self):
        records = load_ssh(SSH_PATH)
        for r in records:
            if r.get("event") == "Failed password":
                assert r["label"] == "attack"

    def test_accepted_publickey_label(self):
        records = load_ssh(SSH_PATH)
        for r in records:
            if r.get("event") == "Accepted publickey":
                assert r["label"] == "legit"


class TestNetworkNormalizer:
    def test_load_returns_list(self):
        records = load_network(NETWORK_PATH)
        assert isinstance(records, list)
        assert len(records) > 0

    def test_label_is_none(self):
        records = load_network(NETWORK_PATH)
        for r in records:
            assert r.get("label") is None  # non supervisé

    def test_flag_syn_only_field(self):
        records = load_network(NETWORK_PATH)
        for r in records:
            assert "flag_syn_only" in r
            assert isinstance(r["flag_syn_only"], bool)


# ── Integrity ─────────────────────────────────────────────────────────────────

class TestIntegrity:
    def test_hash_is_deterministic(self):
        h1 = compute_hash("test content")
        h2 = compute_hash("test content")
        assert h1 == h2

    def test_hash_differs_on_different_content(self):
        assert compute_hash("aaa") != compute_hash("bbb")

    def test_verify_hash_ok(self):
        content = "log entry: 185.1.1.1 GET /admin"
        h = compute_hash(content)
        assert verify_hash(content, h) is True

    def test_verify_hash_fails_on_tampered(self):
        content = "log entry: 185.1.1.1 GET /admin"
        h = compute_hash(content)
        assert verify_hash("tampered content", h) is False

    def test_check_integrity_adds_fields(self):
        record = {
            "ip": "185.1.2.3",
            "timestamp_log":  "2026-04-25T02:00:00",
            "timestamp_recv": "2026-04-25T02:01:10",
            "integrity_ok": True,
        }
        result = check_integrity(record, late_threshold_seconds=60)
        assert "late_seconds" in result
        assert "confidence_penalty" in result
        assert result["late_seconds"] >= 0

    def test_late_log_adds_penalty(self):
        record = {
            "ip": "10.0.0.5",
            "timestamp_log":  "2026-04-25T01:00:00",
            "timestamp_recv": "2026-04-25T02:00:00",  # 3600s de retard
            "integrity_ok": True,
        }
        result = check_integrity(record, late_threshold_seconds=60)
        assert result["confidence_penalty"] > 0.0
        assert result["late_seconds"] == 3600

    def test_tampered_log_max_penalty(self):
        record = {
            "ip": "185.1.2.3",
            "timestamp_log":  "2026-04-25T02:00:00",
            "timestamp_recv": "2026-04-25T02:00:01",
            "integrity_ok": False,
        }
        result = check_integrity(record)
        assert result["confidence_penalty"] >= 0.8
