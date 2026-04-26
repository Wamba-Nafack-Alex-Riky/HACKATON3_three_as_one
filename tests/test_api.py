"""
Tests pour src/api/ — endpoints Flask
"""

import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Patcher le journal path pour les tests (évite d'écrire dans le projet)
import tempfile
import src.journal.logger as journal_logger
_tmp_journal = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
journal_logger.JOURNAL_PATH = _tmp_journal.name
_tmp_journal.close()

from src.api.app import app

# Reset firewall state
import src.responder.firewall as fw


@pytest.fixture
def client():
    app.config["TESTING"] = True
    fw._blocked.clear()
    with app.test_client() as c:
        yield c


class TestAPIStatus:
    def test_status_endpoint_returns_200(self, client):
        resp = client.get("/api/status")
        assert resp.status_code == 200

    def test_status_contains_required_fields(self, client):
        resp  = client.get("/api/status")
        data  = json.loads(resp.data)
        for field in ["status", "blocked_ips", "active_alerts", "system"]:
            assert field in data

    def test_status_is_running(self, client):
        resp = client.get("/api/status")
        data = json.loads(resp.data)
        assert data["status"] == "running"


class TestAPIAlerts:
    def test_alerts_endpoint_returns_200(self, client):
        resp = client.get("/api/alerts")
        assert resp.status_code == 200

    def test_alerts_contains_count_and_list(self, client):
        resp = client.get("/api/alerts")
        data = json.loads(resp.data)
        assert "count" in data
        assert "alerts" in data
        assert isinstance(data["alerts"], list)

    def test_alerts_for_ip_returns_200(self, client):
        resp = client.get("/api/alerts/185.1.2.3")
        assert resp.status_code == 200

    def test_alerts_for_ip_contains_ip_field(self, client):
        resp = client.get("/api/alerts/185.1.2.3")
        data = json.loads(resp.data)
        assert data["ip"] == "185.1.2.3"


class TestAPIJournal:
    def test_journal_endpoint_returns_200(self, client):
        resp = client.get("/api/journal")
        assert resp.status_code == 200

    def test_journal_contains_entries(self, client):
        resp = client.get("/api/journal")
        data = json.loads(resp.data)
        assert "entries" in data
        assert "count" in data


class TestAPIBlocked:
    def test_blocked_endpoint_returns_200(self, client):
        resp = client.get("/api/blocked")
        assert resp.status_code == 200

    def test_blocked_list_is_dict(self, client):
        resp = client.get("/api/blocked")
        data = json.loads(resp.data)
        assert "blocked" in data
        assert isinstance(data["blocked"], dict)

    def test_unblock_non_existing_ip_returns_200(self, client):
        # Déblocage d'une IP non bloquée → succès (idempotent)
        resp = client.post("/api/unblock/185.99.99.99")
        assert resp.status_code == 200

    def test_block_then_unblock_via_api(self, client):
        ip = "185.10.10.10"
        # Bloquer manuellement
        fw.block_ip(ip, reason="test api")
        assert fw.is_blocked(ip)
        # Débloquer via API
        resp = client.post(f"/api/unblock/{ip}")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["unblocked"] is True


class TestAPIWhitelist:
    def test_whitelist_valid_ip(self, client):
        resp = client.post("/api/whitelist/192.168.99.99")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["whitelisted"] is True

    def test_whitelist_invalid_ip_returns_400(self, client):
        resp = client.post("/api/whitelist/not-an-ip")
        assert resp.status_code == 400


class TestAPIConfidence:
    def test_confidence_unknown_ip_returns_found_false(self, client):
        resp = client.get("/api/confidence/1.2.3.4")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["found"] is False
        assert data["ip"] == "1.2.3.4"
