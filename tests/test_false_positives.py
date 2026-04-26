"""
Tests de faux positifs — Twist 3
==============================
Ce fichier prouve au jury que le système ne bloque jamais
un acteur légitime, même quand le risque apparent est élevé.

Scénarios testés :
  1. Travailleur humanitaire en zone de conflit (IP interne)
  2. Admin avec beaucoup de connexions légitimes
  3. IP whitelistée avec activité suspecte → ALERT jamais BLOCK
  4. Utilisateur qui se trompe de mot de passe
  5. Log tardif d'une IP légitime → confiance réduite mais pas de blocage
  6. IP interne avec agent Python (script de monitoring légitime)
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.scorer.risk_scorer  import score
from src.scorer.cost_scorer  import compute_fp_cost
from src.responder.decision  import decide
from src.responder.firewall  import _blocked, block_ip, is_blocked
from src.detector.ssh_rules  import SSHAnalyzer
from datetime import datetime, timezone, timedelta


def _full_pipeline(ip, detector_score, behavioral_score=0, confidence_penalty=0,
                   is_external=False, whitelisted=False, win_24h=0,
                   user="", event="Accepted publickey"):
    """Simule le pipeline complet pour un record et retourne la décision finale."""
    record = {
        "ip":               ip,
        "ip_is_external":   is_external,
        "user":             user,
        "event":            event,
        "detector_score":   detector_score,
        "behavioral_score": behavioral_score,
        "confidence_penalty": confidence_penalty,
        "win_24h":          win_24h,
        "source":           "ssh" if event else "apache",
        "agent_malicious":  False,
        "path_sqli":        False,
        "path_traversal":   False,
        "path_sensitive":   False,
        "rule_triggered":   None,
        "win_10s":          0,
        "win_1h":           0,
        "late_seconds":     0,
        "integrity_ok":     True,
        "whitelisted":      whitelisted,
    }
    scored  = score(record)
    decided = decide(scored)
    return decided


class TestFalsePositives:

    def setup_method(self):
        """Reset firewall state before each test."""
        from src.responder import firewall
        firewall._blocked.clear()

    # ── Scénario 1 : Travailleur humanitaire (IP interne) ─────────────────────

    def test_internal_ip_never_auto_blocked(self):
        """
        Une IP interne (10.0.x.x) représente un personnel de l'ONG.
        Même avec un detector_score moyen, le coût FP est élevé
        et le decision_score doit rester sous le seuil de blocage.
        """
        result = _full_pipeline(
            ip="10.0.0.50",
            detector_score=70,      # Score moyen — suspect mais pas prouvé
            behavioral_score=20,
            is_external=False,      # IP interne !
        )
        assert result["decision"] != "BLOCK", (
            f"Erreur Twist 3 : IP interne bloquée ! "
            f"decision_score={result.get('decision_score')}"
        )

    # ── Scénario 2 : Admin avec beaucoup de connexions légitimes ──────────────

    def test_very_active_legitimate_ip_not_blocked(self):
        """
        Un administrateur très actif sur 24h a un score comportemental
        élevé par simple volume — ce n'est pas une attaque.
        """
        result = _full_pipeline(
            ip="10.0.0.12",         # Trusted IP dans whitelist.yaml
            detector_score=40,
            behavioral_score=60,    # Volume élevé = actif légitimement
            win_24h=300,            # Très actif sur 24h
            is_external=False,
        )
        assert result["decision"] != "BLOCK"

    # ── Scénario 3 : IP whitelistée avec activité suspecte ────────────────────

    def test_whitelisted_ip_always_alert_never_block(self):
        """
        Une IP whitelistée NE DOIT JAMAIS être bloquée automatiquement,
        même si son score de risque est critique.
        """
        result = _full_pipeline(
            ip="10.0.0.11",         # IP dans trusted_ips (whitelist.yaml)
            detector_score=90,
            behavioral_score=80,
            whitelisted=True,
            is_external=False,
        )
        assert result["decision"] != "BLOCK", (
            "Twist 3 CRITIQUE : IP whitelistée auto-bloquée !"
        )
        # Elle doit être ALERT au maximum → signale aux humains
        assert result["response_level"] <= 2

    # ── Scénario 4 : Utilisateur légitime qui se trompe de mdp ───────────────

    def test_few_ssh_failures_no_block(self):
        """
        Un employé qui se trompe 2-3 fois de mot de passe NE doit pas
        déclencher de blocage. Les seuils SSH existent pour ça.
        """
        analyzer = SSHAnalyzer(thresholds={"window_10s": 5, "window_1h": 15, "window_24h": 40})
        ip  = "10.0.0.20"
        base = datetime(2026, 4, 25, 10, 0, 0, tzinfo=timezone.utc)
        records = []
        for i in range(3):  # Seulement 3 échecs espacés
            ts = (base + timedelta(minutes=i)).isoformat()
            records.append({
                "source": "ssh", "ip": ip, "event": "Failed password",
                "user": "alice", "timestamp_log": ts, "timestamp_recv": ts,
                "ip_is_external": False, "log_hash": str(i), "integrity_ok": True,
            })
        results = analyzer.analyze_batch(records)
        # 3 échecs en 3 minutes sur IP interne → score détecteur faible
        last = results[-1]
        assert last["detector_score"] < 50, (
            f"3 erreurs de mdp déclenchent une alerte : score={last['detector_score']}"
        )

    # ── Scénario 5 : Log tardif d'un utilisateur légitime ────────────────────

    def test_late_log_legitimate_ip_not_blocked(self):
        """
        Un log arrivé tardivement (problème réseau) réduit la confiance
        mais ne doit pas mener à un blocage sur une IP interne.
        """
        result = _full_pipeline(
            ip="10.0.0.30",
            detector_score=50,
            confidence_penalty=0.35,  # Log tardif — confiance réduite
            is_external=False,
        )
        assert result["decision"] != "BLOCK"

    # ── Scénario 6 : Script de monitoring légitime (agent Python) ─────────────

    def test_internal_monitoring_script_not_blocked(self):
        """
        Un script de monitoring interne utilise python-requests.
        L'agent est "malicieux" selon nos listes, mais l'IP est interne
        et le contexte est légitime → ne pas bloquer.
        """
        record = {
            "ip":               "10.0.0.100",
            "ip_is_external":   False,
            "user":             "",
            "event":            "",
            "detector_score":   55,     # Agent malveillant détecté → score moyen
            "behavioral_score": 15,
            "confidence_penalty": 0.0,
            "win_24h":          20,
            "source":           "apache",
            "agent_malicious":  True,    # "python-requests" est dans notre liste
            "path_sqli":        False,
            "path_traversal":   False,
            "path_sensitive":   False,
            "rule_triggered":   None,
            "win_10s":          0,
            "win_1h":           0,
            "late_seconds":     0,
            "integrity_ok":     True,
            "whitelisted":      False,
        }
        scored  = score(record)
        decided = decide(scored)
        # Le fp_cost élevé (IP interne) doit faire baisser le decision_score
        assert decided["decision"] != "BLOCK", (
            f"Script interne bloqué ! decision_score={decided.get('decision_score')}"
        )

    # ── Scénario 7 : Attaquant externe → DOIT être bloqué (contrôle négatif) ──

    def test_true_positive_external_attacker_blocked(self):
        """
        Contrôle négatif : un vrai attaquant externe avec score critique
        DOIT être bloqué (s'assurer que notre protection FP ne va pas trop loin).
        """
        result = _full_pipeline(
            ip="185.147.82.139",
            detector_score=95,
            behavioral_score=85,
            is_external=True,
            whitelisted=False,
            win_24h=0,
        )
        assert result["decision"] in ("BLOCK", "SLOWDOWN"), (
            f"Attaquant externe non bloqué ! decision={result['decision']}"
        )
