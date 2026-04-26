"""
cost_scorer.py  —  Twist 3
Score du coût d'un faux positif pour chaque IP.

Ce module est distinct de risk_scorer.py pour permettre une évolution
indépendante : les critères de coût peuvent être affinés sans toucher
au moteur de scoring de risque.

Score de coût : 0 (bloquer sans danger) → 100 (bloquer serait catastrophique).
"""

import ipaddress
import yaml

WHITELIST_PATH = "config/whitelist.yaml"
CONFIG_PATH    = "config/config.yaml"

_whitelist = None


def _load_whitelist() -> dict:
    global _whitelist
    if _whitelist is None:
        try:
            with open(WHITELIST_PATH) as f:
                _whitelist = yaml.safe_load(f)
        except FileNotFoundError:
            _whitelist = {"internal_ranges": [], "trusted_ips": [],
                          "trusted_users": []}
    return _whitelist


def _is_whitelisted(ip: str, user: str = "") -> bool:
    wl = _load_whitelist()
    if ip in wl.get("trusted_ips", []):
        return True
    if user and user in wl.get("trusted_users", []):
        return True
    for cidr in wl.get("internal_ranges", []):
        try:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
                return True
        except ValueError:
            continue
    return False


def compute_fp_cost(record: dict) -> float:
    """
    Calcule le coût d'un faux positif pour un record.

    Composantes :
      - IP whitelistée                → coût très élevé (jamais bloquer)
      - IP interne                    → coût élevé (personnel humanitaire)
      - Taux d'activité légitime 24h  → coût si IP très active
      - Historique de succès SSH      → coût si utilisateur a déjà été accepté
      - Score de confiance bas        → coût réduit (log peu fiable)

    Retourne un float entre 0.0 et 100.0.
    """
    ip          = record.get("ip", "")
    user        = record.get("user", "")
    is_external = record.get("ip_is_external", True)
    win_24h     = int(record.get("win_24h", 0))
    confidence  = float(record.get("confidence_score", 100.0))

    cost = 0.0

    # ── Whitelist : coût maximum ──────────────────────────────────────────────
    if _is_whitelisted(ip, user):
        cost += 80.0

    # ── IP interne : travailleur humanitaire potentiel ────────────────────────
    elif not is_external:
        cost += 55.0

    # ── Activité légitime élevée sur 24h ─────────────────────────────────────
    if win_24h > 100:
        cost += 20.0
    elif win_24h > 50:
        cost += 10.0

    # ── Confidence basse : log peu fiable, décision risquée ──────────────────
    # Si on ne fait pas confiance au log, bloquer sur sa foi est coûteux
    if confidence < 50:
        cost += 15.0
    elif confidence < 70:
        cost += 7.0

    # ── Événement SSH légitime récent de cette IP ─────────────────────────────
    event = record.get("event", "")
    if event == "Accepted publickey":
        cost += 25.0

    # ── TWIST 4 : Déchéance de confiance (Mouvement latéral) ──────────────────
    # Si une IP interne agit comme un attaquant avéré, la dépendance
    # "IP interne = ne pas bloquer" devient destructrice. On annule la protection.
    agent_malicious = record.get("agent_malicious", False)
    path_sqli = record.get("path_sqli", False)
    path_traversal = record.get("path_traversal", False)

    lateral_movement = False
    if not is_external or _is_whitelisted(ip, user):
        # Il faut une preuve indéniable d'intention malveillante
        if agent_malicious or path_sqli or path_traversal:
            lateral_movement = True
            cost = 0.0  # Annulation immédiate de la protection
            
    # Ajouter le flag au record (utile pour les preuves dans le decision_scorer)
    record["lateral_movement_detected"] = lateral_movement

    return round(min(cost, 100.0), 1)


def score_fp_cost_batch(records: list[dict]) -> list[dict]:
    """Ajoute fp_cost_score à chaque record de la liste."""
    return [{**r, "fp_cost_score": compute_fp_cost(r)} for r in records]
