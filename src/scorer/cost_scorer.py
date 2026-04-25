"""
scorer/cost_scorer.py
Score de coût d'un faux positif (Twist 3).
Un score élevé signifie qu'un blocage serait très coûteux (acteur légitime).
"""

import ipaddress


def is_internal(ip: str, internal_ranges: list = None) -> bool:
    """Vérifie si une IP appartient à un réseau interne."""
    if internal_ranges is None:
        internal_ranges = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in internal_ranges:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
    except ValueError:
        pass
    return False


def compute_fp_cost(record: dict, whitelist: dict = None) -> float:
    """
    Calcule le score de coût faux positif (0=aucun coût → 100=coût maximal).

    Règles :
    - IP dans la whitelist explicite  → +80
    - IP interne (10.x / 192.168.x)  → +60
    - IP très active en 24h (>50 ev) → +20
    """
    if whitelist is None:
        whitelist = {}

    ip      = record.get("ip", "")
    cost    = 0.0

    # Whitelist explicite
    trusted_ips = whitelist.get("trusted_ips", [])
    trusted_usr = whitelist.get("trusted_users", [])
    if ip in trusted_ips:
        cost += 80.0
    if record.get("user") in trusted_usr:
        cost += 40.0

    # IP interne
    internal_ranges = whitelist.get("internal_ranges", ["10.0.0.0/8"])
    if not record.get("ip_is_external", True) or is_internal(ip, internal_ranges):
        cost += 60.0

    # Activité légitime importante
    win_24h = record.get("win_24h", 0)
    if win_24h > 50:
        cost += 20.0

    return min(cost, 100.0)


def enrich_with_cost(record: dict, whitelist: dict = None) -> dict:
    """Enrichit le record avec fp_cost_score."""
    cost = compute_fp_cost(record, whitelist)
    return {**record, "fp_cost_score": cost}
