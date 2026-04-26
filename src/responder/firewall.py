"""
firewall.py
─────────────────────────────────────────────────────────────────────────────
Gestion du blocage réseau d'IPs malveillantes via iptables.

Deux modes de fonctionnement :
  ┌─────────────────────────────────────────────────────────┐
  │  DRY_RUN = True  (défaut)                               │
  │  → Simule les commandes, log "DRY-RUN" sans toucher     │
  │    le vrai firewall. Parfait pour la démo hackathon.    │
  ├─────────────────────────────────────────────────────────┤
  │  DRY_RUN = False                                        │
  │  → Exécute de vraies commandes iptables (root requis).  │
  │    À utiliser sur un vrai serveur en production.        │
  └─────────────────────────────────────────────────────────┘

Sécurités intégrées :
  - Vérification de la whitelist (config/whitelist.yaml) avant tout blocage.
  - Vérification CIDR pour les plages internes (ex: 10.0.0.0/8).
  - Idempotent : bloquer deux fois la même IP ne produit qu'une seule règle.
  - Journalisation complète de chaque action pour le jury.

Intégration avec le pipeline :
  apply_decision(record) → appelé en bout de pipeline après decision.py.
  Retourne le record enrichi avec firewall_action.
"""

import ipaddress
import logging
import subprocess
from datetime import datetime, timezone
from threading import Lock
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

# ─── Mode de fonctionnement ───────────────────────────────────────────────────

# Mettre à False uniquement sur un vrai VPS Linux avec droits root
DRY_RUN: bool = True

# ─── État interne (thread-safe) ───────────────────────────────────────────────

# ip → {blocked_at, duration_minutes, reason, level}
_blocked: dict[str, dict] = {}
_lock = Lock()

# ─── Chargement de la whitelist ───────────────────────────────────────────────

_whitelist_cache: Optional[dict] = None


def _load_whitelist() -> dict:
    """Charge et met en cache la whitelist depuis config/whitelist.yaml."""
    global _whitelist_cache
    if _whitelist_cache is not None:
        return _whitelist_cache
    try:
        with open("config/whitelist.yaml") as f:
            _whitelist_cache = yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.warning("[Firewall] whitelist.yaml introuvable — aucune whitelist chargée.")
        _whitelist_cache = {}
    return _whitelist_cache


def reload_whitelist():
    """Force le rechargement de la whitelist (utile si modifiée en live)."""
    global _whitelist_cache
    _whitelist_cache = None
    _load_whitelist()
    logger.info("[Firewall] Whitelist rechargée.")


def _is_whitelisted(ip: str) -> bool:
    """
    Vérifie si une IP est dans la whitelist ou dans une plage interne.
    Retourne True si l'IP NE DOIT PAS être bloquée.
    """
    wl = _load_whitelist()

    # 1. IP exacte dans trusted_ips
    trusted_ips = wl.get("trusted_ips", [])
    if ip in trusted_ips:
        logger.info(f"[Firewall] {ip} → whitelistée (trusted_ip)")
        return True

    # 2. Appartient à une plage CIDR interne (ex: 10.0.0.0/8)
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in wl.get("internal_ranges", []):
            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                logger.info(f"[Firewall] {ip} → whitelistée (plage interne {cidr})")
                return True
    except ValueError:
        logger.warning(f"[Firewall] Adresse IP invalide : {ip}")
        return True   # Par prudence, on ne bloque pas une IP non parseable

    return False


# ─── Exécution des commandes iptables ────────────────────────────────────────

def _iptables_run(cmd: list[str]) -> tuple[bool, str]:
    """
    Exécute une commande iptables.
    En mode DRY_RUN, simule et retourne True sans toucher le système.
    Retourne (succès: bool, sortie_erreur: str).
    """
    if DRY_RUN:
        simulated = " ".join(cmd)
        logger.info(f"[Firewall][DRY-RUN] {simulated}")
        return True, ""

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            logger.error(f"[Firewall] Erreur iptables (code {result.returncode}): {result.stderr.strip()}")
            return False, result.stderr.strip()
        return True, ""
    except FileNotFoundError:
        logger.error("[Firewall] iptables introuvable — vérifiez que vous êtes root sur Linux.")
        return False, "iptables not found"
    except subprocess.TimeoutExpired:
        logger.error("[Firewall] Timeout lors de l'exécution iptables.")
        return False, "timeout"
    except Exception as exc:
        logger.error(f"[Firewall] Exception inattendue : {exc}")
        return False, str(exc)


def _rule_exists(ip: str) -> bool:
    """
    Vérifie si une règle de blocage existe déjà pour cette IP (évite les doublons).
    En DRY_RUN, on se base sur l'état interne _blocked.
    """
    if DRY_RUN:
        return ip in _blocked

    ok, out = _iptables_run([
        "iptables", "-C", "INPUT",
        "-s", ip,
        "-j", "DROP"
    ])
    return ok  # exit 0 = règle existe, exit 1 = n'existe pas


# ─── API publique : blocage / déblocage ──────────────────────────────────────

def block_ip(
    ip: str,
    duration_minutes: int = 1440,
    reason: str = "",
    level: int = 4,
) -> dict:
    """
    Bloque une IP via iptables INPUT DROP.

    Parameters
    ----------
    ip               : Adresse IP à bloquer.
    duration_minutes : Durée du blocage en minutes (référence pour unban.py).
    reason           : Justification courte (affichée dans les logs et iptables).
    level            : Niveau de décision (3=SLOWDOWN, 4=BLOCK).

    Returns
    -------
    dict avec les clés : success, ip, action, already_blocked, whitelisted, error
    """
    result_base = {"ip": ip, "reason": reason, "level": level}

    # ── Whitelist : refus absolu de blocage ──────────────────────────────────
    if _is_whitelisted(ip):
        logger.info(f"[Firewall] BLOCAGE REFUSÉ — {ip} est whitelistée.")
        return {**result_base, "success": False, "whitelisted": True,
                "action": "refused_whitelist", "already_blocked": False, "error": ""}

    with _lock:
        # ── Idempotence : IP déjà bloquée ────────────────────────────────────
        if ip in _blocked:
            logger.debug(f"[Firewall] {ip} déjà bloquée — aucune action.")
            return {**result_base, "success": True, "whitelisted": False,
                    "action": "already_blocked", "already_blocked": True, "error": ""}

        # ── Commentaire lisible pour iptables -L ─────────────────────────────
        comment = f"hackverse:{reason[:35]}" if reason else "hackverse:auto-block"

        # ── Commande iptables ─────────────────────────────────────────────────
        ok, err = _iptables_run([
            "iptables", "-A", "INPUT",
            "-s", ip,
            "-j", "DROP",
            "-m", "comment", "--comment", comment,
        ])

        if ok:
            _blocked[ip] = {
                "blocked_at":        datetime.now(timezone.utc).isoformat(),
                "duration_minutes":  duration_minutes,
                "reason":            reason,
                "level":             level,
                "comment":           comment,
            }
            logger.warning(
                f"[Firewall] 🚫 BLOQUÉ {ip} | "
                f"durée={duration_minutes}min | niveau={level} | raison={reason[:60]}"
            )
            return {**result_base, "success": True, "whitelisted": False,
                    "action": "blocked", "already_blocked": False, "error": ""}
        else:
            logger.error(f"[Firewall] Échec du blocage de {ip} : {err}")
            return {**result_base, "success": False, "whitelisted": False,
                    "action": "block_failed", "already_blocked": False, "error": err}


def unblock_ip(ip: str) -> dict:
    """
    Retire la règle iptables DROP pour une IP.

    Returns
    -------
    dict avec les clés : success, ip, action, was_blocked, error
    """
    with _lock:
        if ip not in _blocked:
            logger.debug(f"[Firewall] {ip} n'est pas dans la liste bloquée.")
            return {"ip": ip, "success": True, "action": "not_blocked",
                    "was_blocked": False, "error": ""}

        ok, err = _iptables_run([
            "iptables", "-D", "INPUT",
            "-s", ip,
            "-j", "DROP",
        ])

        if ok:
            del _blocked[ip]
            logger.info(f"[Firewall] ✅ DÉBLOQUÉ {ip}")
            return {"ip": ip, "success": True, "action": "unblocked",
                    "was_blocked": True, "error": ""}
        else:
            logger.error(f"[Firewall] Échec du déblocage de {ip} : {err}")
            return {"ip": ip, "success": False, "action": "unblock_failed",
                    "was_blocked": True, "error": err}


# ─── Requêtes d'état ──────────────────────────────────────────────────────────

def is_blocked(ip: str) -> bool:
    """Retourne True si l'IP est actuellement bloquée."""
    with _lock:
        return ip in _blocked


def get_blocked_list() -> dict[str, dict]:
    """
    Retourne une copie de la liste des IPs bloquées.
    Format : {ip: {blocked_at, duration_minutes, reason, level}}
    Utilisé par unban.py et l'API REST.
    """
    with _lock:
        return dict(_blocked)


def get_stats() -> dict:
    """Stats globales pour le dashboard."""
    with _lock:
        levels = [info["level"] for info in _blocked.values()]
        return {
            "total_blocked":    len(_blocked),
            "blocks_level_4":   levels.count(4),
            "blocks_level_3":   levels.count(3),
            "dry_run_active":   DRY_RUN,
        }


# ─── Intégration pipeline ─────────────────────────────────────────────────────

def apply_decision(record: dict) -> dict:
    """
    Appelé en bout de pipeline après decision.py.
    Exécute l'action firewall selon le response_level du record.

    Niveaux :
      4 (BLOCK)    → blocage long (block_long_minutes depuis config)
      3 (SLOWDOWN) → blocage court (block_temp_minutes depuis config)
      1-2          → aucune action firewall

    Retourne le record enrichi avec firewall_action et firewall_result.
    """
    level  = record.get("response_level", 1)
    ip     = record.get("ip", "")
    reason = record.get("justification", "")[:60]

    if not ip or level < 3:
        return {**record, "firewall_action": "none", "firewall_result": {}}

    durations   = _load_duration_config()
    fw_result   = {}
    fw_action   = "none"

    if level >= 4:
        fw_result = block_ip(
            ip,
            duration_minutes=durations["block_long_minutes"],
            reason=reason,
            level=4,
        )
        fw_action = fw_result.get("action", "block_failed")

    elif level == 3:
        fw_result = block_ip(
            ip,
            duration_minutes=durations["block_temp_minutes"],
            reason=f"SLOWDOWN:{reason}",
            level=3,
        )
        fw_action = fw_result.get("action", "rate_limit_failed")

    return {**record, "firewall_action": fw_action, "firewall_result": fw_result}


def _load_duration_config() -> dict:
    """Charge les durées de blocage depuis config.yaml."""
    try:
        with open("config/config.yaml") as f:
            cfg = yaml.safe_load(f)
        thresholds = cfg.get("ssh_thresholds", {})
        return {
            "block_temp_minutes": thresholds.get("block_temp_minutes", 60),
            "block_long_minutes": thresholds.get("block_long_minutes", 1440),
        }
    except Exception:
        return {"block_temp_minutes": 60, "block_long_minutes": 1440}


# ─── Test standalone ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    print("=== Test Firewall (DRY_RUN=True) ===\n")

    # 1. Bloquer une IP externe
    print("► Blocage de 203.0.113.42 (IP externe malveillante)...")
    r = block_ip("203.0.113.42", duration_minutes=60, reason="SQLi détecté", level=4)
    print(f"  Résultat : {r}\n")

    # 2. Bloquer deux fois la même IP (idempotence)
    print("► Blocage doublon de 203.0.113.42...")
    r = block_ip("203.0.113.42", duration_minutes=60, reason="doublon test", level=4)
    print(f"  Résultat : {r}\n")

    # 3. Tenter de bloquer une IP interne (whitelist CIDR)
    print("► Tentative de blocage d'une IP interne (10.0.0.5)...")
    r = block_ip("10.0.0.5", duration_minutes=60, reason="faux positif", level=4)
    print(f"  Résultat : {r}\n")

    # 4. Stats
    print(f"► Stats : {get_stats()}\n")

    # 5. IPs bloquées
    print(f"► IPs bloquées : {list(get_blocked_list().keys())}\n")

    # 6. Déblocage
    print("► Déblocage de 203.0.113.42...")
    r = unblock_ip("203.0.113.42")
    print(f"  Résultat : {r}\n")

    # 7. Test via apply_decision
    print("► Test apply_decision (level=4)...")
    fake_record = {
        "ip": "198.51.100.7",
        "response_level": 4,
        "justification": "Score 92 — brute force SSH détecté",
    }
    enriched = apply_decision(fake_record)
    print(f"  firewall_action = {enriched['firewall_action']}")
    print(f"  firewall_result = {enriched['firewall_result']}")
