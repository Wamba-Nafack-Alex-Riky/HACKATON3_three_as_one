"""
unban.py
─────────────────────────────────────────────────────────────────────────────
Gère le déblocage automatique des IPs après expiration de leur durée de blocage.

Rôle dans le pipeline :
  - Tourne dans un thread daemon en arrière-plan (lancé par main.py).
  - Toutes les CHECK_INTERVAL secondes, parcourt la liste des IPs bloquées.
  - Si la durée de blocage est expirée → appelle firewall.unblock_ip()
    et rate_limiter.remove_slowdown() pour restaurer un accès normal.
  - Évite les blocages permanents par erreur (faux-positifs persistants).

Niveaux de déblocage :
  - BLOCK (level 4)    : durée dans config → block_long_minutes (défaut 24h)
  - SLOWDOWN (level 3) : durée dans config → block_temp_minutes (défaut 60min)

Journal :
  Chaque déblocage est logué avec IP, raison initiale et durée de blocage.
"""

import time
import threading
import logging
from datetime import datetime, timezone

import yaml

from src.responder import firewall
from src.responder import rate_limiter

logger = logging.getLogger(__name__)

# Fréquence de vérification des expirations (secondes)
CHECK_INTERVAL = 15


# ─── Config ───────────────────────────────────────────────────────────────────

def _load_durations() -> dict:
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


# ─── Logique de déblocage ─────────────────────────────────────────────────────

def _check_and_unban():
    """
    Parcourt toutes les IPs bloquées et débloque celles dont la durée est expirée.
    """
    now     = datetime.now(timezone.utc)
    blocked = firewall.get_blocked_list()

    if not blocked:
        return

    for ip, info in blocked.items():
        try:
            blocked_at       = datetime.fromisoformat(info["blocked_at"])
            duration_minutes = info.get("duration_minutes", 60)
            reason           = info.get("reason", "")

            # Calcul de l'expiration
            elapsed_minutes = (now - blocked_at).total_seconds() / 60

            if elapsed_minutes >= duration_minutes:
                logger.info(
                    f"[Unban] Expiration de {ip} — "
                    f"durée: {duration_minutes}min | "
                    f"bloqué depuis: {elapsed_minutes:.1f}min | "
                    f"raison: {reason[:60]}"
                )

                # Déblocage firewall
                ok_fw = firewall.unblock_ip(ip)

                # Retrait du rate-limiting applicatif
                rate_limiter.remove_slowdown(ip)

                if ok_fw:
                    logger.info(f"[Unban] ✅ {ip} débloqé avec succès.")
                else:
                    logger.warning(f"[Unban] ⚠️  Échec du déblocage firewall pour {ip}.")

        except Exception as exc:
            logger.error(f"[Unban] Erreur pour {ip}: {exc}")


# ─── Thread de surveillance ───────────────────────────────────────────────────

def run_unban_loop(stop_event: threading.Event | None = None):
    """
    Boucle principale du watcher de déblocage.
    Tourne indéfiniment jusqu'à ce que stop_event soit levé.

    Appelé par start_unban_thread() dans un thread daemon.
    """
    logger.info(
        f"[Unban] Watcher démarré — vérification toutes les {CHECK_INTERVAL}s."
    )

    while True:
        if stop_event and stop_event.is_set():
            logger.info("[Unban] Arrêt demandé — watcher arrêté.")
            return

        _check_and_unban()

        # Attente par petits pas pour réagir vite au stop_event
        for _ in range(CHECK_INTERVAL):
            if stop_event and stop_event.is_set():
                return
            time.sleep(1)


def start_unban_thread(
    stop_event: threading.Event | None = None,
) -> threading.Thread:
    """
    Lance le watcher de déblocage dans un thread daemon.
    Retourne le thread pour supervision dans main.py.

    Example (dans main.py)
    ----------------------
        stop = threading.Event()
        t = start_unban_thread(stop_event=stop)
        # Pour arrêter : stop.set()
    """
    thread = threading.Thread(
        target=run_unban_loop,
        kwargs={"stop_event": stop_event},
        name="UnbanWatcherThread",
        daemon=True,
    )
    thread.start()
    logger.info("[Unban] Thread démarré.")
    return thread


# ─── Déblocage manuel ─────────────────────────────────────────────────────────

def manual_unban(ip: str) -> dict:
    """
    Débloque manuellement une IP (ex: depuis l'API REST / dashboard).
    Retourne un dict résumant l'action effectuée.
    """
    was_blocked = firewall.is_blocked(ip)

    firewall.unblock_ip(ip)
    rate_limiter.remove_slowdown(ip)

    result = {
        "ip":          ip,
        "was_blocked": was_blocked,
        "unbanned_at": datetime.now(timezone.utc).isoformat(),
        "method":      "manual",
    }
    logger.info(f"[Unban] Déblocage MANUEL de {ip} — était bloqué: {was_blocked}")
    return result


def get_blocked_summary() -> list[dict]:
    """
    Retourne un résumé des IPs bloquées avec leur temps restant.
    Utilisé par l'API REST (Iness) pour le dashboard.
    """
    now     = datetime.now(timezone.utc)
    blocked = firewall.get_blocked_list()
    summary = []

    for ip, info in blocked.items():
        try:
            blocked_at       = datetime.fromisoformat(info["blocked_at"])
            duration_minutes = info.get("duration_minutes", 60)
            elapsed_minutes  = (now - blocked_at).total_seconds() / 60
            remaining        = max(0.0, duration_minutes - elapsed_minutes)

            summary.append({
                "ip":               ip,
                "reason":           info.get("reason", ""),
                "blocked_at":       info["blocked_at"],
                "duration_minutes": duration_minutes,
                "elapsed_minutes":  round(elapsed_minutes, 1),
                "remaining_minutes": round(remaining, 1),
            })
        except Exception:
            continue

    return summary


# ─── Test standalone ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    # Simulation : bloquer une IP avec une durée très courte pour tester
    print("=== Test Unban Watcher ===")
    firewall.DRY_RUN = True

    # Bloquer deux IPs de test
    firewall.block_ip("1.2.3.4", duration_minutes=1, reason="Test blocage court")
    firewall.block_ip("5.6.7.8", duration_minutes=60, reason="Test blocage long")

    print(f"IPs bloquées : {list(firewall.get_blocked_list().keys())}")
    print(f"Résumé : {get_blocked_summary()}")

    # Lancer le watcher (il va checker toutes les CHECK_INTERVAL secondes)
    stop = threading.Event()
    start_unban_thread(stop_event=stop)

    print(f"Watcher actif — attente de {CHECK_INTERVAL + 2}s...")
    time.sleep(CHECK_INTERVAL + 2)
    stop.set()
    print(f"IPs encore bloquées : {list(firewall.get_blocked_list().keys())}")
