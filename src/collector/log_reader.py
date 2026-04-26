"""
log_reader.py
─────────────────────────────────────────────────────────────────────────────
Simule la lecture en continu des fichiers CSV comme s'ils étaient des logs
live arrivant en temps réel.

Fonctionnement :
  - Charge les trois sources (Apache, SSH, Network) via le normalizer.
  - Les diffuse ligne par ligne avec un délai configurable (streaming_delay).
  - Appelle un callback pour chaque event → permet au pipeline de réagir
    immédiatement sans attendre la fin du fichier.
  - Tourne en boucle infinie (rejoue les logs quand il atteint la fin),
    ce qui maintient un flux permanent pour la démo.

Twist 2 — Silence Detector :
  - Met à jour un timestamp partagé `last_event_time` après chaque event.
  - Le SilenceDetector (silence_detector.py) surveille ce timestamp.
"""

import time
import threading
import logging
from datetime import datetime, timezone
from typing import Callable, Optional

import yaml

from src.collector.normalizer import load_all

logger = logging.getLogger(__name__)


# ─── Shared state ─────────────────────────────────────────────────────────────

# Timestamp du dernier event émis — partagé avec le SilenceDetector
last_event_time: Optional[datetime] = None
_lock = threading.Lock()


def _update_last_event():
    """Met à jour le timestamp partagé de manière thread-safe."""
    global last_event_time
    with _lock:
        last_event_time = datetime.now(timezone.utc)


def get_last_event_time() -> Optional[datetime]:
    """Retourne le timestamp du dernier event (thread-safe)."""
    with _lock:
        return last_event_time


# ─── Loader ───────────────────────────────────────────────────────────────────

def _load_config(config_path: str = "config/config.yaml") -> dict:
    """Charge la configuration YAML du projet."""
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def _load_events(config: dict) -> list[dict]:
    """
    Charge et mélange les events des trois sources.
    Retourne une liste triée par timestamp_log pour respecter l'ordre chronologique.
    """
    data = load_all(
        apache_path=config["data"]["apache_log"],
        ssh_path=config["data"]["ssh_log"],
        network_path=config["data"]["network_log"],
    )

    all_events: list[dict] = []
    all_events.extend(data["apache"])
    all_events.extend(data["ssh"])
    all_events.extend(data["network"])

    # Tri chronologique pour simuler un flux réaliste
    def _sort_key(e: dict):
        try:
            return str(e.get("timestamp_log", ""))
        except Exception:
            return ""

    all_events.sort(key=_sort_key)

    logger.info(
        f"[LogReader] {len(data['apache'])} events Apache | "
        f"{len(data['ssh'])} SSH | {len(data['network'])} Network — "
        f"Total : {len(all_events)} events chargés."
    )
    return all_events


# ─── Streaming ────────────────────────────────────────────────────────────────

def stream_logs(
    callback: Callable[[dict], None],
    config_path: str = "config/config.yaml",
    streaming_delay: float = 0.05,
    loop: bool = True,
    stop_event: Optional[threading.Event] = None,
):
    """
    Diffuse les events en continu et appelle `callback(event)` pour chaque event.

    Parameters
    ----------
    callback        : Fonction appelée avec chaque event normalisé (dict).
    config_path     : Chemin vers config.yaml.
    streaming_delay : Délai (secondes) entre chaque event pour simuler le live.
                      0.05s ≈ 20 events/sec — ajustable selon les besoins.
    loop            : Si True, relance le flux depuis le début à la fin des logs.
    stop_event      : threading.Event() pour arrêter proprement le thread.
    """
    config = _load_config(config_path)
    events = _load_events(config)

    if not events:
        logger.error("[LogReader] Aucun event chargé — vérifiez les chemins dans config.yaml.")
        return

    cycle = 0
    while True:
        cycle += 1
        logger.info(f"[LogReader] ── Cycle {cycle} — diffusion de {len(events)} events ──")

        for i, event in enumerate(events):
            # Arrêt propre si demandé par le pipeline
            if stop_event and stop_event.is_set():
                logger.info("[LogReader] Arrêt demandé — flux interrompu.")
                return

            # Mise à jour du timestamp partagé (pour le SilenceDetector)
            _update_last_event()

            # Transmission au pipeline
            try:
                callback(event)
            except Exception as exc:
                logger.warning(f"[LogReader] Erreur dans le callback (event #{i}) : {exc}")

            # Délai de simulation live
            if streaming_delay > 0:
                time.sleep(streaming_delay)

        if not loop:
            logger.info("[LogReader] Fin du flux (mode one-shot).")
            break

        # Petite pause entre les cycles pour éviter une boucle trop agressive
        logger.info("[LogReader] Fin du cycle — reprise dans 2s...")
        time.sleep(2)


# ─── Lancement dans un thread dédié ───────────────────────────────────────────

def start_reader_thread(
    callback: Callable[[dict], None],
    config_path: str = "config/config.yaml",
    streaming_delay: float = 0.05,
    stop_event: Optional[threading.Event] = None,
) -> threading.Thread:
    """
    Lance le streaming dans un thread daemon.
    Retourne le thread pour que main.py puisse le superviser.

    Example (dans main.py)
    ----------------------
        stop = threading.Event()
        t = start_reader_thread(callback=pipeline.process, stop_event=stop)
        # Pour arrêter : stop.set()
    """
    thread = threading.Thread(
        target=stream_logs,
        kwargs={
            "callback": callback,
            "config_path": config_path,
            "streaming_delay": streaming_delay,
            "loop": True,
            "stop_event": stop_event,
        },
        name="LogReaderThread",
        daemon=True,
    )
    thread.start()
    logger.info("[LogReader] Thread démarré.")
    return thread


# ─── Test standalone ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    received = {"count": 0}

    def demo_callback(event: dict):
        received["count"] += 1
        if received["count"] % 500 == 0:
            print(
                f"  → Event #{received['count']} | "
                f"source={event['source']} | "
                f"ip={event.get('ip', 'N/A')} | "
                f"label={event.get('label', '?')}"
            )

    stop = threading.Event()
    print("=== Test LogReader — Ctrl+C pour arrêter ===")
    try:
        # Streaming rapide pour le test (délai 10ms)
        stream_logs(callback=demo_callback, streaming_delay=0.01, stop_event=stop)
    except KeyboardInterrupt:
        stop.set()
        print(f"\n[LogReader] Arrêté — {received['count']} events traités.")
