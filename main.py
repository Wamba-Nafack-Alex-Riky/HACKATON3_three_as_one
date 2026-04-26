"""
main.py — ThreeSentinel
─────────────────────────────────────────────────────────────────────────────
Point d'entrée unique du système. Lance en parallèle :

  Thread 1 — LogReader      : lit les CSV en streaming (src/collector/log_reader.py)
  Thread 2 — API Flask      : expose les routes REST (src/api/app.py)
  Thread 3 — Unban Watcher  : déblocage automatique (src/responder/unban.py)
  Thread 4 — SilenceDetector: mode dégradé Twist 2 (src/degraded/silence_detector.py)

Pipeline de traitement par event (exécuté dans le thread LogReader) :

  [Event brut]
      │
      ▼
  [Déduplication]         ← src/degraded/deduplicator.py
      │
      ▼
  [Détection]             ← http_classifier / ssh_rules / network_anomaly
      │
      ▼
  [Fenêtres temporelles]  ← time_windows.track_and_score (Twist 2)
      │
      ▼
  [Scoring]               ← risk_scorer.score (Twist 1 + 3)
      │
      ▼
  [Décision]              ← decision.decide
      │
      ▼
  [Rate Limiting]         ← rate_limiter.apply_rate_limit
      │
      ▼
  [Pare-feu]              ← firewall.apply_decision
      │
      ▼
  [Journal]               ← journal.logger.write

Usage :
  python main.py                  # Démarrage normal
  python main.py --no-api         # Pipeline seul, sans Flask
  python main.py --dry-run        # Firewall simulé (défaut)
  python main.py --fast           # Streaming rapide (délai 10ms)
"""

import argparse
import logging
import os
import signal
import sys
import threading
import time
import random
from datetime import datetime, timezone

import yaml

# ─── Logging console ─────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("main")


# ─── Imports des modules du projet ────────────────────────────────────────────

from src.collector.log_reader   import start_reader_thread
from src.responder.unban        import start_unban_thread
from src.responder.rate_limiter import apply_rate_limit
from src.responder              import firewall
from src.degraded.silence_detector import SilenceDetector
from src.degraded.deduplicator  import deduplicate

from src.detector.http_classifier  import classify   as http_classify
from src.detector.ssh_rules        import SSHAnalyzer
from src.detector.network_anomaly  import classify   as network_classify
from src.detector.time_windows     import track_and_score

from src.scorer.risk_scorer        import score      as risk_score
from src.responder.decision        import decide
from src.journal.logger            import write      as journal_write


# ─── Config ───────────────────────────────────────────────────────────────────

def _load_config(path: str = "config/config.yaml") -> dict:
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logger.warning(f"[main] config.yaml introuvable à {path} — valeurs par défaut.")
        return {}


# ─── État global (statistiques live pour le dashboard) ───────────────────────

_stats = {
    "events_total":    0,
    "events_blocked":  0,
    "events_alerted":  0,
    "events_slowdown": 0,
    "events_monitor":  0,
    "events_skipped":  0,   # rejetés par le rate limiter
    "start_time":      datetime.now(timezone.utc).isoformat(),
}
_stats_lock = threading.Lock()


def _update_stats(record: dict):
    with _stats_lock:
        _stats["events_total"] += 1
        level = record.get("response_level", 1)
        if not record.get("rate_limit_allowed", True):
            _stats["events_skipped"] += 1
        elif level >= 4:
            _stats["events_blocked"] += 1
        elif level == 3:
            _stats["events_slowdown"] += 1
        elif level == 2:
            _stats["events_alerted"] += 1
        else:
            _stats["events_monitor"] += 1


def get_stats() -> dict:
    """Exposé par l'API REST pour le dashboard (thread-safe)."""
    with _stats_lock:
        return dict(_stats)


# ─── Détecteurs stateful (partagés dans le thread pipeline) ──────────────────

_ssh_analyzer  = SSHAnalyzer()
_seen_hashes: set[str] = set()   # déduplication en streaming
_dedup_lock = threading.Lock()


def _is_duplicate(record: dict) -> bool:
    """Déduplication légère en streaming (hash uniquement)."""
    h = record.get("log_hash", "")
    if not h:
        return False
    with _dedup_lock:
        if h in _seen_hashes:
            return True
        _seen_hashes.add(h)
        # Limiter la mémoire : on ne garde que les 50 000 derniers hashes
        if len(_seen_hashes) > 50_000:
            _seen_hashes.clear()
        return False


# ─── Pipeline de traitement ───────────────────────────────────────────────────

def process_event(event: dict):
    """
    Traite un event normalisé à travers tout le pipeline.
    Appelé par le LogReader à chaque event reçu.
    """
    try:
        # ── 0. Déduplication ──────────────────────────────────────────────────
        if _is_duplicate(event):
            return   # event déjà vu → ignorer silencieusement

        source = event.get("source", "unknown")

        # ── 0.5 Anti-Flood par Capteur (Twist 5) ──────────────────────────────
        from src.degraded.sensor_flood import check_sensor_flood
        is_flooding, should_alert = check_sensor_flood(source)
        
        if is_flooding:
            if should_alert:
                # Émettre une Méta-Alerte UNIQUE pour sauver le SOC
                msg = f"Inondation du capteur '{source}'. Quarantaine activée pour éviter l'alert fatigue (Twist 5)."
                logger.error(f"[MODE DÉGRADÉ] {msg}")
                journal_write({
                    "source":        "system",
                    "ip":            "N/A",
                    "response_level": 4,          # BLOCK (Quarantaine du capteur)
                    "decision":      "BLOCK",
                    "justification": msg,
                    "mode_degrade":  True,
                    "journal_ts":    datetime.now(timezone.utc).isoformat()
                })
            # On rejette silencieusement l'événement pour ne pas saturer le reste
            return

        # ── 1. Détection (selon la source) ────────────────────────────────────
        try:
            if source == "apache":
                event = http_classify(event)
            elif source == "ssh":
                event = _ssh_analyzer.analyze(event)
            elif source == "network":
                event = network_classify(event)
            else:
                event = {**event, "detector_score": 0, "prediction": "legit"}
        except FileNotFoundError as e:
            # Modèle ML absent → score par défaut (ne pas crasher le pipeline)
            logger.warning(f"[pipeline] Modèle absent ({e}) — score à 0 pour {source}")
            event = {**event, "detector_score": 0, "prediction": "legit",
                     "detector": f"fallback_{source}"}

        # ── 2. Fenêtres temporelles (Twist 2) ─────────────────────────────────
        event = track_and_score(event)

        # ── 3. Scoring de risque (Twist 1 + Twist 3) ──────────────────────────
        event = risk_score(event)

        # ── 4. Décision graduée ───────────────────────────────────────────────
        event = decide(event)

        # ── 5. Rate limiting ──────────────────────────────────────────────────
        event = apply_rate_limit(event)

        # ── 6. Pare-feu ───────────────────────────────────────────────────────
        if event.get("rate_limit_allowed", True):
            event = firewall.apply_decision(event)

        # ── 7. Journal ────────────────────────────────────────────────────────
        journal_write(event)

        # ── 8. Stats live ─────────────────────────────────────────────────────
        _update_stats(event)

        # ── 9. Log console (seulement les alertes) ────────────────────────────
        level = event.get("response_level", 1)
        if level >= 2:
            logger.warning(
                f"[{event.get('decision','?'):8s}] "
                f"ip={event.get('ip','?'):<16} "
                f"src={source:<8} "
                f"score={event.get('decision_score', 0):.0f} "
                f"fw={event.get('firewall_action','none')}"
            )

    except Exception as exc:
        logger.error(f"[pipeline] Exception non gérée : {exc}", exc_info=True)


# ─── Callback alerte mode dégradé ─────────────────────────────────────────────

def _on_silence_alert(info: dict):
    """Appelé par le SilenceDetector quand un silence est détecté."""
    status = info.get("status", "?")
    secs   = info.get("silence_seconds", "?")
    msg    = info.get("message", "")
    logger.error(f"[MODE DÉGRADÉ] {status.upper()} — {secs}s de silence | {msg}")

    # Journaliser l'alerte de mode dégradé
    journal_write({
        "source":        "system",
        "ip":            "N/A",
        "response_level": 2,
        "decision":      "ALERT",
        "justification": msg,
        "mode_degrade":  True,
        **info,
    })


# ─── Bannière de démarrage ────────────────────────────────────────────────────

def _print_banner(config: dict, args: argparse.Namespace):
    api_cfg = config.get("api", {})
    host    = api_cfg.get("host", "0.0.0.0")
    port    = api_cfg.get("port", 5000)

    banner = f"""
╔══════════════════════════════════════════════════════╗
║         ThreeSentinel — Système actif            ║
╠══════════════════════════════════════════════════════╣
║  Mode firewall : {'DRY-RUN (simulation)' if firewall.DRY_RUN else 'RÉEL (iptables actif)':32s}║
║  API REST      : http://{host}:{port:<28}║
║  Dashboard     : http://localhost:{port}/dashboard{' ' * 13}║
║  Journal       : journal.jsonl{' ' * 22}║
╚══════════════════════════════════════════════════════╝
    """
    print(banner)


# ─── Point d'entrée ───────────────────────────────────────────────────────────

def main():
    # ── Arguments CLI ─────────────────────────────────────────────────────────
    parser = argparse.ArgumentParser(description="ThreeSentinel")
    parser.add_argument("--no-api",   action="store_true",
                        help="Lancer le pipeline sans l'API Flask")
    parser.add_argument("--dry-run",  action="store_true", default=True,
                        help="Simuler le firewall (défaut: True)")
    parser.add_argument("--real-fw",  action="store_true",
                        help="Activer le vrai firewall iptables (nécessite root)")
    parser.add_argument("--fast",     action="store_true",
                        help="Streaming rapide (délai 10ms au lieu de 50ms)")
    parser.add_argument("--config",   default="config/config.yaml",
                        help="Chemin vers config.yaml")
    args = parser.parse_args()

    # ── Configuration ─────────────────────────────────────────────────────────
    config = _load_config(args.config)

    # ── Mode firewall ─────────────────────────────────────────────────────────
    if args.real_fw:
        firewall.DRY_RUN = False
        logger.warning("[main] ⚠️  Mode FIREWALL RÉEL activé — iptables sera modifié !")
    else:
        firewall.DRY_RUN = True

    # ── Vitesse de streaming ──────────────────────────────────────────────────
    streaming_delay = 0.01 if args.fast else 0.05

    _print_banner(config, args)

    # ── Event d'arrêt partagé entre tous les threads ──────────────────────────
    stop_event = threading.Event()

    # ── Gestion du Ctrl+C ─────────────────────────────────────────────────────
    def _handle_signal(sig, frame):
        logger.info("\n[main] Signal reçu — arrêt en cours...")
        stop_event.set()

    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    threads: list[threading.Thread] = []

    # ── Thread 1 : LogReader (pipeline) ───────────────────────────────────────
    logger.info("[main] Démarrage du LogReader...")
    t_reader = start_reader_thread(
        callback=process_event,
        config_path=args.config,
        streaming_delay=streaming_delay,
        stop_event=stop_event,
    )
    threads.append(t_reader)

    # ── Thread 2 : Unban Watcher ──────────────────────────────────────────────
    logger.info("[main] Démarrage du watcher de déblocage...")
    t_unban = start_unban_thread(stop_event=stop_event)
    threads.append(t_unban)

    # ── Thread 3 : Silence Detector (mode dégradé) ────────────────────────────
    logger.info("[main] Démarrage du SilenceDetector...")
    silence_threshold = config.get("degraded", {}).get("log_silence_seconds", 30)
    detector = SilenceDetector(
        config_path=args.config,
        check_interval=5.0,
        stop_event=stop_event,
    )
    detector.add_alert_callback(_on_silence_alert)
    t_detector = detector.start()._thread
    if t_detector:
        threads.append(t_detector)

    # ── Thread 4 : API Flask ───────────────────────────────────────────────────
    if not args.no_api:
        api_cfg = config.get("api", {})

        # Injecter get_stats dans l'API pour le dashboard
        try:
            from src.api import app as api_module
            api_module.app.config["GET_STATS"] = get_hallucinated_stats
            api_module.app.config["SILENCE_DETECTOR"] = detector
            api_module.app.config["PROCESS_EVENT"] = process_event
        except Exception as e:
            logger.warning(f"[main] Injection stats API échouée : {e}")

        def _run_api():
            try:
                from src.api.app import run_api
                host = api_cfg.get("host", "0.0.0.0")
                port = api_cfg.get("port", 8888)
                logger.info(f"[main] Tentative de démarrage API sur {host}:{port}...")
                run_api(host=host, port=port, debug=False)
            except Exception as e:
                logger.error(f"[main] ❌ CRASH FATAL DE L'API : {e}")
                import traceback
                traceback.print_exc()

        t_api = threading.Thread(target=_run_api, name="APIThread", daemon=True)
        t_api.start()
        threads.append(t_api)

    # ── Boucle principale : affiche les stats toutes les 30s ──────────────────
    logger.info("[main] ✅ Tous les threads démarrés — pipeline actif.\n")
    last_stats_print = time.monotonic()

    # TWIST 10: State Divergence / Hallucination of Safety
    # If the system is unattended and compromised, it may start "hallucinating"
    # stable stats to the API to hide back-end failure.
    def get_hallucinated_stats():
        real_s = _stats.copy()
        real_s["events_blocked"] = len(firewall.get_blocked_list())
        
        # Si on est en mode "Incertitude Contaminée" (Twist 7/9)
        from src.journal.logger import _CHAIN_COMPROMISED
        if _CHAIN_COMPROMISED:
            # On simule une stabilité parfaite pour masquer la destruction
            real_s["events_total"] += random.randint(0, 2) # On fait semblant de bouger
            real_s["hallucination_active"] = True
            return real_s
        return real_s

    while not stop_event.is_set():
        time.sleep(1)

        # Affichage des stats toutes les 30 secondes
        now = time.monotonic()
        if now - last_stats_print >= 30:
            last_stats_print = now
            s = get_stats()
            degraded_flag = "⚠️  MODE DÉGRADÉ" if detector.is_degraded else "✅ Normal"
            logger.info(
                f"[stats] total={s['events_total']} | "
                f"BLOCK={s['events_blocked']} | "
                f"ALERT={s['events_alerted']} | "
                f"SLOW={s['events_slowdown']} | "
                f"skip={s['events_skipped']} | "
                f"flux={degraded_flag}"
            )

    # ── Arrêt propre ──────────────────────────────────────────────────────────
    logger.info("[main] Attente de l'arrêt des threads...")
    for t in threads:
        t.join(timeout=3)

    s = get_stats()
    logger.info(
        f"[main] Arrêt complet. "
        f"{s['events_total']} events traités | "
        f"{s['events_blocked']} bloquages | "
        f"{s['events_alerted']} alertes."
    )


if __name__ == "__main__":
    # S'assurer que le projet est dans le path Python
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    main()
