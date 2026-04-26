"""
silence_detector.py  —  Mode Dégradé (Twist 2)
─────────────────────────────────────────────────────────────────────────────
Détecte quand les logs cessent d'arriver — deux scénarios possibles :
  1. Panne réseau / service crashé      → "probable_failure"
  2. Attaquant qui a désactivé la journalisation → "suspicious_silence"

Architecture :
  Le détecteur tourne dans un thread daemon (run_watcher).
  Il surveille le timestamp partagé issu de log_reader.get_last_event_time().
  Quand le silence dépasse le seuil (config: log_silence_seconds), il :
    - Change l'état global du système en DEGRADED
    - Appelle le ou les callbacks enregistrés (ex: API, journal)
    - Logue une alerte avec heuristique (panne vs attaque)

Heuristique silence vs panne :
  silence ≤ 5×seuil   → suspicious_silence  (attaque probable)
  silence  > 5×seuil  → probable_failure    (panne probable)

Intégration dans main.py :
  from src.degraded.silence_detector import SilenceDetector
  detector = SilenceDetector()
  detector.add_alert_callback(mon_callback)
  detector.start()
"""

import logging
import threading
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional

import yaml

logger = logging.getLogger(__name__)


# ─── États du système ─────────────────────────────────────────────────────────

class SystemStatus(str, Enum):
    OK                = "ok"               # Flux normal
    SUSPICIOUS_SILENCE = "suspicious_silence"  # Silence court → possible attaque
    PROBABLE_FAILURE  = "probable_failure"  # Silence long  → probable panne
    NEVER_RECEIVED    = "never_received"   # Aucun log reçu depuis le démarrage


# ─── Détecteur ────────────────────────────────────────────────────────────────

class SilenceDetector:
    """
    Surveille le flux de logs et détecte les silences anormaux.

    Usage
    -----
        stop = threading.Event()
        detector = SilenceDetector(stop_event=stop)
        detector.add_alert_callback(lambda info: print(info))
        detector.start()

        # Pour arrêter proprement :
        stop.set()
    """

    def __init__(
        self,
        config_path: str = "config/config.yaml",
        check_interval: float = 5.0,
        stop_event: Optional[threading.Event] = None,
    ):
        self.config_path    = config_path
        self.check_interval = check_interval
        self.stop_event     = stop_event or threading.Event()

        # Config lue depuis config.yaml → degraded.log_silence_seconds
        self._threshold_seconds: int = self._load_threshold()

        # État courant
        self._status:       SystemStatus        = SystemStatus.NEVER_RECEIVED
        self._last_alert:   Optional[dict]      = None
        self._silence_start: Optional[datetime] = None
        self._lock          = threading.Lock()

        # Callbacks appelés lors d'une alerte (ex: API, journal)
        self._callbacks: list[Callable[[dict], None]] = []

        # Thread de surveillance
        self._thread: Optional[threading.Thread] = None

    # ── Configuration ─────────────────────────────────────────────────────────

    def _load_threshold(self) -> int:
        try:
            with open(self.config_path) as f:
                cfg = yaml.safe_load(f)
            return int(cfg.get("degraded", {}).get("log_silence_seconds", 30))
        except Exception:
            return 30

    # ── Gestion des callbacks ─────────────────────────────────────────────────

    def add_alert_callback(self, callback: Callable[[dict], None]):
        """
        Enregistre un callback appelé à chaque alerte de silence.
        Le callback reçoit un dict avec : status, silence_seconds, message, ...
        """
        self._callbacks.append(callback)

    def _fire_callbacks(self, alert_info: dict):
        for cb in self._callbacks:
            try:
                cb(alert_info)
            except Exception as exc:
                logger.error(f"[SilenceDetector] Erreur callback : {exc}")

    # ── Mise à jour de l'état ─────────────────────────────────────────────────

    def _compute_status(self, silence_seconds: float) -> tuple[SystemStatus, str]:
        """Retourne (status, message) selon la durée du silence."""
        threshold = self._threshold_seconds

        if silence_seconds < threshold:
            return SystemStatus.OK, ""

        if silence_seconds > threshold * 5:
            msg = (
                f"Silence de {silence_seconds:.0f}s détecté (seuil: {threshold}s). "
                "Durée anormalement longue → probable panne réseau ou crash du service "
                "de collecte. Vérifiez le collecteur et les sources de logs."
            )
            return SystemStatus.PROBABLE_FAILURE, msg
        else:
            msg = (
                f"Silence de {silence_seconds:.0f}s détecté (seuil: {threshold}s). "
                "Intervalle court et suspect → possible suppression active des logs "
                "par un attaquant. Le système fonctionne en MODE DÉGRADÉ."
            )
            return SystemStatus.SUSPICIOUS_SILENCE, msg

    def _check_once(self, last_event_time: Optional[datetime]) -> dict:
        """
        Effectue une vérification et retourne l'état courant sous forme de dict.
        """
        now = datetime.now(timezone.utc)

        if last_event_time is None:
            return {
                "status":          SystemStatus.NEVER_RECEIVED,
                "silence_seconds": None,
                "last_seen":       None,
                "message":         "Aucun log reçu depuis le démarrage du système.",
                "threshold":       self._threshold_seconds,
                "checked_at":      now.isoformat(),
            }

        silence_seconds = (now - last_event_time).total_seconds()
        status, message = self._compute_status(silence_seconds)

        info = {
            "status":          status,
            "silence_seconds": round(silence_seconds, 1),
            "last_seen":       last_event_time.isoformat(),
            "message":         message,
            "threshold":       self._threshold_seconds,
            "checked_at":      now.isoformat(),
        }

        with self._lock:
            previous_status = self._status

            if status == SystemStatus.OK:
                # Retour à la normale après un silence : log de récupération
                if previous_status not in (SystemStatus.OK, SystemStatus.NEVER_RECEIVED):
                    logger.info(
                        f"[SilenceDetector] ✅ Flux rétabli — "
                        f"était en {previous_status.value} | "
                        f"silence total ≈ {silence_seconds:.0f}s"
                    )
                self._status       = SystemStatus.OK
                self._silence_start = None

            else:
                # Nouveau silence : enregistrer le début
                if self._silence_start is None:
                    self._silence_start = now

                # Logguer et déclencher les callbacks seulement à la transition
                # ou toutes les 60s pour rappel
                is_new_alert = previous_status == SystemStatus.OK
                is_reminder  = (
                    previous_status == status and
                    silence_seconds % 60 < self.check_interval
                )

                if is_new_alert or is_reminder:
                    if status == SystemStatus.SUSPICIOUS_SILENCE:
                        logger.warning(f"[SilenceDetector] ⚠️  {message}")
                    else:
                        logger.error(f"[SilenceDetector] 🔴 {message}")

                    self._last_alert = info
                    self._fire_callbacks(info)

                self._status = status

        return info

    # ── Boucle de surveillance ────────────────────────────────────────────────

    def _run_loop(self):
        """Boucle principale du thread de surveillance."""
        logger.info(
            f"[SilenceDetector] Démarré — seuil: {self._threshold_seconds}s | "
            f"vérification toutes les {self.check_interval}s"
        )

        # Import ici pour éviter les imports circulaires
        from src.collector.log_reader import get_last_event_time

        while not self.stop_event.is_set():
            last_event = get_last_event_time()
            self._check_once(last_event)

            # Attente interruptible par petits pas
            for _ in range(int(self.check_interval)):
                if self.stop_event.is_set():
                    break
                time.sleep(1)

        logger.info("[SilenceDetector] Arrêté proprement.")

    # ── Démarrage / arrêt ─────────────────────────────────────────────────────

    def start(self) -> "SilenceDetector":
        """Lance le watcher dans un thread daemon. Retourne self pour chaining."""
        self._thread = threading.Thread(
            target=self._run_loop,
            name="SilenceDetectorThread",
            daemon=True,
        )
        self._thread.start()
        return self

    def stop(self):
        """Arrête proprement le watcher."""
        self.stop_event.set()

    # ── Lecture d'état (pour l'API REST) ─────────────────────────────────────

    def get_status(self) -> dict:
        """
        Retourne l'état actuel du détecteur.
        Appelé par l'API REST d'Iness pour le dashboard.
        """
        from src.collector.log_reader import get_last_event_time

        last_event = get_last_event_time()
        return self._check_once(last_event)

    @property
    def is_degraded(self) -> bool:
        """True si le système est en mode dégradé (silence détecté)."""
        with self._lock:
            return self._status not in (SystemStatus.OK, SystemStatus.NEVER_RECEIVED)

    @property
    def current_status(self) -> SystemStatus:
        with self._lock:
            return self._status


# ─── Instance globale partagée ────────────────────────────────────────────────
# Créée ici, démarrée dans main.py via silence_detector.start()

_detector_instance: Optional[SilenceDetector] = None


def get_detector() -> SilenceDetector:
    """Retourne l'instance globale du détecteur (singleton)."""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = SilenceDetector()
    return _detector_instance


# ─── Fonctions raccourcies (compatibilité avec l'ancienne API) ────────────────

def update(source: str):
    """Alias de compatibilité — l'update se fait maintenant via log_reader."""
    pass  # Géré automatiquement par get_last_event_time() dans log_reader


def get_system_status() -> dict:
    """Raccourci pour obtenir le statut global — utilisé par l'API."""
    return get_detector().get_status()


def is_degraded() -> bool:
    """Raccourci pour vérifier si le système est en mode dégradé."""
    return get_detector().is_degraded


# ─── Test standalone ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    print("=== Test SilenceDetector ===")
    print("Simulation d'un silence de 35 secondes...\n")

    # Patch du log_reader pour le test
    import src.collector.log_reader as lr
    from datetime import timedelta

    # Simuler un dernier event il y a 35 secondes
    lr.last_event_time = datetime.now(timezone.utc) - timedelta(seconds=35)

    alerts_received = []

    def on_alert(info: dict):
        alerts_received.append(info)
        print(f"  🚨 ALERTE reçue : status={info['status']} | "
              f"silence={info['silence_seconds']}s")

    stop = threading.Event()
    detector = SilenceDetector(check_interval=3.0, stop_event=stop)
    detector.add_alert_callback(on_alert)
    detector.start()

    time.sleep(6)  # Laisser tourner 2 cycles

    print(f"\n► Statut courant : {detector.current_status.value}")
    print(f"► Mode dégradé  : {detector.is_degraded}")
    print(f"► Alertes reçues : {len(alerts_received)}")

    # Simuler le retour à la normale
    print("\n► Simulation du retour à la normale...")
    lr.last_event_time = datetime.now(timezone.utc)
    time.sleep(6)

    print(f"► Statut après retour : {detector.current_status.value}")
    stop.set()
    print("\n=== Test terminé ===")
