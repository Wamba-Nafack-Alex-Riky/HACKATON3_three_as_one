"""
sensor_flood.py — Twist 5
─────────────────────────────────────────────────────────────────────────────
Détection de compromission par inondation (Alert Fatigue).
Si un capteur (ex: apache) envoie un volume de logs délirant, on le considère
comme compromis et on rejette ses logs pour sauver le SIEM et l'équipe SOC.
"""

import time
import threading
import logging

logger = logging.getLogger(__name__)

# ─── Configuration ────────────────────────────────────────────────────────────
# Seuil : max 50 événements par seconde et par source en moyenne.
# Burst autorisé (max_tokens) : 100 événements.
REFILL_RATE_SECONDS = 0.02  # 1 token toutes les 0.02s (soit 50 tokens par sec)
MAX_TOKENS          = 100

class SensorBucket:
    def __init__(self, source: str):
        self.source = source
        self.tokens = float(MAX_TOKENS)
        self.last_refill = time.monotonic()
        self.is_flooding = False
        self.flood_alert_sent = False
        self.lock = threading.Lock()

    def consume(self) -> bool:
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            
            # Recharge (50 tokens par seconde)
            new_tokens = elapsed / REFILL_RATE_SECONDS
            if new_tokens > 0:
                self.tokens = min(float(MAX_TOKENS), self.tokens + new_tokens)
                self.last_refill = now
            
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                
                # S'il était en inondation mais que les tokens remontent bien,
                # on pourrait le sortir de quarantaine (hystérésis)
                # Mais en sécurité, on reste prudent. On le sort s'il est au max.
                if self.is_flooding and self.tokens >= MAX_TOKENS * 0.9:
                    self.is_flooding = False
                    self.flood_alert_sent = False
                    logger.info(f"[SensorFlood] Capteur '{self.source}' est de nouveau stable.")
                return True
            else:
                self.is_flooding = True
                return False

_sensors: dict[str, SensorBucket] = {}
_sensors_lock = threading.Lock()

def _get_bucket(source: str) -> SensorBucket:
    with _sensors_lock:
        if source not in _sensors:
            _sensors[source] = SensorBucket(source)
        return _sensors[source]

def check_sensor_flood(source: str) -> tuple[bool, bool]:
    """
    Vérifie si le capteur est en inondation.
    Retourne (is_flooding, should_send_alert).
    """
    if not source or source == "unknown":
        return False, False
        
    bucket = _get_bucket(source)
    allowed = bucket.consume()
    
    is_flooding = not allowed
    should_send_alert = False
    
    if is_flooding:
        with bucket.lock:
            if not bucket.flood_alert_sent:
                bucket.flood_alert_sent = True
                should_send_alert = True
                
    return is_flooding, should_send_alert
