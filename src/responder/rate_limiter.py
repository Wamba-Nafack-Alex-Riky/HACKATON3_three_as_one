"""
rate_limiter.py
─────────────────────────────────────────────────────────────────────────────
Implémente un rate-limiting applicatif par IP (Token Bucket Algorithm).

Rôle dans le pipeline :
  - Déclenché quand decision.py retourne response_level == 3 (SLOWDOWN).
  - Au lieu de bloquer immédiatement l'IP (niveau BLOCK), on lui impose
    un délai artificiel ou on refuse les events excédentaires.
  - Permet une réponse graduée : ralentir avant de bloquer.

Algorithme — Token Bucket :
  Chaque IP dispose d'un "seau" de tokens. Chaque event consomme 1 token.
  Les tokens se rechargent à un taux fixe. Quand le seau est vide → rejet.
  C'est l'algorithme standard des rate-limiters (nginx, AWS API Gateway...).

Intégration :
  from src.responder.rate_limiter import check_rate_limit, apply_rate_limit

  record = apply_rate_limit(record)   # enrichit record avec rate_limit_*
  if record["rate_limit_allowed"]:
      # traiter normalement
  else:
      # ignorer / logger comme rejeté
"""

import time
import threading
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ─── Configuration ────────────────────────────────────────────────────────────

# Taux de recharge : 1 token toutes les N secondes pour les IPs sous rate-limit
REFILL_RATE_SECONDS = 2.0       # 1 token rechargé toutes les 2 secondes
MAX_TOKENS          = 10        # Capacité max du seau (burst max)
SLOWDOWN_CAPACITY   = 3         # Seau réduit pour les IPs en SLOWDOWN
SLOWDOWN_REFILL     = 5.0       # Recharge plus lente pour IPs suspectes


# ─── Token Bucket ─────────────────────────────────────────────────────────────

@dataclass
class TokenBucket:
    """Représente le seau de tokens d'une IP."""
    ip:           str
    tokens:       float = field(default=float(MAX_TOKENS))
    max_tokens:   float = field(default=float(MAX_TOKENS))
    refill_rate:  float = field(default=REFILL_RATE_SECONDS)  # secondes par token
    last_refill:  float = field(default_factory=time.monotonic)
    is_limited:   bool  = False   # True si l'IP est en mode SLOWDOWN actif
    limited_at:   Optional[float] = None

    def _refill(self):
        """Recharge les tokens selon le temps écoulé."""
        now     = time.monotonic()
        elapsed = now - self.last_refill
        # Nombre de tokens à ajouter en fonction du temps écoulé
        new_tokens = elapsed / self.refill_rate
        if new_tokens >= 1.0:
            self.tokens     = min(self.max_tokens, self.tokens + new_tokens)
            self.last_refill = now

    def consume(self) -> bool:
        """
        Consomme 1 token. Retourne True si autorisé, False si rejeté.
        """
        self._refill()
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


# ─── Registry des IPs ─────────────────────────────────────────────────────────

_buckets: dict[str, TokenBucket] = {}
_lock    = threading.Lock()


def _get_or_create_bucket(ip: str) -> TokenBucket:
    """Retourne le bucket de l'IP, le crée s'il n'existe pas."""
    if ip not in _buckets:
        _buckets[ip] = TokenBucket(ip=ip)
    return _buckets[ip]


# ─── API publique ──────────────────────────────────────────────────────────────

def apply_slowdown(ip: str):
    """
    Applique le mode SLOWDOWN à une IP :
    réduit sa capacité et ralentit la recharge.
    Appelé par le pipeline quand decision_level == 3.
    """
    with _lock:
        bucket = _get_or_create_bucket(ip)
        if not bucket.is_limited:
            bucket.is_limited  = True
            bucket.limited_at  = time.monotonic()
            bucket.max_tokens  = float(SLOWDOWN_CAPACITY)
            bucket.tokens      = min(bucket.tokens, float(SLOWDOWN_CAPACITY))
            bucket.refill_rate = SLOWDOWN_REFILL
            logger.info(f"[RateLimiter] SLOWDOWN appliqué à {ip} "
                        f"(capacity={SLOWDOWN_CAPACITY}, refill={SLOWDOWN_REFILL}s)")


def remove_slowdown(ip: str):
    """
    Retire le mode SLOWDOWN d'une IP (appelé par unban.py).
    Remet les paramètres normaux.
    """
    with _lock:
        if ip in _buckets:
            bucket             = _buckets[ip]
            bucket.is_limited  = False
            bucket.limited_at  = None
            bucket.max_tokens  = float(MAX_TOKENS)
            bucket.refill_rate = REFILL_RATE_SECONDS
            logger.info(f"[RateLimiter] Slowdown retiré pour {ip}")


def check_rate_limit(ip: str) -> tuple[bool, dict]:
    """
    Vérifie si un event de cette IP est autorisé.

    Returns
    -------
    allowed : bool   — True si l'event peut passer
    info    : dict   — Métadonnées pour le journal
    """
    with _lock:
        bucket  = _get_or_create_bucket(ip)
        allowed = bucket.consume()
        info = {
            "rate_limited":   bucket.is_limited,
            "tokens_left":    round(bucket.tokens, 2),
            "rate_allowed":   allowed,
        }
        if not allowed:
            logger.debug(f"[RateLimiter] {ip} — event rejeté (bucket vide)")
        return allowed, info


def apply_rate_limit(record: dict) -> dict:
    """
    Fonction principale appelée par le pipeline pour chaque event.

    - Si response_level == 3 (SLOWDOWN), active le mode lent sur l'IP.
    - Consomme un token et indique si l'event est autorisé.
    - Enrichit le record avec les champs rate_limit_*.

    Usage dans le pipeline :
        record = apply_rate_limit(record)
        if not record["rate_limit_allowed"]:
            return   # event rejeté → ne pas traiter davantage
    """
    ip    = record.get("ip", "")
    level = record.get("response_level", 1)

    if not ip:
        return {**record, "rate_limit_allowed": True, "rate_limited": False}

    # Activer le slowdown si décidé par decision.py
    if level >= 3:
        apply_slowdown(ip)

    allowed, info = check_rate_limit(ip)

    enriched = {
        **record,
        "rate_limit_allowed": allowed,
        **info,
    }

    if not allowed:
        logger.warning(
            f"[RateLimiter] Event REJETÉ — IP={ip} | "
            f"level={level} | tokens={info['tokens_left']}"
        )

    return enriched


def get_limited_ips() -> list[dict]:
    """
    Retourne la liste des IPs actuellement sous rate-limit.
    Utilisé par l'API REST (Iness) pour le dashboard.
    """
    with _lock:
        return [
            {
                "ip":         ip,
                "tokens":     round(b.tokens, 2),
                "max_tokens": b.max_tokens,
                "is_limited": b.is_limited,
                "limited_at": b.limited_at,
            }
            for ip, b in _buckets.items()
            if b.is_limited
        ]


def get_stats() -> dict:
    """Stats globales pour le dashboard."""
    with _lock:
        limited = sum(1 for b in _buckets.values() if b.is_limited)
        return {
            "total_tracked_ips": len(_buckets),
            "currently_limited": limited,
        }
