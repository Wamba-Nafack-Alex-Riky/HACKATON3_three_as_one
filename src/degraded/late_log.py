"""
late_log.py  —  Mode dégradé / Twist 1
Gestion des logs tardifs et incohérents.

Un log est considéré "tardif" si son timestamp_log est très antérieur
à son timestamp_recv. Dans ce cas :
  - La confiance est réduite (confidence_penalty augmenté)
  - Un flag mode_degrade=True est ajouté au record
  - Le record est toujours traité mais avec un poids réduit dans le scoring

Un log est "incohérent" si des champs clés sont absents, ont des valeurs
impossibles (ex: status=999, port=0 sur SSH), ou si les timestamps sont
dans le futur.
"""

from datetime import datetime, timezone
from typing import Optional
import logging

logger = logging.getLogger(__name__)

# Seuils par défaut (surchargés par config.yaml si disponible)
LATE_THRESHOLD_SECONDS   = 60      # 60s de délai = log tardif
FUTURE_THRESHOLD_SECONDS = 5       # 5s dans le futur = timestamp suspect
MAX_LATE_PENALTY         = 0.50    # Pénalité max pour un log très tardif


def _parse_ts(ts_str: str) -> Optional[datetime]:
    formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%z",
        "%d/%b/%Y:%H:%M:%S %z",
        "%d/%b/%Y:%H:%M:%S",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(str(ts_str).strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def _load_threshold() -> int:
    """Charge le seuil depuis config.yaml si disponible."""
    try:
        import yaml
        with open("config/config.yaml") as f:
            cfg = yaml.safe_load(f)
        return int(cfg.get("degraded", {}).get(
            "late_log_threshold_seconds", LATE_THRESHOLD_SECONDS))
    except Exception:
        return LATE_THRESHOLD_SECONDS


def check_late(record: dict) -> dict:
    """
    Analyse un record pour détecter s'il est tardif ou incohérent.
    Retourne le record enrichi avec :
      - late_seconds        : délai en secondes (0 si non calculable)
      - confidence_penalty  : pénalité additionnelle sur la confiance
      - mode_degrade        : True si le log est en mode dégradé
      - degrade_reason      : liste des raisons du mode dégradé
    """
    result    = record.copy()
    threshold = _load_threshold()
    now_utc   = datetime.now(timezone.utc)

    mode_degrade   = False
    degrade_reason = []
    confidence_penalty = float(record.get("confidence_penalty", 0.0))
    late_seconds   = int(record.get("late_seconds", 0))

    # ── 1. Vérification du délai timestamp ────────────────────────────────────
    ts_log  = _parse_ts(str(record.get("timestamp_log",  "")))
    ts_recv = _parse_ts(str(record.get("timestamp_recv", "")))

    if ts_log is None:
        # Timestamp manquant ou illisible
        mode_degrade = True
        degrade_reason.append("timestamp_log manquant ou illisible")
        confidence_penalty = max(confidence_penalty + 0.20, 0.20)

    elif ts_log > now_utc.replace(tzinfo=ts_log.tzinfo if ts_log.tzinfo else timezone.utc):
        # Timestamp dans le futur → très suspect (manipulation possible)
        future_s = int((ts_log - now_utc).total_seconds())
        if future_s > FUTURE_THRESHOLD_SECONDS:
            mode_degrade = True
            degrade_reason.append(f"timestamp dans le futur de {future_s}s — manipulation possible")
            confidence_penalty = max(confidence_penalty + 0.40, 0.40)

    else:
        # Calcul du délai
        ref_recv = ts_recv if ts_recv else now_utc
        if ts_log.tzinfo and ref_recv.tzinfo is None:
            ref_recv = ref_recv.replace(tzinfo=timezone.utc)
        elif not ts_log.tzinfo:
            ts_log = ts_log.replace(tzinfo=timezone.utc)
            ref_recv = ref_recv.replace(tzinfo=timezone.utc)

        late_seconds = max(0, int((ref_recv - ts_log).total_seconds()))

        if late_seconds > threshold:
            mode_degrade = True
            degrade_reason.append(f"log tardif de {late_seconds}s (seuil={threshold}s)")
            # Pénalité linéaire : 0 → MAX_LATE_PENALTY sur 10× le seuil
            ratio = min(late_seconds / (threshold * 10), 1.0)
            extra_penalty = round(MAX_LATE_PENALTY * ratio, 3)
            confidence_penalty = min(confidence_penalty + extra_penalty, 1.0)
            logger.debug(f"[LATE-LOG] {record.get('ip','?')} — {late_seconds}s de retard")

    # ── 2. Cohérence des champs ────────────────────────────────────────────────
    source = record.get("source", "apache")

    if source == "ssh":
        event = str(record.get("event", "")).strip()
        if event not in ("Failed password", "Accepted publickey", ""):
            mode_degrade = True
            degrade_reason.append(f"événement SSH inconnu: '{event}'")
            confidence_penalty = min(confidence_penalty + 0.10, 1.0)

    elif source == "apache":
        try:
            status = int(record.get("status", 0))
        except (ValueError, TypeError):
            status = 0
        if not (100 <= status <= 599):
            mode_degrade = True
            degrade_reason.append(f"status HTTP invalide: {status}")
            confidence_penalty = min(confidence_penalty + 0.10, 1.0)

    elif source == "network":
        try:
            dst_port = int(record.get("dst_port", 0))
        except (ValueError, TypeError):
            dst_port = -1
        if not (0 <= dst_port <= 65535):
            mode_degrade = True
            degrade_reason.append(f"port de destination invalide: {dst_port}")
            confidence_penalty = min(confidence_penalty + 0.10, 1.0)

    # ── Mise à jour du record ─────────────────────────────────────────────────
    result["late_seconds"]       = late_seconds
    result["confidence_penalty"] = round(confidence_penalty, 4)
    result["mode_degrade"]       = mode_degrade
    result["degrade_reason"]     = degrade_reason

    if mode_degrade:
        logger.info(
            f"[DEGRADE] {record.get('ip','?')} ({source}) — "
            f"raisons: {', '.join(degrade_reason)}"
        )

    return result


def check_late_batch(records: list[dict]) -> list[dict]:
    """Applique check_late à tous les records."""
    return [check_late(r) for r in records]
