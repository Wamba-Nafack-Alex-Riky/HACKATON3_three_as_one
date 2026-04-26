"""
confidence.py  —  Twist 1
Score de confiance d'un enregistrement de log.

Combine :
  - L'intégrité du log (hachage SHA-256)
  - Le délai entre la date du log et la date de réception
  - La complétude du record (champs manquants = confiance réduite)

Retourne un score de confiance 0-100 (100 = totalement fiable)
et une pénalité 0.0-1.0 à appliquer au risk_score.
"""

from datetime import datetime, timezone
from typing import Optional


# Champs obligatoires selon la source du log
REQUIRED_FIELDS = {
    "apache":  ["ip", "method", "path", "status", "timestamp_log"],
    "ssh":     ["ip", "event", "user", "timestamp_log"],
    "network": ["ip", "dst_port", "protocol", "bytes_sent", "timestamp_log"],
}


def _count_missing(record: dict) -> int:
    """Compte les champs obligatoires absents ou vides."""
    source = record.get("source", "apache")
    fields = REQUIRED_FIELDS.get(source, [])
    missing = 0
    for f in fields:
        val = record.get(f)
        if val is None or str(val).strip() in ("", "nan", "None"):
            missing += 1
    return missing


def compute_confidence(record: dict,
                       late_threshold_seconds: int = 60) -> dict:
    """
    Retourne le record enrichi avec :
      - confidence_score   : 0-100 (100 = confiance totale)
      - confidence_penalty : 0.0-1.0 (pénalité sur le risk_score)
      - late_seconds       : délai entre log et réception
      - integrity_ok       : si le hachage est valide
    """
    result = record.copy()

    # ── 1. Intégrité du hachage ────────────────────────────────────────────────
    integrity_ok = record.get("integrity_ok", True)
    integrity_penalty = 0.0 if integrity_ok else 0.40

    # ── 2. Délai (double horodatage) ───────────────────────────────────────────
    late_seconds = int(record.get("late_seconds", 0))

    # Si late_seconds n'a pas encore été calculé, on le calcule ici
    if late_seconds == 0:
        ts_log  = _parse_ts(str(record.get("timestamp_log",  "")))
        ts_recv = _parse_ts(str(record.get("timestamp_recv", "")))
        if ts_log and ts_recv:
            late_seconds = max(0, int((ts_recv - ts_log).total_seconds()))

    if late_seconds > late_threshold_seconds:
        # Pénalité croissante : 0.05 par tranche de seuil, max 0.35
        ratio = min(late_seconds / (late_threshold_seconds * 10), 1.0)
        latency_penalty = round(0.35 * ratio, 3)
    else:
        latency_penalty = 0.0

    # ── 3. Complétude du record ────────────────────────────────────────────────
    n_missing = _count_missing(record)
    completeness_penalty = min(n_missing * 0.05, 0.25)

    # ── Score final ───────────────────────────────────────────────────────────
    total_penalty = min(
        integrity_penalty + latency_penalty + completeness_penalty,
        1.0
    )
    confidence_score = round((1.0 - total_penalty) * 100, 1)

    result["confidence_score"]   = confidence_score
    result["confidence_penalty"] = round(total_penalty, 4)
    result["late_seconds"]       = late_seconds
    result["integrity_ok"]       = integrity_ok
    result["missing_fields"]     = n_missing

    return result


def compute_batch(records: list[dict],
                  late_threshold_seconds: int = 60) -> list[dict]:
    return [compute_confidence(r, late_threshold_seconds) for r in records]


# ── Helpers ────────────────────────────────────────────────────────────────────

def _parse_ts(ts_str: str) -> Optional[datetime]:
    formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%z",
        "%d/%b/%Y:%H:%M:%S %z",
        "%d/%b/%Y:%H:%M:%S",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str.strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None
