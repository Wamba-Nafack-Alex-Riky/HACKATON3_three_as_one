"""
silence_detector.py  —  Mode dégradé
Detects when logs stop arriving — could be a network failure
or an attacker who has disabled logging.
Distinguishes between the two using heuristics.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_last_seen: dict[str, datetime] = {}   # source → last log timestamp


def update(source: str):
    """Call this every time a log from 'source' is received."""
    _last_seen[source] = datetime.now(timezone.utc)


def check_silence(source: str, threshold_seconds: int = 30) -> dict:
    """
    Returns a status dict for the given source.
    If no log has been received for threshold_seconds, raises a SILENCE alert.
    """
    now  = datetime.now(timezone.utc)
    last = _last_seen.get(source)

    if last is None:
        return {"source": source, "status": "never_received", "silence_seconds": None}

    silence_seconds = int((now - last).total_seconds())

    if silence_seconds >= threshold_seconds:
        # Heuristic: distinguish failure from attack
        # If silence > 5 × threshold, likely a failure not an attack
        if silence_seconds > threshold_seconds * 5:
            status  = "probable_failure"
            message = (
                f"No logs from '{source}' for {silence_seconds}s. "
                "Likely a network/service failure. Check the source."
            )
        else:
            status  = "suspicious_silence"
            message = (
                f"No logs from '{source}' for {silence_seconds}s. "
                "Could indicate log suppression by an attacker."
            )
        logger.warning(f"[SILENCE] {message}")
        return {
            "source":          source,
            "status":          status,
            "silence_seconds": silence_seconds,
            "message":         message,
            "last_seen":       last.isoformat(),
        }

    return {
        "source":          source,
        "status":          "ok",
        "silence_seconds": silence_seconds,
        "last_seen":       last.isoformat(),
    }


def check_all(threshold_seconds: int = 30) -> list[dict]:
    return [check_silence(src, threshold_seconds) for src in _last_seen]
