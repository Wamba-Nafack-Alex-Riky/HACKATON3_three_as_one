"""
deduplicator.py  —  Mode dégradé
Detects and removes duplicate log entries before analysis.
A duplicate is a record with the same hash OR the same
(ip, timestamp_log, source, event/path) combination.
"""

import logging

logger = logging.getLogger(__name__)


def deduplicate(records: list[dict]) -> list[dict]:
    """
    Returns deduplicated records. Each removed duplicate is logged.
    The record enriched with 'is_duplicate': False for kept records.
    """
    seen_hashes: set[str] = set()
    seen_keys:   set[tuple] = set()
    result = []
    dup_count = 0

    for rec in records:
        log_hash = rec.get("log_hash", "")
        key = (
            rec.get("ip", ""),
            rec.get("timestamp_log", ""),
            rec.get("source", ""),
            rec.get("event", rec.get("path", "")),
        )

        is_dup = (log_hash and log_hash in seen_hashes) or key in seen_keys

        if is_dup:
            dup_count += 1
            logger.debug(f"[DEDUP] Duplicate removed: {key}")
        else:
            if log_hash:
                seen_hashes.add(log_hash)
            seen_keys.add(key)
            result.append({**rec, "is_duplicate": False})

    if dup_count:
        logger.info(f"[DEDUP] Removed {dup_count} duplicate records "
                    f"from {len(records)} total.")

    return result
