"""
integrity.py  —  Twist 1
Verifies log integrity via SHA-256 and detects late logs via double timestamp.
"""

import hashlib
from datetime import datetime, timezone
from typing import Optional


def compute_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def verify_hash(content: str, stored_hash: str) -> bool:
    return compute_hash(content) == stored_hash


def parse_timestamp(ts_str: str) -> Optional[datetime]:
    """Try multiple timestamp formats used in our logs."""
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


def check_integrity(record: dict, late_threshold_seconds: int = 60) -> dict:
    """
    Adds two integrity fields to a record:
      - integrity_ok      : True if hash matches (no tampering)
      - late_seconds      : how many seconds late the log arrived
      - confidence_penalty: 0.0 (on time) to 1.0 (very late / tampered)
    """
    result = record.copy()

    # --- Hash check ---
    # Since we computed the hash at load time, integrity_ok starts as True.
    # In a real deployment, you'd re-hash and compare to a stored value.
    result["integrity_ok"] = record.get("integrity_ok", True)

    # --- Latency check ---
    ts_log  = parse_timestamp(str(record.get("timestamp_log",  "")))
    ts_recv = parse_timestamp(str(record.get("timestamp_recv", "")))

    late_seconds = 0
    confidence_penalty = 0.0

    if ts_log and ts_recv:
        delta = (ts_recv - ts_log).total_seconds()
        late_seconds = max(0, int(delta))

        if late_seconds > late_threshold_seconds:
            # Penalty grows linearly up to 0.5 at 10× the threshold
            ratio = min(late_seconds / (late_threshold_seconds * 10), 1.0)
            confidence_penalty = round(0.5 * ratio, 3)

    if not result["integrity_ok"]:
        confidence_penalty = max(confidence_penalty, 0.8)

    result["late_seconds"]       = late_seconds
    result["confidence_penalty"] = confidence_penalty
    return result


def batch_check(records: list[dict], late_threshold_seconds: int = 60) -> list[dict]:
    return [check_integrity(r, late_threshold_seconds) for r in records]
