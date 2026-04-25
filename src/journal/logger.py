"""
journal/logger.py
Writes every decision to a structured JSON journal file.
Each line is a valid JSON object (JSONL format).
"""

import json
import os
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

JOURNAL_PATH = "journal.jsonl"

# Fields to keep in the journal (keep it readable for the jury)
JOURNAL_FIELDS = [
    "source", "timestamp_log", "timestamp_recv",
    "ip", "method", "path", "user", "event",
    "status", "bytes", "user_agent",
    # Detection
    "prediction", "detector", "rule_triggered",
    "detector_score", "behavioral_score",
    "win_10s", "win_1h", "win_24h",
    "ssh_fail_10s", "ssh_fail_1h", "ssh_fail_24h",
    # Scoring (Twist 1 + Twist 3)
    "risk_score", "fp_cost_score", "decision_score",
    "confidence_penalty", "confidence_multiplier",
    "integrity_ok", "late_seconds",
    # Decision
    "response_level", "response_label", "decision",
    "justification", "evidence",
    "whitelisted", "firewall_action",
    # Mode dégradé
    "mode_degrade", "is_duplicate",
]


def _filter(record: dict) -> dict:
    out = {}
    for field in JOURNAL_FIELDS:
        val = record.get(field)
        if val is not None:
            out[field] = val
    out["journal_ts"] = datetime.now(timezone.utc).isoformat()
    return out


def write(record: dict):
    """Append one decision record to the journal."""
    entry = _filter(record)
    try:
        with open(JOURNAL_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.error(f"[JOURNAL] Write failed: {e}")


def write_batch(records: list[dict]):
    for rec in records:
        write(rec)


def read_all(limit: int = 500) -> list[dict]:
    """Read last `limit` entries from the journal."""
    if not os.path.exists(JOURNAL_PATH):
        return []
    entries = []
    try:
        with open(JOURNAL_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except Exception as e:
        logger.error(f"[JOURNAL] Read failed: {e}")
    return entries[-limit:]


def read_alerts(min_level: int = 2) -> list[dict]:
    """Return only entries with response_level >= min_level."""
    return [e for e in read_all(1000)
            if e.get("response_level", 1) >= min_level]


def read_blocked() -> list[dict]:
    """Return only BLOCK decisions."""
    return [e for e in read_all(1000)
            if e.get("decision") == "BLOCK"]
