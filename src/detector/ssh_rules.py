"""
ssh_rules.py
Detects SSH brute force using temporal sliding windows.
No ML — pure rule-based counting (more explainable, faster, correct for this data).
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional


# Thresholds (can be overridden from config.yaml)
DEFAULT_THRESHOLDS = {
    "window_10s":  3,   # failures in 10 s  → ALERT
    "window_1h":  15,   # failures in 1 h   → BLOCK TEMP
    "window_24h": 40,   # failures in 24 h  → BLOCK LONG
}


def _parse_ts(ts_str: str) -> Optional[datetime]:
    formats = ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"]
    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str.strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


class SSHAnalyzer:
    """
    Stateful analyzer: keeps a history of events per IP to evaluate
    multi-window thresholds correctly across a batch of records.
    """

    def __init__(self, thresholds: dict = None):
        self.thresholds = thresholds or DEFAULT_THRESHOLDS
        # ip → list of (datetime, event_type)
        self._history: dict[str, list] = defaultdict(list)

    def _count_failures_in_window(self, ip: str, ref_time: datetime,
                                  window_seconds: int) -> int:
        count = 0
        for ts, event in self._history[ip]:
            delta = (ref_time - ts).total_seconds()
            if 0 <= delta <= window_seconds and event == "Failed password":
                count += 1
        return count

    def analyze(self, record: dict) -> dict:
        """
        Analyze a single SSH record. Returns the record enriched with:
          - ssh_fail_10s / ssh_fail_1h / ssh_fail_24h : failure counts
          - detector_score  : 0-100
          - prediction      : 'legit' | 'attack'
          - rule_triggered  : which rule fired (or None)
        """
        ip    = record.get("ip", "")
        event = record.get("event", "")
        ts    = _parse_ts(str(record.get("timestamp_log", "")))

        if ts is None:
            ts = datetime.now(timezone.utc)

        # Store event in history
        self._history[ip].append((ts, event))

        # Only failures are threats
        if event != "Failed password":
            return {
                **record,
                "prediction":    "legit",
                "detector_score": 0,
                "rule_triggered": None,
                "ssh_fail_10s":  0,
                "ssh_fail_1h":   0,
                "ssh_fail_24h":  0,
                "detector":      "ssh_rules",
            }

        fail_10s  = self._count_failures_in_window(ip, ts, 10)
        fail_1h   = self._count_failures_in_window(ip, ts, 3600)
        fail_24h  = self._count_failures_in_window(ip, ts, 86400)

        # Determine rule triggered and score
        rule_triggered = None
        detector_score = 0.0

        if fail_10s >= self.thresholds["window_10s"]:
            rule_triggered = f"ssh_brute_force_10s (≥{self.thresholds['window_10s']} failures)"
            detector_score = 95.0
        elif fail_1h >= self.thresholds["window_1h"]:
            rule_triggered = f"ssh_brute_force_1h (≥{self.thresholds['window_1h']} failures)"
            detector_score = 80.0
        elif fail_24h >= self.thresholds["window_24h"]:
            rule_triggered = f"ssh_brute_force_24h (≥{self.thresholds['window_24h']} failures)"
            detector_score = 65.0
        elif fail_1h >= 5:
            # Below threshold but suspicious — partial score
            detector_score = round(40 + (fail_1h / self.thresholds["window_1h"]) * 40, 1)

        prediction = "attack" if detector_score >= 50 else "legit"

        return {
            **record,
            "prediction":     prediction,
            "detector_score": min(detector_score, 100.0),
            "rule_triggered": rule_triggered,
            "ssh_fail_10s":   fail_10s,
            "ssh_fail_1h":    fail_1h,
            "ssh_fail_24h":   fail_24h,
            "detector":       "ssh_rules",
        }

    def analyze_batch(self, records: list[dict]) -> list[dict]:
        """
        Process records in chronological order so window counts are accurate.
        """
        sorted_recs = sorted(
            records,
            key=lambda r: str(r.get("timestamp_log", ""))
        )
        return [self.analyze(r) for r in sorted_recs]
