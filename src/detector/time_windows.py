"""
time_windows.py  —  Twist 2
Tracks per-IP event counts across 3 time windows: 10s, 1h, 24h.
Detects slow & silent battacks that stay under single-window thresholds.
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional


def _parse_ts(ts_str: str) -> datetime:
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
    return datetime.now(timezone.utc)


class WindowTracker:
    """
    Maintains a sliding event history per IP.
    Call .add(ip, timestamp) for every event, then .counts(ip, ref_time)
    to get how many events occurred in each window.
    """

    WINDOWS = {
        "10s":  10,
        "1h":   3_600,
        "24h":  86_400,
    }

    def __init__(self):
        # ip → list of datetime objects
        self._events: dict[str, list[datetime]] = defaultdict(list)

    def add(self, ip: str, ts: datetime):
        self._events[ip].append(ts)

    def counts(self, ip: str, ref_time: datetime) -> dict:
        result = {}
        for label, seconds in self.WINDOWS.items():
            count = sum(
                1 for t in self._events[ip]
                if 0 <= (ref_time - t).total_seconds() <= seconds
            )
            result[label] = count
        return result

    def behavioral_score(self, ip: str, ref_time: datetime,
                         source: str = "apache") -> float:
        """
        Returns a 0-100 behavioral suspicion score based on
        event frequency across all windows.
        """
        c = self.counts(ip, ref_time)

        if source == "ssh":
            # SSH: each failure in a short window is very suspicious
            score = (
                min(c["10s"]  / 3,  1.0) * 60 +
                min(c["1h"]   / 15, 1.0) * 25 +
                min(c["24h"]  / 40, 1.0) * 15
            )
        else:
            # HTTP / network: higher tolerance
            score = (
                min(c["10s"]  / 20,  1.0) * 40 +
                min(c["1h"]   / 100, 1.0) * 35 +
                min(c["24h"]  / 500, 1.0) * 25
            )

        return round(min(score, 100.0), 1)


# ── Module-level singleton used by the full pipeline ──────────────────────────
_tracker = WindowTracker()


def track_and_score(record: dict) -> dict:
    """
    Registers the event and returns the record enriched with:
      - win_10s / win_1h / win_24h : event counts per window
      - behavioral_score           : 0-100 suspicion from activity frequency
    """
    ip     = record.get("ip", "unknown")
    source = record.get("source", "apache")
    ts     = _parse_ts(str(record.get("timestamp_log", "")))

    _tracker.add(ip, ts)
    counts = _tracker.counts(ip, ts)
    bscore = _tracker.behavioral_score(ip, ts, source)

    return {
        **record,
        "win_10s":          counts["10s"],
        "win_1h":           counts["1h"],
        "win_24h":          counts["24h"],
        "behavioral_score": bscore,
    }


def track_batch(records: list[dict]) -> list[dict]:
    """Process in chronological order so window counts are correct."""
    sorted_recs = sorted(
        records,
        key=lambda r: str(r.get("timestamp_log", ""))
    )
    return [track_and_score(r) for r in sorted_recs]
