"""
decision.py  —  Twist 3
Graduated response: MONITOR → ALERT → SLOWDOWN → BLOCK.
Decision based on decision_score, not raw risk_score,
to account for false-positive cost.
"""

import yaml

CONFIG_PATH = "config/config.yaml"
_config     = None


def _load_config() -> dict:
    global _config
    if _config is None:
        try:
            with open(CONFIG_PATH) as f:
                _config = yaml.safe_load(f)
        except FileNotFoundError:
            _config = {}
    return _config


def _get_thresholds() -> dict:
    cfg = _load_config()
    s   = cfg.get("scoring", {})
    return {
        "block":    s.get("block_threshold",    75),
        "slowdown": s.get("slowdown_threshold", 65),
        "alert":    s.get("alert_threshold",    50),
    }


def decide(record: dict) -> dict:
    """
    Adds to the record:
      - response_level   : 1=MONITOR 2=ALERT 3=SLOWDOWN 4=BLOCK
      - response_label   : human-readable label
      - decision         : same as response_label
      - justification    : plain-text reason (readable by jury)
      - evidence         : list of evidence strings
    """
    decision_score = float(record.get("decision_score", 0))
    risk_score     = float(record.get("risk_score",     0))
    fp_cost        = float(record.get("fp_cost_score",  0))
    whitelisted    = record.get("whitelisted", False)
    source         = record.get("source", "unknown")
    ip             = record.get("ip", "unknown")
    thresholds     = _get_thresholds()

    # --- Build evidence list ---
    evidence = []

    if record.get("ip_is_external"):
        evidence.append("External IP (non-internal network)")

    if record.get("agent_malicious"):
        evidence.append(f"Malicious user-agent: {record.get('user_agent','')[:40]}")

    if record.get("path_sqli"):
        evidence.append(f"SQL injection in path: {record.get('path','')[:60]}")

    if record.get("path_traversal"):
        evidence.append(f"Path traversal attempt: {record.get('path','')[:60]}")

    if record.get("path_sensitive"):
        evidence.append(f"Access to sensitive path: {record.get('path','')[:60]}")

    if record.get("rule_triggered"):
        evidence.append(f"SSH rule: {record.get('rule_triggered')}")

    if record.get("prediction") == "anomaly":
        evidence.append(f"Network anomaly detected (iso_score={record.get('iso_raw_score')})")

    if record.get("behavioral_score", 0) > 50:
        evidence.append(
            f"High behavioral score: {record.get('behavioral_score')} "
            f"(10s={record.get('win_10s',0)}, 1h={record.get('win_1h',0)}, "
            f"24h={record.get('win_24h',0)})"
        )

    if record.get("late_seconds", 0) > 60:
        evidence.append(f"Log arrived {record.get('late_seconds')}s late (confidence reduced)")

    if not record.get("integrity_ok"):
        evidence.append("Log integrity check FAILED — possible tampering")

    # --- Whitelisted: never block, always human review ---
    # TWIST 4: Unless lateral movement is detected from a compromised internal/whitelisted IP
    lateral_movement = record.get("lateral_movement_detected", False)
    if whitelisted and not lateral_movement:
        return {
            **record,
            "evidence":       evidence,
            "response_level": 2,
            "response_label": "ALERT",
            "decision":       "ALERT",
            "justification":  (
                f"IP {ip} is whitelisted. Risk={risk_score:.0f} but "
                f"false-positive cost={fp_cost:.0f}. "
                "Forwarded to human review — never auto-blocked."
            ),
        }

    # --- Graduated response ---
    if decision_score >= thresholds["block"]:
        level, label = 4, "BLOCK"
        justification = (
            f"Decision score {decision_score:.0f} ≥ threshold {thresholds['block']}. "
            f"Risk={risk_score:.0f}, FP-cost={fp_cost:.0f}. "
            f"Automatic block applied."
        )
    elif decision_score >= thresholds["slowdown"]:
        level, label = 3, "SLOWDOWN"
        justification = (
            f"Decision score {decision_score:.0f} ≥ threshold {thresholds['slowdown']}. "
            f"Rate-limiting applied. Human review recommended."
        )
    elif decision_score >= thresholds["alert"]:
        level, label = 2, "ALERT"
        justification = (
            f"Decision score {decision_score:.0f} ≥ threshold {thresholds['alert']}. "
            f"Alert raised. No automatic action."
        )
    else:
        level, label = 1, "MONITOR"
        justification = (
            f"Decision score {decision_score:.0f} below all thresholds. "
            f"Event logged and monitored."
        )

    return {
        **record,
        "evidence":       evidence,
        "response_level": level,
        "response_label": label,
        "decision":       label,
        "justification":  justification,
    }


def decide_batch(records: list[dict]) -> list[dict]:
    return [decide(r) for r in records]
