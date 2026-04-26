"""
risk_scorer.py
Combines detector_score, behavioral_score, and confidence_penalty
into a single final risk score (0-100) per record.
Also computes the false-positive cost score (Twist 3).
"""

import yaml
import ipaddress

WHITELIST_PATH = "config/whitelist.yaml"
CONFIG_PATH    = "config/config.yaml"

_whitelist = None
_config    = None


def _load_whitelist() -> dict:
    global _whitelist
    if _whitelist is None:
        try:
            with open(WHITELIST_PATH) as f:
                _whitelist = yaml.safe_load(f)
        except FileNotFoundError:
            _whitelist = {"internal_ranges": [], "trusted_ips": [],
                          "trusted_users": []}
    return _whitelist


def _load_config() -> dict:
    global _config
    if _config is None:
        try:
            with open(CONFIG_PATH) as f:
                _config = yaml.safe_load(f)
        except FileNotFoundError:
            _config = {}
    return _config


def is_whitelisted(ip: str, user: str = "") -> bool:
    wl = _load_whitelist()

    if ip in wl.get("trusted_ips", []):
        return True

    if user and user in wl.get("trusted_users", []):
        return True

    for cidr in wl.get("internal_ranges", []):
        try:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
                return True
        except ValueError:
            continue

    return False


from src.scorer.cost_scorer import compute_fp_cost


def score(record: dict) -> dict:
    """
    Returns the record enriched with:
      - risk_score            : final 0-100 risk score
      - fp_cost_score         : false-positive cost (Twist 3)
      - decision_score        : risk - fp_cost (what drives the decision)
      - whitelisted           : bool
      - confidence_multiplier : 1.0 reduced by integrity/latency penalty
    """
    # --- Gather sub-scores ---
    detector_score    = float(record.get("detector_score",    0))
    behavioral_score  = float(record.get("behavioral_score",  0))
    confidence_penalty = float(record.get("confidence_penalty", 0))

    # ── TWIST 6 : Mode Release (Concept Drift) ─────────────────────────
    # On bride l'IA et l'analyse comportementale qui sont devenues obsolètes,
    # à moins d'avoir une preuve irréfutable (signature) de malveillance.
    cfg = _load_config()
    is_release_mode = cfg.get("scoring", {}).get("release_mode", False)
    
    if is_release_mode:
        explicit_proof = (record.get("path_sqli") or 
                          record.get("agent_malicious") or 
                          record.get("path_traversal") or 
                          record.get("rule_triggered"))
        if not explicit_proof:
            detector_score = min(detector_score, 40.0)
            behavioral_score = min(behavioral_score, 40.0)

    # Weight: detector carries 70%, behavioral 30%
    raw_risk = detector_score * 0.70 + behavioral_score * 0.30

    # Apply confidence penalty from Twist 1 (tampered / late logs)
    confidence_mult = max(0.0, 1.0 - confidence_penalty)
    risk_score      = round(raw_risk * confidence_mult, 1)

    # False-positive cost (Twist 3)
    fp_cost    = compute_fp_cost(record)
    whitelisted = is_whitelisted(
        record.get("ip", ""), record.get("user", "")
    )

    # Decision score drives the response level
    decision_score = max(0.0, risk_score - fp_cost * 0.5)

    return {
        **record,
        "risk_score":            min(risk_score, 100.0),
        "fp_cost_score":         fp_cost,
        "decision_score":        round(decision_score, 1),
        "confidence_multiplier": round(confidence_mult, 3),
        "whitelisted":           whitelisted,
    }


def score_batch(records: list[dict]) -> list[dict]:
    return [score(r) for r in records]
