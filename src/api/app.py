"""
api/app.py
Flask REST API — exposes system state, alerts, journal, and controls.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from flask import Flask, jsonify, request, abort
from src.journal.logger import read_all, read_alerts, read_blocked
from src.responder.firewall import (
    get_blocked_list, block_ip, unblock_ip, is_blocked
)
from src.scorer.risk_scorer import is_whitelisted
from src.degraded.silence_detector import check_all as silence_check_all

import yaml

app = Flask(__name__)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_config():
    try:
        with open("config/config.yaml") as f:
            return yaml.safe_load(f)
    except Exception:
        return {}


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/api/status", methods=["GET"])
def status():
    """Overall system health."""
    blocked   = get_blocked_list()
    alerts    = read_alerts(min_level=2)
    silence   = silence_check_all()
    suspicious_silence = [s for s in silence if s["status"] == "suspicious_silence"]

    return jsonify({
        "status":              "running",
        "blocked_ips":         len(blocked),
        "active_alerts":       len(alerts),
        "suspicious_silence":  suspicious_silence,
        "system":              "hackverse-ids v1.0",
    })


@app.route("/api/alerts", methods=["GET"])
def alerts():
    """Recent alerts (level >= 2)."""
    min_level = int(request.args.get("min_level", 2))
    limit     = int(request.args.get("limit", 100))
    data      = read_alerts(min_level=min_level)[-limit:]
    return jsonify({"count": len(data), "alerts": data})


@app.route("/api/alerts/<ip>", methods=["GET"])
def alerts_for_ip(ip):
    """All alerts for a specific IP."""
    all_alerts = read_alerts(min_level=1)
    ip_alerts  = [a for a in all_alerts if a.get("ip") == ip]
    return jsonify({"ip": ip, "count": len(ip_alerts), "alerts": ip_alerts})


@app.route("/api/journal", methods=["GET"])
def journal():
    """Full decision journal."""
    limit = int(request.args.get("limit", 200))
    data  = read_all(limit=limit)
    return jsonify({"count": len(data), "entries": data})


@app.route("/api/blocked", methods=["GET"])
def blocked():
    """Currently blocked IPs."""
    data = get_blocked_list()
    return jsonify({"count": len(data), "blocked": data})


@app.route("/api/unblock/<ip>", methods=["POST"])
def unblock(ip):
    """Manually unblock an IP."""
    if not ip:
        abort(400, "IP required")
    success = unblock_ip(ip)
    return jsonify({"ip": ip, "unblocked": success})


@app.route("/api/whitelist/<ip>", methods=["POST"])
def whitelist_ip(ip):
    """Add an IP to the whitelist (runtime only — persists until restart)."""
    import yaml, ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        abort(400, "Invalid IP address")

    try:
        with open("config/whitelist.yaml") as f:
            wl = yaml.safe_load(f)
        if ip not in wl.get("trusted_ips", []):
            wl.setdefault("trusted_ips", []).append(ip)
            with open("config/whitelist.yaml", "w") as f:
                yaml.dump(wl, f)
        # Force reload
        import src.scorer.risk_scorer as rs
        rs._whitelist = None
        return jsonify({"ip": ip, "whitelisted": True})
    except Exception as e:
        abort(500, str(e))


@app.route("/api/confidence/<ip>", methods=["GET"])
def confidence(ip):
    """Risk and confidence summary for a specific IP."""
    all_entries = read_all(limit=1000)
    ip_entries  = [e for e in all_entries if e.get("ip") == ip]

    if not ip_entries:
        return jsonify({"ip": ip, "found": False})

    latest = ip_entries[-1]
    return jsonify({
        "ip":                  ip,
        "found":               True,
        "events_total":        len(ip_entries),
        "risk_score":          latest.get("risk_score"),
        "fp_cost_score":       latest.get("fp_cost_score"),
        "decision_score":      latest.get("decision_score"),
        "confidence_penalty":  latest.get("confidence_penalty"),
        "whitelisted":         is_whitelisted(ip),
        "currently_blocked":   is_blocked(ip),
        "last_decision":       latest.get("decision"),
        "last_evidence":       latest.get("evidence", []),
    })


@app.route("/api/silence", methods=["GET"])
def silence():
    """Check for suspicious silence in log sources."""
    return jsonify({"sources": silence_check_all()})


@app.route("/", methods=["GET"])
def index():
    """Simple HTML dashboard."""
    from flask import redirect
    return redirect("/dashboard")


@app.route("/dashboard", methods=["GET"])
def dashboard():
    """Serve the HTML dashboard."""
    try:
        with open("src/dashboard/templates/index.html") as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>Dashboard not found</h1>", 404


def run_api(host="0.0.0.0", port=5000, debug=False):
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run_api(debug=True)
