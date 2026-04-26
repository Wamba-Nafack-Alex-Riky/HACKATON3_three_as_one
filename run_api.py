"""
run_api.py — Lance uniquement l'API Flask (sans le pipeline de logs).

Usage :
  Terminal 1 (pipeline) : python main.py --no-api --fast
  Terminal 2 (API)      : python run_api.py

L'API lit le journal.jsonl produit par le pipeline et expose toutes les routes REST.
"""

import os
import sys
import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.api.app import app, run_api

# ── Config ────────────────────────────────────────────────────────────────────
def _load_config(path="config/config.yaml") -> dict:
    try:
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}

cfg = _load_config()
api_cfg = cfg.get("api", {})
host = api_cfg.get("host", "0.0.0.0")
port = api_cfg.get("port", 8888)

# ── Stats fallback (lecture directe du journal) ───────────────────────────────
def _get_stats_from_journal():
    """Calcule les stats directement depuis journal.jsonl (sans pipeline actif)."""
    from src.journal.logger import read_all
    from src.responder.firewall import get_blocked_list
    import threading
    from datetime import datetime, timezone

    entries = read_all(limit=5000)
    blocked = get_blocked_list()

    by_decision = {}
    for e in entries:
        dec = e.get("decision", "MONITOR")
        by_decision[dec] = by_decision.get(dec, 0) + 1

    return {
        "events_total":    len(entries),
        "events_blocked":  by_decision.get("BLOCK", 0),
        "events_alerted":  by_decision.get("ALERT", 0),
        "events_slowdown": by_decision.get("SLOWDOWN", 0),
        "events_monitor":  by_decision.get("MONITOR", 0),
        "events_skipped":  0,
        "start_time":      datetime.now(timezone.utc).isoformat(),
    }

# Injecter les dépendances minimales dans l'app Flask
app.config["GET_STATS"] = _get_stats_from_journal
# PROCESS_EVENT et SILENCE_DETECTOR resteront None → /api/inject retournera une erreur claire

if __name__ == "__main__":
    print(f"""
╔══════════════════════════════════════════════════════╗
║         ThreeSentinel — API Standalone               ║
╠══════════════════════════════════════════════════════╣
║  Dashboard : http://localhost:{port}/dashboard{' ' * 14}║
║  API REST  : http://{host}:{port:<29}║
║  Journal   : journal.jsonl (lecture seule)           ║
╚══════════════════════════════════════════════════════╝
    """)
    run_api(host=host, port=port, debug=False)
