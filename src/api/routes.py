"""
api/routes.py
Définition des routes REST pour l'API Flask ThreeSentinel.
Toutes les routes sont regroupées dans un Blueprint `api_bp`
et enregistrées dans app.py via app.register_blueprint().
"""

from flask import Blueprint, jsonify, request, abort
import ipaddress
from datetime import datetime, timezone

# --- Blueprint -----------------------------------------------------------------
api_bp = Blueprint("api", __name__, url_prefix="/api")

# Les dépendances sont importées ici pour éviter les imports circulaires
def _get_deps():
    from src.journal.logger import read_all, read_alerts, read_blocked
    from src.responder.firewall import (
        get_blocked_list, block_ip, unblock_ip, is_blocked
    )
    from src.scorer.risk_scorer import is_whitelisted
    from src.degraded.silence_detector import get_system_status as silence_check_all
    return {
        "read_all": read_all,
        "read_alerts": read_alerts,
        "read_blocked": read_blocked,
        "get_blocked_list": get_blocked_list,
        "block_ip": block_ip,
        "unblock_ip": unblock_ip,
        "is_blocked": is_blocked,
        "is_whitelisted": is_whitelisted,
        "silence_check_all": silence_check_all,
    }


# ── GET /api/status ─────────────────────────────────────────────────────────
@api_bp.route("/status", methods=["GET"])
def status():
    """
    État général du système.

    Réponse :
    {
        "status": "running",
        "blocked_ips": 3,
        "active_alerts": 12,
        "suspicious_silence": [],
        "system": "threesentinel v1.0"
    }
    """
    d = _get_deps()
    blocked  = d["get_blocked_list"]()
    alerts   = d["read_alerts"](min_level=2)
    silence  = d["silence_check_all"]()
    susp_sil = [silence] if silence.get("status") == "suspicious_silence" else []

    return jsonify({
        "status":             "running",
        "blocked_ips":        len(blocked),
        "active_alerts":      len(alerts),
        "suspicious_silence": susp_sil,
        "system":             "threesentinel v1.0",
    })


# ── GET /api/alerts ──────────────────────────────────────────────────────────
@api_bp.route("/alerts", methods=["GET"])
def alerts():
    """
    Liste des alertes récentes.

    Query params :
      - min_level (int, défaut=2) : niveau minimum (1=MONITOR … 4=BLOCK)
      - limit (int, défaut=100)   : nombre max d'entrées retournées
    """
    d         = _get_deps()
    min_level = int(request.args.get("min_level", 2))
    limit     = int(request.args.get("limit", 100))
    data      = d["read_alerts"](min_level=min_level)[-limit:]
    return jsonify({"count": len(data), "alerts": data})


# ── GET /api/alerts/<ip> ─────────────────────────────────────────────────────
@api_bp.route("/alerts/<ip>", methods=["GET"])
def alerts_for_ip(ip):
    """
    Toutes les alertes pour une IP donnée.

    Exemple : GET /api/alerts/185.147.82.139
    """
    d          = _get_deps()
    all_alerts = d["read_alerts"](min_level=1)
    ip_alerts  = [a for a in all_alerts if a.get("ip") == ip]
    return jsonify({"ip": ip, "count": len(ip_alerts), "alerts": ip_alerts})


# ── GET /api/journal ─────────────────────────────────────────────────────────
@api_bp.route("/journal", methods=["GET"])
def journal():
    """
    Journal complet des décisions (JSONL).

    Query params :
      - limit (int, défaut=200) : nombre max d'entrées
    """
    d     = _get_deps()
    limit = int(request.args.get("limit", 200))
    data  = d["read_all"](limit=limit)
    return jsonify({"count": len(data), "entries": data})


# ── GET /api/blocked ─────────────────────────────────────────────────────────
@api_bp.route("/blocked", methods=["GET"])
def blocked():
    """
    Liste des IPs actuellement bloquées par iptables.

    Réponse :
    {
        "count": 2,
        "blocked": {
            "185.147.82.139": {"blocked_at": "...", "duration_minutes": 1440, "reason": "..."}
        }
    }
    """
    d    = _get_deps()
    data = d["get_blocked_list"]()
    return jsonify({"count": len(data), "blocked": data})


# ── POST /api/unblock/<ip> ───────────────────────────────────────────────────
@api_bp.route("/unblock/<ip>", methods=["POST"])
def unblock(ip):
    """
    Déblocage manuel d'une IP.

    Exemple : POST /api/unblock/185.147.82.139
    Réponse :
    { "ip": "185.147.82.139", "unblocked": true }
    """
    if not ip:
        abort(400, description="IP requise")
    d       = _get_deps()
    result  = d["unblock_ip"](ip)
    success = result.get("success", False)
    return jsonify({"ip": ip, "unblocked": success, "details": result})


# ── POST /api/whitelist/<ip> ─────────────────────────────────────────────────
@api_bp.route("/whitelist/<ip>", methods=["POST"])
def whitelist_add(ip):
    """
    Ajoute une IP à la whitelist (persiste dans config/whitelist.yaml).

    Exemple : POST /api/whitelist/10.0.0.50
    Réponse :
    { "ip": "10.0.0.50", "whitelisted": true }
    """
    # Validation format IP
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        abort(400, description=f"Adresse IP invalide : {ip}")

    try:
        import yaml
        wl_path = "config/whitelist.yaml"
        with open(wl_path) as f:
            wl = yaml.safe_load(f) or {}

        trusted = wl.setdefault("trusted_ips", [])
        if ip not in trusted:
            trusted.append(ip)
            with open(wl_path, "w") as f:
                yaml.dump(wl, f, default_flow_style=False, allow_unicode=True)

        # Forcer le rechargement du cache whitelist
        import src.scorer.risk_scorer as rs
        rs._whitelist = None

        return jsonify({"ip": ip, "whitelisted": True})
    except Exception as e:
        abort(500, description=str(e))


# ── DELETE /api/whitelist/<ip> ───────────────────────────────────────────────
@api_bp.route("/whitelist/<ip>", methods=["DELETE"])
def whitelist_remove(ip):
    """
    Retire une IP de la whitelist.

    Exemple : DELETE /api/whitelist/10.0.0.50
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        abort(400, description=f"Adresse IP invalide : {ip}")

    try:
        import yaml
        wl_path = "config/whitelist.yaml"
        with open(wl_path) as f:
            wl = yaml.safe_load(f) or {}

        trusted = wl.get("trusted_ips", [])
        if ip in trusted:
            trusted.remove(ip)
            with open(wl_path, "w") as f:
                yaml.dump(wl, f, default_flow_style=False, allow_unicode=True)

        import src.scorer.risk_scorer as rs
        rs._whitelist = None

        return jsonify({"ip": ip, "whitelisted": False})
    except Exception as e:
        abort(500, description=str(e))


# ── GET /api/confidence/<ip> ─────────────────────────────────────────────────
@api_bp.route("/confidence/<ip>", methods=["GET"])
def confidence(ip):
    """
    Score de confiance et de risque pour une IP donnée.

    Réponse conforme au format standard défini dans le README :
    {
        "ip": "185.147.82.139",
        "score_risque": 87,
        "score_confiance": 92,
        "score_cout_faux_positif": 8,
        "decision": "BLOCAGE",
        "niveau_reponse": 4,
        "preuves": [...],
        "whitelist": false,
        "integrite_log": "verified",
        "mode_degrade": false,
        "timestamp": "2026-04-25T03:21:14Z"
    }
    """
    d           = _get_deps()
    all_entries = d["read_all"](limit=1000)
    ip_entries  = [e for e in all_entries if e.get("ip") == ip]

    if not ip_entries:
        return jsonify({"ip": ip, "found": False, "message": "Aucune entrée pour cette IP"})

    latest = ip_entries[-1]

    # Score de confiance = 100 - penalité de confiance (normalisé 0-100)
    confidence_penalty = float(latest.get("confidence_penalty", 0))
    score_confiance    = round((1.0 - confidence_penalty) * 100, 1)

    # Intégrité log
    integrite = "verified" if latest.get("integrity_ok", True) else "tampered"

    return jsonify({
        "ip":                    ip,
        "found":                 True,
        "events_total":          len(ip_entries),
        "score_risque":          latest.get("risk_score"),
        "score_confiance":       score_confiance,
        "score_cout_faux_positif": latest.get("fp_cost_score"),
        "decision_score":        latest.get("decision_score"),
        "decision":              latest.get("decision"),
        "niveau_reponse":        latest.get("response_level"),
        "preuves":               latest.get("evidence", []),
        "whitelist":             d["is_whitelisted"](ip),
        "currently_blocked":     d["is_blocked"](ip),
        "integrite_log":         integrite,
        "mode_degrade":          latest.get("mode_degrade", False),
        "timestamp":             latest.get("journal_ts"),
    })


# ── GET /api/silence ─────────────────────────────────────────────────────────
@api_bp.route("/silence", methods=["GET"])
def silence():
    """
    Vérifie si des sources de logs sont silencieuses (Twist 2 — mode dégradé).

    Réponse :
    { "sources": [{"source": "ssh", "status": "suspicious_silence", ...}] }
    """
    d = _get_deps()
    return jsonify({"sources": d["silence_check_all"]()})


# ── GET /api/stats ───────────────────────────────────────────────────────────
@api_bp.route("/stats", methods=["GET"])
def stats():
    """
    Statistiques globales pour le dashboard.

    Réponse :
    {
        "total_events": 1450,
        "by_decision": {"BLOCK": 23, "ALERT": 87, "SLOWDOWN": 12, "MONITOR": 1328},
        "by_source": {"ssh": 735, "apache": 614, "network": 101},
        "top_ips": [{"ip": "...", "count": 15}, ...]
    }
    """
    d       = _get_deps()
    entries = d["read_all"](limit=5000)

    by_decision = {}
    by_source   = {}
    ip_counter  = {}

    for e in entries:
        dec = e.get("decision", "MONITOR")
        by_decision[dec] = by_decision.get(dec, 0) + 1

        src = e.get("source", "unknown")
        by_source[src] = by_source.get(src, 0) + 1

        ip = e.get("ip", "")
        if ip:
            ip_counter[ip] = ip_counter.get(ip, 0) + 1

    top_ips = sorted(
        [{"ip": ip, "count": c} for ip, c in ip_counter.items()],
        key=lambda x: x["count"],
        reverse=True
    )[:10]

    return jsonify({
        "total_events": len(entries),
        "by_decision":  by_decision,
        "by_source":    by_source,
        "top_ips":      top_ips,
    })


# ── POST /api/inject ─────────────────────────────────────────────────────────
@api_bp.route("/inject", methods=["POST"])
def inject():
    """
    Injecte un événement manuellement dans le pipeline (Utile pour la DÉMO).
    """
    from flask import current_app
    process_func = current_app.config.get("PROCESS_EVENT")
    if not process_func:
        return jsonify({"success": False, "error": "Pipeline non lié"}), 500

    data = request.json
    if not data:
        return jsonify({"success": False, "error": "JSON requis"}), 400

    # Enrichissement minimal pour passer les filtres
    data.setdefault("timestamp_log", datetime.now(timezone.utc).isoformat())
    data.setdefault("timestamp_recv", datetime.now(timezone.utc).isoformat())
    data.setdefault("integrity_ok", True)
    data.setdefault("source", "ssh")

    try:
        # Envoyer directement au pipeline de détection
        result = process_func(data)
        return jsonify({
            "success": True,
            "message": "Événement injecté avec succès",
            "decision": result.get("decision"),
            "risk_score": result.get("risk_score")
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ── GET /api/whitelist ───────────────────────────────────────────────────────
@api_bp.route("/whitelist", methods=["GET"])
def whitelist_list():
    """
    Retourne la whitelist complète (IPs de confiance + plages internes).
    """
    try:
        import yaml
        with open("config/whitelist.yaml") as f:
            wl = yaml.safe_load(f) or {}
        return jsonify(wl)
    except Exception as e:
        abort(500, description=str(e))
