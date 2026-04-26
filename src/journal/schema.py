"""
journal/schema.py
Schéma officiel d'un enregistrement de journal ThreeSentinel.
Utilisé pour la validation et la documentation lisible par le jury.
"""

from datetime import datetime, timezone


# ── Valeurs autorisées ────────────────────────────────────────────────────────

VALID_DECISIONS    = {"MONITOR", "ALERT", "SLOWDOWN", "BLOCK"}
VALID_SOURCES      = {"ssh", "apache", "network", "unknown"}
VALID_LEVELS       = {1, 2, 3, 4}
VALID_INTEGRITY    = {"verified", "tampered", "unknown"}
VALID_FW_ACTIONS   = {"none", "blocked", "block_failed",
                      "rate_limited", "rate_limit_failed"}


# ── Schéma de référence (valeurs par défaut) ──────────────────────────────────

JOURNAL_SCHEMA: dict = {
    # --- Identifiant de l'événement ---
    "journal_ts":          str,   # ISO-8601, horodatage d'écriture dans le journal
    "timestamp_recv":      str,   # ISO-8601, heure de réception du log
    "timestamp_log":       str,   # ISO-8601, heure déclarée dans le log source

    # --- Source ---
    "source":              str,   # "ssh" | "apache" | "network"
    "ip":                  str,   # Adresse IP source
    "user":                str,   # Utilisateur SSH (si applicable)

    # --- Données brutes (HTTP) ---
    "method":              str,   # GET / POST / PUT / DELETE
    "path":                str,   # Chemin HTTP
    "status_code":         int,   # Code HTTP (200, 403, 404, 500…)
    "bytes":               int,   # Taille de la réponse
    "user_agent":          str,   # User-Agent HTTP

    # --- Données brutes (SSH) ---
    "event":               str,   # "Accepted publickey" | "Failed password"

    # --- Détection ---
    "prediction":          str,   # "legit" | "attack" | "scan" | "anomaly"
    "detector":            str,   # "http_classifier" | "ssh_rules" | "network_anomaly"
    "rule_triggered":      str,   # Règle SSH déclenchée (ex: "window_10s")
    "detector_score":      float, # Score brut du détecteur (0-100)
    "behavioral_score":    float, # Score comportemental (0-100)

    # --- Fenêtres temporelles (SSH + comportement) ---
    "win_10s":             int,   # Nb d'événements dans les 10 dernières secondes
    "win_1h":              int,   # Nb d'événements dans la dernière heure
    "win_24h":             int,   # Nb d'événements dans les dernières 24 heures

    # --- Intégrité (Twist 1) ---
    "integrity_ok":        bool,  # True si le hash du log est valide
    "log_hash":            str,   # SHA256 du log brut
    "late_seconds":        float, # Délai entre timestamp_log et timestamp_recv

    # --- Scoring (Twist 1 + Twist 3) ---
    "risk_score":          float, # Score de risque final (0-100)
    "fp_cost_score":       float, # Score de coût d'un faux positif (0-100)
    "decision_score":      float, # risk_score - 0.5 * fp_cost (driver de la décision)
    "confidence_penalty":  float, # Pénalité de confiance (0.0 = aucune, 1.0 = max)
    "confidence_multiplier": float, # 1.0 - confidence_penalty

    # --- Décision (Twist 3) ---
    "response_level":      int,   # 1=MONITOR 2=ALERT 3=SLOWDOWN 4=BLOCK
    "response_label":      str,   # "MONITOR" | "ALERT" | "SLOWDOWN" | "BLOCK"
    "decision":            str,   # Identique à response_label
    "justification":       str,   # Justification textuelle lisible par le jury
    "evidence":            list,  # Liste de preuves (strings)

    # --- Whitelist ---
    "whitelisted":         bool,  # True si l'IP est dans la whitelist

    # --- Pare-feu ---
    "firewall_action":     str,   # "none" | "blocked" | "rate_limited" | ...

    # --- Mode dégradé ---
    "mode_degrade":        bool,  # True si le système tourne en mode dégradé
    "is_duplicate":        bool,  # True si ce log était un doublon (filtré)
}


# ── Exemple de journal complet (lisible jury) ─────────────────────────────────

EXAMPLE_ENTRY: dict = {
    "journal_ts":            "2026-04-25T03:21:14Z",
    "timestamp_recv":        "2026-04-25T03:21:14Z",
    "timestamp_log":         "2026-04-25T03:21:10Z",
    "source":                "ssh",
    "ip":                    "185.147.82.139",
    "user":                  "root",
    "event":                 "Failed password",
    "prediction":            "attack",
    "detector":              "ssh_rules",
    "rule_triggered":        "window_10s",
    "detector_score":        95.0,
    "behavioral_score":      80.0,
    "win_10s":               15,
    "win_1h":                42,
    "win_24h":               120,
    "integrity_ok":          True,
    "late_seconds":          4.0,
    "risk_score":            90.5,
    "fp_cost_score":         6.0,
    "decision_score":        87.5,
    "confidence_penalty":    0.0,
    "confidence_multiplier": 1.0,
    "response_level":        4,
    "response_label":        "BLOCK",
    "decision":              "BLOCK",
    "justification":         "Decision score 87.5 ≥ threshold 75. Risk=90.5, FP-cost=6.0. Automatic block applied.",
    "evidence": [
        "External IP (non-internal network)",
        "SSH rule: window_10s — 15 Failed password en 10s",
        "High behavioral score: 80 (10s=15, 1h=42, 24h=120)",
    ],
    "whitelisted":           False,
    "firewall_action":       "blocked",
    "mode_degrade":          False,
    "is_duplicate":          False,
}


# ── Fonctions utilitaires ─────────────────────────────────────────────────────

def validate(entry: dict) -> tuple[bool, list[str]]:
    """
    Vérifie qu'une entrée de journal respecte le schéma.
    Retourne (is_valid, liste_des_erreurs).
    """
    errors = []

    # Champs obligatoires
    required = ["journal_ts", "ip", "source", "decision", "response_level"]
    for field in required:
        if field not in entry:
            errors.append(f"Champ obligatoire manquant : '{field}'")

    # Valeurs contrôlées
    if "decision" in entry and entry["decision"] not in VALID_DECISIONS:
        errors.append(
            f"decision='{entry['decision']}' invalide. "
            f"Valeurs autorisées : {VALID_DECISIONS}"
        )

    if "source" in entry and entry["source"] not in VALID_SOURCES:
        errors.append(
            f"source='{entry['source']}' invalide. "
            f"Valeurs autorisées : {VALID_SOURCES}"
        )

    if "response_level" in entry and entry["response_level"] not in VALID_LEVELS:
        errors.append(
            f"response_level={entry['response_level']} invalide. "
            f"Valeurs autorisées : {VALID_LEVELS}"
        )

    # Plages numériques
    for field, lo, hi in [
        ("risk_score",     0, 100),
        ("fp_cost_score",  0, 100),
        ("decision_score", 0, 100),
    ]:
        val = entry.get(field)
        if val is not None:
            try:
                v = float(val)
                if not (lo <= v <= hi):
                    errors.append(f"{field}={v} hors plage [{lo}, {hi}]")
            except (TypeError, ValueError):
                errors.append(f"{field} doit être un nombre, reçu : {val!r}")

    return len(errors) == 0, errors


def to_jury_summary(entry: dict) -> dict:
    """
    Retourne une version simplifiée et lisible par le jury d'une entrée de journal.
    Format conforme au README.md.
    """
    confidence_penalty = float(entry.get("confidence_penalty", 0))
    score_confiance    = round((1.0 - confidence_penalty) * 100, 1)
    integrite          = "verified" if entry.get("integrity_ok", True) else "tampered"

    return {
        "ip":                      entry.get("ip"),
        "source":                  entry.get("source"),
        "score_risque":            entry.get("risk_score"),
        "score_confiance":         score_confiance,
        "score_cout_faux_positif": entry.get("fp_cost_score"),
        "decision":                entry.get("decision"),
        "niveau_reponse":          entry.get("response_level"),
        "preuves":                 entry.get("evidence", []),
        "whitelist":               entry.get("whitelisted", False),
        "integrite_log":           integrite,
        "mode_degrade":            entry.get("mode_degrade", False),
        "timestamp":               entry.get("journal_ts"),
        "justification":           entry.get("justification"),
    }


def format_for_jury(entries: list[dict]) -> list[dict]:
    """Convertit une liste d'entrées en résumés lisibles par le jury."""
    return [to_jury_summary(e) for e in entries]
