"""
journal/logger.py  —  HackVerse IDS
====================================
Écrit chaque décision du pipeline dans un journal structuré (JSONL).
Chaque ligne est un objet JSON valide et autonome, lisible directement
par le jury, un SIEM, ou grep.

Format : journal.jsonl  (JSON Lines — une entrée par ligne)

Fonctions publiques :
  write(record)              → écrit 1 entrée
  write_batch(records)       → écrit N entrées
  read_all(limit)            → lit les N dernières entrées
  read_alerts(min_level)     → filtre alertes niveau >= min_level
  read_blocked()             → uniquement les décisions BLOCK
  export_jury(path)          → exporte un JSON lisible jury
  stats()                    → statistiques globales du journal
  rotate(max_lines)          → garde seulement les max_lines dernières
"""

import json
import os
import logging
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

JOURNAL_PATH     = os.environ.get("HACKVERSE_JOURNAL", "journal.jsonl")
JOURNAL_MAX_LINES = 10_000   # Au-delà → rotation automatique

# ── Champs conservés dans le journal ─────────────────────────────────────────
# (ordre intentionnel pour la lisibilité jury)

JOURNAL_FIELDS = [
    # — Horodatages —
    "journal_ts",         # heure d'écriture dans le journal (UTC)
    "timestamp_recv",     # heure de réception du log
    "timestamp_log",      # heure déclarée dans le log source
    # — Identification —
    "source",             # "ssh" | "apache" | "network"
    "ip",                 # IP source
    "user",               # utilisateur SSH
    # — Données brutes HTTP —
    "method", "path", "status", "bytes", "user_agent",
    # — Données brutes SSH —
    "event",
    # — Détection —
    "prediction",         # "legit" | "attack" | "scan" | "anomaly"
    "detector",           # module ayant produit la détection
    "rule_triggered",     # règle SSH déclenchée
    "detector_score",     # score brut 0-100
    "behavioral_score",   # score comportemental 0-100
    # — Fenêtres temporelles —
    "win_10s", "win_1h", "win_24h",
    "ssh_fail_10s", "ssh_fail_1h", "ssh_fail_24h",
    # — Intégrité (Twist 1) —
    "integrity_ok",       # True = hash SHA256 vérifié
    "log_hash",           # SHA256 du log brut
    "late_seconds",       # délai entre timestamp_log et timestamp_recv
    # — Scoring (Twist 1 + 3) —
    "risk_score",         # score risque final 0-100
    "fp_cost_score",      # coût d'un faux positif 0-100
    "decision_score",     # risk - 0.5*fp_cost → driver de la décision
    "confidence_penalty", # pénalité confiance 0.0-1.0
    "confidence_multiplier",
    # — Décision (Twist 3) —
    "response_level",     # 1=MONITOR 2=ALERT 3=SLOWDOWN 4=BLOCK
    "response_label",     # label lisible
    "decision",           # idem response_label
    "justification",      # texte explicatif lisible jury
    "evidence",           # liste de preuves (strings)
    "whitelisted",        # IP dans la whitelist ?
    "firewall_action",    # "none" | "blocked" | "rate_limited" | ...
    # — Mode dégradé —
    "mode_degrade",       # True si mode dégradé actif
    "is_duplicate",       # True si log doublon (filtré)
]


# ── Interne : filtrage et enrichissement ─────────────────────────────────────

def _filter(record: dict) -> dict:
    """
    Extrait uniquement les champs JOURNAL_FIELDS du record et
    ajoute journal_ts (horodatage UTC de l'écriture).
    """
    out: dict = {}
    for field in JOURNAL_FIELDS:
        val = record.get(field)
        if val is not None:
            out[field] = val
    # Toujours forcer l'horodatage d'écriture
    out["journal_ts"] = datetime.now(timezone.utc).isoformat()
    return out


# ── Écriture ──────────────────────────────────────────────────────────────────

def write(record: dict) -> bool:
    """
    Ajoute une entrée de décision au journal.

    Args:
        record: dict enrichi par le pipeline (scorer → decision → firewall)

    Returns:
        True si l'écriture a réussi, False sinon.
    """
    entry = _filter(record)
    try:
        with open(JOURNAL_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return True
    except Exception as e:
        log.error(f"[JOURNAL] Échec écriture : {e}")
        return False


def write_batch(records: list[dict]) -> int:
    """
    Écrit plusieurs entrées d'un coup.

    Returns:
        Nombre d'entrées effectivement écrites.
    """
    written = 0
    for rec in records:
        if write(rec):
            written += 1
    if written < len(records):
        log.warning(f"[JOURNAL] {len(records)-written} entrées non écrites sur {len(records)}")
    return written


# ── Lecture ───────────────────────────────────────────────────────────────────

def read_all(limit: int = 500) -> list[dict]:
    """
    Retourne les `limit` dernières entrées du journal.
    """
    if not os.path.exists(JOURNAL_PATH):
        return []
    entries = []
    try:
        with open(JOURNAL_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError as e:
                    log.warning(f"[JOURNAL] Ligne JSON invalide ignorée : {e}")
    except Exception as e:
        log.error(f"[JOURNAL] Échec lecture : {e}")
    return entries[-limit:]


def read_alerts(min_level: int = 2) -> list[dict]:
    """
    Retourne uniquement les entrées avec response_level >= min_level.

    Niveaux : 1=MONITOR  2=ALERT  3=SLOWDOWN  4=BLOCK
    """
    return [
        e for e in read_all(limit=2000)
        if e.get("response_level", 1) >= min_level
    ]


def read_blocked() -> list[dict]:
    """Retourne uniquement les décisions BLOCK."""
    return [
        e for e in read_all(limit=2000)
        if e.get("decision") == "BLOCK"
    ]


def read_by_ip(ip: str, limit: int = 500) -> list[dict]:
    """Retourne toutes les entrées pour une IP spécifique."""
    return [
        e for e in read_all(limit=limit)
        if e.get("ip") == ip
    ]


def read_by_source(source: str, limit: int = 500) -> list[dict]:
    """
    Retourne les entrées filtrées par source.
    source : "ssh" | "apache" | "network"
    """
    return [
        e for e in read_all(limit=limit)
        if e.get("source") == source
    ]


# ── Statistiques ──────────────────────────────────────────────────────────────

def stats(limit: int = 5000) -> dict:
    """
    Calcule des statistiques globales sur le journal.

    Retourne :
    {
        "total":          int,
        "by_decision":    {"BLOCK": N, "ALERT": N, ...},
        "by_source":      {"ssh": N, "apache": N, "network": N},
        "top_ips":        [{"ip": str, "count": int}, ...],   # top 10
        "integrity_fail": int,   # logs dont integrity_ok == False
        "mode_degrade_count": int,
        "period_start":   str | None,
        "period_end":     str | None,
    }
    """
    entries = read_all(limit=limit)

    by_decision: dict[str, int] = {}
    by_source:   dict[str, int] = {}
    ip_counter:  dict[str, int] = {}
    integrity_fail    = 0
    mode_degrade_count = 0
    timestamps: list[str] = []

    for e in entries:
        # Décisions
        dec = e.get("decision", "MONITOR")
        by_decision[dec] = by_decision.get(dec, 0) + 1

        # Sources
        src = e.get("source", "unknown")
        by_source[src] = by_source.get(src, 0) + 1

        # IPs
        ip = e.get("ip")
        if ip:
            ip_counter[ip] = ip_counter.get(ip, 0) + 1

        # Intégrité
        if e.get("integrity_ok") is False:
            integrity_fail += 1

        # Mode dégradé
        if e.get("mode_degrade"):
            mode_degrade_count += 1

        # Période
        ts = e.get("journal_ts")
        if ts:
            timestamps.append(ts)

    top_ips = sorted(
        [{"ip": ip, "count": c} for ip, c in ip_counter.items()],
        key=lambda x: x["count"],
        reverse=True
    )[:10]

    return {
        "total":               len(entries),
        "by_decision":         by_decision,
        "by_source":           by_source,
        "top_ips":             top_ips,
        "integrity_fail":      integrity_fail,
        "mode_degrade_count":  mode_degrade_count,
        "period_start":        min(timestamps) if timestamps else None,
        "period_end":          max(timestamps) if timestamps else None,
    }


# ── Export jury ───────────────────────────────────────────────────────────────

def export_jury(
    path: str = "journal_jury.json",
    limit: int = 500,
    min_level: int = 1,
) -> str:
    """
    Exporte un fichier JSON lisible par le jury.
    Contient :
      - un résumé statistique
      - la liste des entrées significatives (format simplifié)
      - un exemple d'entrée annotée

    Args:
        path:      chemin du fichier de sortie
        limit:     nombre max d'entrées
        min_level: niveau minimum à inclure (1=tout, 2=alertes+, 4=blocages seuls)

    Returns:
        Chemin du fichier écrit.
    """
    from src.journal.schema import to_jury_summary, EXAMPLE_ENTRY

    entries = read_alerts(min_level=min_level)[-limit:]
    summary = stats()

    output = {
        "meta": {
            "projet":    "HackVerse IDS — Le système qui se défend seul",
            "equipe":    "Iness · Alex · Henri",
            "hackathon": "HackVerse",
            "export_ts": datetime.now(timezone.utc).isoformat(),
            "journal":   JOURNAL_PATH,
        },
        "resume": {
            "total_evenements":     summary["total"],
            "par_decision":         summary["by_decision"],
            "par_source":           summary["by_source"],
            "top_ips_suspectes":    summary["top_ips"][:5],
            "logs_integrite_echec": summary["integrity_fail"],
            "evenements_degrade":   summary["mode_degrade_count"],
            "periode_debut":        summary["period_start"],
            "periode_fin":          summary["period_end"],
        },
        "format_exemple": EXAMPLE_ENTRY,
        "entrees": [to_jury_summary(e) for e in entries],
    }

    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(output, f, ensure_ascii=False, indent=2)
        log.info(f"[JOURNAL] Export jury → {path} ({len(entries)} entrées)")
        return path
    except Exception as e:
        log.error(f"[JOURNAL] Échec export jury : {e}")
        raise


# ── Rotation ──────────────────────────────────────────────────────────────────

def rotate(max_lines: int = JOURNAL_MAX_LINES) -> int:
    """
    Garde uniquement les `max_lines` dernières entrées du journal.
    Appelé automatiquement si le fichier dépasse JOURNAL_MAX_LINES.

    Returns:
        Nombre de lignes supprimées.
    """
    if not os.path.exists(JOURNAL_PATH):
        return 0

    entries = read_all(limit=max_lines * 2)
    if len(entries) <= max_lines:
        return 0

    kept    = entries[-max_lines:]
    removed = len(entries) - len(kept)

    try:
        with open(JOURNAL_PATH, "w", encoding="utf-8") as f:
            for entry in kept:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        log.info(f"[JOURNAL] Rotation : {removed} lignes supprimées, {len(kept)} conservées")
        return removed
    except Exception as e:
        log.error(f"[JOURNAL] Échec rotation : {e}")
        return 0


def _auto_rotate_if_needed():
    """Vérifie et déclenche une rotation si le journal est trop grand."""
    try:
        if os.path.exists(JOURNAL_PATH):
            # Compte rapide des lignes
            with open(JOURNAL_PATH, "r", encoding="utf-8") as f:
                count = sum(1 for _ in f)
            if count > JOURNAL_MAX_LINES:
                rotate(JOURNAL_MAX_LINES)
    except Exception:
        pass
