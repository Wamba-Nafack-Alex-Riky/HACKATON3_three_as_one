"""
behavior.py  —  Twist 2
Profilage comportemental par IP.

Pour chaque IP, on construit un profil "normal" à partir des premières
observations et on mesure l'écart de chaque nouvel événement par rapport
à ce profil. Plus l'écart est grand, plus le score comportemental est élevé.

Ce module complète time_windows.py (fréquence) en ajoutant une dimension
qualitative : diversité des ports, des méthodes HTTP, des user-agents, etc.
"""

from collections import defaultdict
from typing import Optional


class BehaviorProfiler:
    """
    Maintient un profil par IP et calcule un score de déviation comportementale.

    Profil d'une IP :
      - ports_seen       : ensemble des ports de destination contactés
      - methods_seen     : ensemble des méthodes HTTP utilisées
      - agents_seen      : ensemble des user-agents vus
      - paths_seen       : ensemble des chemins HTTP visités
      - events_seen      : ensemble des types d'événements SSH
      - total_events     : nombre total d'événements enregistrés
      - external_count   : nombre d'événements depuis une IP externe
      - fail_count       : nombre d'échecs (SSH Failed password, HTTP 4xx/5xx)
    """

    def __init__(self):
        # ip → profil (dict)
        self._profiles: dict[str, dict] = defaultdict(lambda: {
            "ports_seen":     set(),
            "methods_seen":   set(),
            "agents_seen":    set(),
            "paths_seen":     set(),
            "events_seen":    set(),
            "total_events":   0,
            "external_count": 0,
            "fail_count":     0,
            "new_port_count": 0,   # ports jamais vus par cette IP
        })

    def _get_profile(self, ip: str) -> dict:
        return self._profiles[ip]

    def update(self, record: dict) -> dict:
        """
        Met à jour le profil de l'IP et retourne le record enrichi avec
        un score comportemental basé sur la déviation par rapport au profil.
        """
        ip      = record.get("ip", "unknown")
        source  = record.get("source", "apache")
        profile = self._get_profile(ip)

        profile["total_events"] += 1

        if record.get("ip_is_external"):
            profile["external_count"] += 1

        # --- SSH ---
        if source == "ssh":
            event = record.get("event", "")
            profile["events_seen"].add(event)
            if event == "Failed password":
                profile["fail_count"] += 1

        # --- Apache HTTP ---
        elif source == "apache":
            method = record.get("method", "")
            agent  = record.get("user_agent", "")
            path   = record.get("path", "")
            status = int(record.get("status", 200))

            profile["methods_seen"].add(method)
            if agent:
                profile["agents_seen"].add(agent[:50])
            if path:
                profile["paths_seen"].add(path[:80])
            if status >= 400:
                profile["fail_count"] += 1

        # --- Network flows ---
        elif source == "network":
            dst_port = record.get("dst_port", 0)
            if dst_port not in profile["ports_seen"]:
                profile["new_port_count"] += 1
            profile["ports_seen"].add(dst_port)

        behavioral_score = self._compute_score(ip, source, record)

        return {
            **record,
            "behavioral_score":   behavioral_score,
            "profile_total":      profile["total_events"],
            "profile_fail_count": profile["fail_count"],
            "profile_ports":      len(profile["ports_seen"]),
        }

    def _compute_score(self, ip: str, source: str, record: dict) -> float:
        """
        Score 0-100 basé sur les signaux comportementaux.
        Chaque composante est bornée et pondérée.
        """
        profile = self._get_profile(ip)
        score   = 0.0

        # Composante 1 — Taux d'échec (SSH / HTTP 4xx-5xx)
        total  = max(profile["total_events"], 1)
        fail_r = profile["fail_count"] / total
        score += min(fail_r, 1.0) * 40.0

        # Composante 2 — IP externe : facteur aggravant
        if record.get("ip_is_external"):
            score += 10.0

        # Composante 3 — Network : diversité anormale des ports
        if source == "network":
            new_port_ratio = profile["new_port_count"] / total
            score += min(new_port_ratio * 3, 1.0) * 25.0
            # Accès à des ports très sensibles
            if record.get("port_sensitive"):
                score += 15.0

        # Composante 4 — HTTP : diversité anormale des user-agents
        if source == "apache":
            agent_diversity = len(profile["agents_seen"]) / max(total, 1)
            if agent_diversity > 0.5:
                score += 10.0
            # Accès à des chemins sensibles
            if record.get("path_sensitive") or record.get("path_sqli") or record.get("path_traversal"):
                score += 15.0

        # Composante 5 — Indicateurs malveillants directs
        if record.get("agent_malicious"):
            score += 20.0

        return round(min(score, 100.0), 1)

    def get_profile_summary(self, ip: str) -> dict:
        """Retourne un résumé lisible du profil pour le journal/jury."""
        p = self._profiles.get(ip, {})
        return {
            "ip":           ip,
            "total_events": p.get("total_events", 0),
            "fail_count":   p.get("fail_count", 0),
            "ports_count":  len(p.get("ports_seen", set())),
            "agents_count": len(p.get("agents_seen", set())),
            "paths_count":  len(p.get("paths_seen", set())),
        }


# ── Module-level singleton ─────────────────────────────────────────────────────
_profiler = BehaviorProfiler()


def profile_and_score(record: dict) -> dict:
    """
    API publique : met à jour le profil et retourne le record enrichi avec
    behavioral_score, profile_total, profile_fail_count, profile_ports.
    """
    return _profiler.update(record)


def profile_batch(records: list[dict]) -> list[dict]:
    """Traite les records dans l'ordre chronologique."""
    sorted_recs = sorted(
        records,
        key=lambda r: str(r.get("timestamp_log", ""))
    )
    return [profile_and_score(r) for r in sorted_recs]


def get_profile_summary(ip: str) -> dict:
    return _profiler.get_profile_summary(ip)
