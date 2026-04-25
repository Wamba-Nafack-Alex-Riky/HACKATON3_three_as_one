"""
scorer/confidence.py
Score de confiance du log source (Twist 1).
Pénalise les logs tardifs, incomplets ou dont l'intégrité est compromise.
"""


def compute_confidence_penalty(record: dict) -> float:
    """
    Retourne une pénalité de confiance entre 0.0 (aucune) et 1.0 (max).
    Cette valeur réduit le risk_score via : risk * (1 - penalty).

    Critères :
    - Log tardif (late_seconds > seuil)  → pénalité configurable (défaut 0.30)
    - Intégrité corrompue               → pénalité forte (0.50)
    - Champs obligatoires manquants      → pénalité modérée (0.20)
    """
    penalty = 0.0

    # 1. Intégrité log (Twist 1 — hachage SHA256)
    if record.get("integrity_ok") is False:
        penalty += 0.50

    # 2. Log tardif
    late = float(record.get("late_seconds", 0))
    late_threshold = float(record.get("_late_threshold", 60))
    late_penalty   = float(record.get("_late_penalty",   0.30))
    if late > late_threshold:
        penalty += late_penalty

    # 3. Champs manquants
    critical_fields = ["ip", "source", "timestamp_log"]
    missing = sum(1 for f in critical_fields if not record.get(f))
    if missing > 0:
        penalty += 0.10 * missing

    return min(penalty, 1.0)


def enrich_with_confidence(record: dict, config: dict = None) -> dict:
    """
    Enrichit le record avec confidence_penalty calculée.
    Peut recevoir le bloc 'degraded' de config.yaml pour les seuils.
    """
    if config is None:
        config = {}
    deg = config.get("degraded", {})

    record = {
        **record,
        "_late_threshold": deg.get("late_log_threshold_seconds", 60),
        "_late_penalty":   deg.get("confidence_penalty_late",    0.30),
    }
    penalty = compute_confidence_penalty(record)

    return {
        **record,
        "confidence_penalty": penalty,
    }
