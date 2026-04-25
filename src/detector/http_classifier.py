"""
http_classifier.py
Runs the trained Random Forest on Apache log records.
Returns prediction + confidence per record.
"""

import os
import joblib

MODEL_PATH = "src/models/http_model.pkl"

MALICIOUS_AGENTS = ["nikto", "sqlmap", "masscan", "nmap", "zgrab",
                    "python-requests", "curl", "go-http-client"]
SENSITIVE_PATHS  = [".env", ".git", "phpmyadmin", "backup.sql",
                    "config.php", "wp-admin", "passwd"]
SQLI_PATTERNS    = ["drop table", "select ", "union ", "' or ", "'--",
                    "1=1", "sleep(", "benchmark("]
TRAVERSAL        = ["../", "..\\", "/etc/", "/proc/"]
METHOD_MAP       = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3,
                    "HEAD": 4, "OPTIONS": 5, "PATCH": 6}
LABEL_NAMES      = {0: "legit", 1: "scan", 2: "attack"}

_bundle = None


def _load_model():
    global _bundle
    if _bundle is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Model not found at {MODEL_PATH}. "
                "Run: python -m src.models.train_http"
            )
        _bundle = joblib.load(MODEL_PATH)
    return _bundle


def _to_features(record: dict) -> list:
    path  = str(record.get("path",       "")).lower()
    agent = str(record.get("user_agent", "")).lower()
    try:
        status = int(record.get("status", 0))
    except (ValueError, TypeError):
        status = 0

    return [
        1 if record.get("ip_is_external")                           else 0,
        METHOD_MAP.get(record.get("method", "GET"), 0),
        1 if any(t in path  for t in TRAVERSAL)                     else 0,
        1 if any(s in path  for s in SQLI_PATTERNS)                 else 0,
        1 if any(p in path  for p in SENSITIVE_PATHS)               else 0,
        1 if any(b in agent for b in MALICIOUS_AGENTS)              else 0,
        status,
        int(record.get("bytes", 0)),
    ]


def classify(record: dict) -> dict:
    """
    Returns the record enriched with:
      - prediction  : 'legit' | 'scan' | 'attack'
      - proba_legit / proba_scan / proba_attack : class probabilities
      - detector_score : 0-100 risk score from this detector
    """
    bundle = _load_model()
    clf    = bundle["model"]

    feat   = [_to_features(record)]
    pred   = clf.predict(feat)[0]
    proba  = clf.predict_proba(feat)[0]   # [p_legit, p_scan, p_attack]

    label = LABEL_NAMES.get(pred, "legit")

    # Risk score: weighted sum of non-legit probabilities
    detector_score = round((proba[1] * 60 + proba[2] * 100), 1)
    detector_score = min(detector_score, 100.0)

    return {
        **record,
        "prediction":     label,
        "proba_legit":    round(float(proba[0]), 4),
        "proba_scan":     round(float(proba[1]), 4),
        "proba_attack":   round(float(proba[2]), 4),
        "detector_score": detector_score,
        "detector":       "random_forest_http",
    }


def classify_batch(records: list[dict]) -> list[dict]:
    return [classify(r) for r in records]
