"""
network_anomaly.py
Runs the trained Isolation Forest on network flow records.
Returns anomaly score per record.
"""

import os
import joblib

MODEL_PATH   = "src/models/network_model.pkl"
PROTOCOL_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2}

_bundle = None


def _load_model():
    global _bundle
    if _bundle is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Model not found at {MODEL_PATH}. "
                "Run: python -m src.models.train_network"
            )
        _bundle = joblib.load(MODEL_PATH)
    return _bundle


def _to_features(record: dict) -> list:
    flags = str(record.get("flags", ""))
    return [
        1 if record.get("ip_is_external") else 0,
        1 if record.get("port_sensitive")  else 0,
        PROTOCOL_MAP.get(record.get("protocol", "TCP"), 0),
        int(record.get("bytes_sent",  0)),
        int(record.get("packets",     0)),
        int(record.get("duration_ms", 0)),
        1 if flags == "SYN"          else 0,
        1 if "SYN,SYN" in flags      else 0,
        int(record.get("dst_port",   0)),
    ]


def classify(record: dict) -> dict:
    """
    Returns the record enriched with:
      - prediction     : 'anomaly' | 'normal'
      - anomaly_score  : 0-100 (higher = more anomalous)
      - detector_score : same, for unified scoring pipeline
      - iso_raw_score  : raw Isolation Forest score (negative = anomaly)
    """
    bundle  = _load_model()
    clf     = bundle["model"]
    scaler  = bundle["scaler"]

    feat        = scaler.transform([_to_features(record)])
    pred        = clf.predict(feat)[0]          # 1=normal, -1=anomaly
    raw_score   = clf.decision_function(feat)[0]  # negative = more anomalous

    # Convert raw score to 0-100 where 100 = most anomalous
    # Typical range of decision_function: [-0.5, 0.5]
    normalized  = max(0.0, min(1.0, (-raw_score + 0.1) / 0.6))
    detector_score = round(normalized * 100, 1)

    prediction = "anomaly" if pred == -1 else "normal"

    return {
        **record,
        "prediction":     prediction,
        "iso_raw_score":  round(float(raw_score), 4),
        "detector_score": detector_score,
        "detector":       "isolation_forest_network",
    }


def classify_batch(records: list[dict]) -> list[dict]:
    return [classify(r) for r in records]
