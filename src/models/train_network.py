"""
train_network.py
Trains an Isolation Forest on network_flows_1.csv (no labels → anomaly detection).
Saves the trained model to src/models/network_model.pkl
Run once: python -m src.models.train_network
"""

import os
import sys
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from src.collector.normalizer import load_network

DATA_PATH  = "data/sample_logs/network_flows_1.csv"
MODEL_PATH = "src/models/network_model.pkl"

SENSITIVE_PORTS = {22, 3306, 5432, 6379, 27017, 1433, 23, 21}
PROTOCOL_MAP    = {"TCP": 0, "UDP": 1, "ICMP": 2}


def extract_features(records: list[dict]) -> list[list]:
    rows = []
    for r in records:
        flags = str(r.get("flags", ""))
        feat  = [
            1 if r.get("ip_is_external") else 0,
            1 if r.get("port_sensitive")  else 0,
            PROTOCOL_MAP.get(r.get("protocol", "TCP"), 0),
            int(r.get("bytes_sent",  0)),
            int(r.get("packets",     0)),
            int(r.get("duration_ms", 0)),
            1 if flags == "SYN"         else 0,   # port scan indicator
            1 if "SYN,SYN" in flags     else 0,   # aggressive scan
            int(r.get("dst_port",    0)),
        ]
        rows.append(feat)
    return rows


def train():
    print("[NET] Loading network flow data …")
    records = load_network(DATA_PATH)
    print(f"[NET] {len(records)} records loaded.")

    X = extract_features(records)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # contamination = estimated fraction of anomalies in the dataset
    # External IPs with sensitive ports ≈ 15 % of our data
    clf = IsolationForest(
        n_estimators=100,
        contamination=0.15,
        random_state=42,
        n_jobs=-1,
    )
    print("[NET] Training Isolation Forest …")
    clf.fit(X_scaled)

    preds = clf.predict(X_scaled)
    n_anomalies = (preds == -1).sum()
    print(f"[NET] Anomalies detected in training data: {n_anomalies} / {len(records)}"
          f" ({100*n_anomalies/len(records):.1f}%)")

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump({"model": clf, "scaler": scaler,
                 "protocol_map": PROTOCOL_MAP}, MODEL_PATH)
    print(f"[NET] Model saved → {MODEL_PATH}")


if __name__ == "__main__":
    train()
