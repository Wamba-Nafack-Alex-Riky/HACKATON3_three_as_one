"""
train_http.py
Trains a Random Forest classifier on apache_access_1.csv.
Saves the trained model to src/models/http_model.pkl
Run once: python -m src.models.train_http
"""

import os
import sys
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder

# Allow running from project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from src.collector.normalizer import load_apache

DATA_PATH  = "data/sample_logs/apache_access_1.csv"
MODEL_PATH = "src/models/http_model.pkl"

MALICIOUS_AGENTS = ["nikto", "sqlmap", "masscan", "nmap", "zgrab",
                    "python-requests", "curl", "go-http-client"]
SENSITIVE_PATHS  = [".env", ".git", "phpmyadmin", "backup.sql",
                    "config.php", "wp-admin", "passwd"]
SQLI_PATTERNS    = ["drop table", "select ", "union ", "' or ", "'--",
                    "1=1", "sleep(", "benchmark("]
TRAVERSAL        = ["../", "..\\", "/etc/", "/proc/"]

METHOD_MAP   = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3, "HEAD": 4,
                "OPTIONS": 5, "PATCH": 6}
LABEL_MAP    = {"legit": 0, "scan": 1, "attack": 2}


def extract_features(records: list[dict]) -> tuple:
    rows, labels = [], []
    for r in records:
        path   = str(r.get("path",       "")).lower()
        agent  = str(r.get("user_agent", "")).lower()
        status = int(r.get("status",     0))
        try:
            status = int(status)
        except (ValueError, TypeError):
            status = 0

        feat = [
            1 if r.get("ip_is_external")  else 0,
            METHOD_MAP.get(r.get("method", "GET"), 0),
            1 if any(t in path  for t in TRAVERSAL)        else 0,
            1 if any(s in path  for s in SQLI_PATTERNS)    else 0,
            1 if any(p in path  for p in SENSITIVE_PATHS)  else 0,
            1 if any(b in agent for b in MALICIOUS_AGENTS) else 0,
            status,
            int(r.get("bytes", 0)),
        ]
        rows.append(feat)
        labels.append(LABEL_MAP.get(r.get("label", "legit"), 0))

    return rows, labels


def train():
    print("[HTTP] Loading Apache data …")
    records = load_apache(DATA_PATH)
    print(f"[HTTP] {len(records)} records loaded.")

    X, y = extract_features(records)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        class_weight="balanced",   # handles class imbalance (few attacks)
        random_state=42,
        n_jobs=-1,
    )
    print("[HTTP] Training Random Forest …")
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print("\n[HTTP] Classification report:")
    print(classification_report(
        y_test, y_pred,
        target_names=["legit", "scan", "attack"]
    ))

    feature_names = ["ip_external", "method", "path_traversal",
                     "path_sqli", "path_sensitive", "agent_malicious",
                     "status_code", "bytes"]
    importances = clf.feature_importances_
    print("\n[HTTP] Feature importances:")
    for name, imp in sorted(zip(feature_names, importances),
                            key=lambda x: -x[1]):
        print(f"  {name:25s}: {imp:.4f}")

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump({"model": clf, "label_map": LABEL_MAP,
                 "method_map": METHOD_MAP}, MODEL_PATH)
    print(f"\n[HTTP] Model saved → {MODEL_PATH}")


if __name__ == "__main__":
    train()
