"""
benchmark.py — Rapport de performance des modèles ML et explication des scores
Exécuter : .venv/bin/python benchmark.py
"""
import sys, os, json
sys.path.insert(0, ".")

import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, average_precision_score
)
from sklearn.model_selection import cross_val_score, StratifiedKFold
import joblib

from src.collector.normalizer import load_apache, load_network, load_ssh

SEP = "─" * 70

# ══════════════════════════════════════════════════════════════════════════════
# 1. MODÈLE HTTP — Random Forest
# ══════════════════════════════════════════════════════════════════════════════

MALICIOUS_AGENTS = ["nikto", "sqlmap", "masscan", "nmap", "zgrab",
                    "python-requests", "curl", "go-http-client"]
SENSITIVE_PATHS  = [".env", ".git", "phpmyadmin", "backup.sql",
                    "config.php", "wp-admin", "passwd"]
SQLI_PATTERNS    = ["drop table", "select ", "union ", "' or ", "'--",
                    "1=1", "sleep(", "benchmark("]
TRAVERSAL        = ["../", "..\\", "/etc/", "/proc/"]
METHOD_MAP       = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3,
                    "HEAD": 4, "OPTIONS": 5, "PATCH": 6}
LABEL_MAP        = {"legit": 0, "scan": 1, "attack": 2}
FEATURE_NAMES    = ["ip_external", "method", "path_traversal",
                    "path_sqli", "path_sensitive", "agent_malicious",
                    "status_code", "bytes"]


def extract_http_features(records):
    rows, labels = [], []
    for r in records:
        path  = str(r.get("path",       "")).lower()
        agent = str(r.get("user_agent", "")).lower()
        try:
            status = int(r.get("status", 0))
        except:
            status = 0
        feat = [
            1 if r.get("ip_is_external") else 0,
            METHOD_MAP.get(r.get("method", "GET"), 0),
            1 if any(t in path  for t in TRAVERSAL)       else 0,
            1 if any(s in path  for s in SQLI_PATTERNS)   else 0,
            1 if any(p in path  for p in SENSITIVE_PATHS) else 0,
            1 if any(b in agent for b in MALICIOUS_AGENTS) else 0,
            status,
            int(r.get("bytes", 0)),
        ]
        rows.append(feat)
        labels.append(LABEL_MAP.get(r.get("label", "legit"), 0))
    return rows, labels


def run_http_benchmark():
    print(f"\n{'═'*70}")
    print("  MODÈLE 1 : Random Forest — Détection HTTP (Apache logs)")
    print(f"{'═'*70}")

    records = load_apache("data/sample_logs/apache_access_1.csv")
    X, y    = extract_http_features(records)
    X       = np.array(X)
    y       = np.array(y)

    bundle = joblib.load("src/models/http_model.pkl")
    clf    = bundle["model"]

    print(f"\n📊 Dataset : {len(records):,} lignes")
    unique, counts = np.unique(y, return_counts=True)
    label_names = {0: "legit", 1: "scan", 2: "attack"}
    print("   Distribution des classes :")
    for u, c in zip(unique, counts):
        pct = 100 * c / len(y)
        print(f"     {label_names[u]:8s} : {c:6,} ({pct:.1f}%)")

    # --- Validation croisée (5-fold) ---
    print(f"\n{SEP}")
    print("  Cross-Validation 5-fold (Stratifiée)")
    print(SEP)
    cv    = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    accs  = cross_val_score(clf, X, y, cv=cv, scoring="accuracy")
    f1s   = cross_val_score(clf, X, y, cv=cv, scoring="f1_weighted")
    print(f"  Accuracy  : {accs.mean():.4f} ± {accs.std():.4f}")
    print(f"  F1 (wtd)  : {f1s.mean():.4f} ± {f1s.std():.4f}")

    # --- Rapport complet sur tout le dataset ---
    y_pred = clf.predict(X)
    print(f"\n{SEP}")
    print("  Rapport de classification (dataset complet)")
    print(SEP)
    print(classification_report(y, y_pred,
          target_names=["legit", "scan", "attack"]))

    # --- Matrice de confusion ---
    cm = confusion_matrix(y, y_pred)
    print(f"\n{SEP}")
    print("  Matrice de confusion (lignes=réel, colonnes=prédit)")
    print(f"  {'':10} {'legit':>8} {'scan':>8} {'attack':>8}")
    for i, row in enumerate(cm):
        print(f"  {label_names[i]:10} {row[0]:>8} {row[1]:>8} {row[2]:>8}")

    # --- Feature importances ---
    imp = clf.feature_importances_
    print(f"\n{SEP}")
    print("  Importance des features (quel signal pèse le plus ?)")
    print(SEP)
    for name, val in sorted(zip(FEATURE_NAMES, imp), key=lambda x: -x[1]):
        bar = "█" * int(val * 40)
        print(f"  {name:25s} {val:.4f}  {bar}")


# ══════════════════════════════════════════════════════════════════════════════
# 2. MODÈLE NETWORK — Isolation Forest
# ══════════════════════════════════════════════════════════════════════════════

SENSITIVE_PORTS = {22, 3306, 5432, 6379, 27017, 1433, 23, 21}
PROTOCOL_MAP    = {"TCP": 0, "UDP": 1, "ICMP": 2}
NET_FEATURES    = ["ip_external", "port_sensitive", "protocol",
                   "bytes_sent", "packets", "duration_ms",
                   "flag_syn_only", "flag_multi_syn", "dst_port"]


def extract_net_features(records):
    rows = []
    for r in records:
        flags = str(r.get("flags", ""))
        rows.append([
            1 if r.get("ip_is_external") else 0,
            1 if r.get("port_sensitive")  else 0,
            PROTOCOL_MAP.get(r.get("protocol", "TCP"), 0),
            int(r.get("bytes_sent",  0)),
            int(r.get("packets",     0)),
            int(r.get("duration_ms", 0)),
            1 if flags == "SYN"       else 0,
            1 if "SYN,SYN" in flags   else 0,
            int(r.get("dst_port",    0)),
        ])
    return np.array(rows)


def run_network_benchmark():
    print(f"\n\n{'═'*70}")
    print("  MODÈLE 2 : Isolation Forest — Détection Anomalies Réseau")
    print(f"{'═'*70}")

    records = load_network("data/sample_logs/network_flows_1.csv")
    X_raw   = extract_net_features(records)

    bundle  = joblib.load("src/models/network_model.pkl")
    clf     = bundle["model"]
    scaler  = bundle["scaler"]

    X_scaled = scaler.fit_transform(X_raw)

    print(f"\n📊 Dataset : {len(records):,} flows réseau")

    preds      = clf.predict(X_scaled)
    raw_scores = clf.decision_function(X_scaled)
    n_anom     = (preds == -1).sum()
    n_norm     = (preds ==  1).sum()

    print(f"\n{SEP}")
    print("  Résultats de détection")
    print(SEP)
    print(f"  Normal   : {n_norm:,} flows ({100*n_norm/len(records):.1f}%)")
    print(f"  Anomalie : {n_anom:,} flows ({100*n_anom/len(records):.1f}%)")

    # Distribution des scores bruts
    print(f"\n{SEP}")
    print("  Distribution des scores bruts (decision_function)")
    print(f"  (Score négatif = plus anormal)")
    print(SEP)
    print(f"  Min    : {raw_scores.min():.4f}")
    print(f"  Max    : {raw_scores.max():.4f}")
    print(f"  Moyen  : {raw_scores.mean():.4f}")
    print(f"  Médian : {np.median(raw_scores):.4f}")
    print(f"  Seuil  : 0.0 (en dessous = anomalie)")

    # Analyse des anomalies
    anom_records = [records[i] for i, p in enumerate(preds) if p == -1]
    ext_anom = sum(1 for r in anom_records if r.get("ip_is_external"))
    sens_anom = sum(1 for r in anom_records if r.get("port_sensitive"))
    syn_anom  = sum(1 for r in anom_records if r.get("flag_syn_only"))

    print(f"\n{SEP}")
    print("  Profil des anomalies détectées")
    print(SEP)
    print(f"  IPs externes          : {ext_anom:4d} / {n_anom} ({100*ext_anom/max(n_anom,1):.0f}%)")
    print(f"  Ports sensibles       : {sens_anom:4d} / {n_anom} ({100*sens_anom/max(n_anom,1):.0f}%)")
    print(f"  Scan SYN              : {syn_anom:4d} / {n_anom} ({100*syn_anom/max(n_anom,1):.0f}%)")

    # Top ports dans les anomalies
    port_counts = {}
    for r in anom_records:
        p = r.get("dst_port", 0)
        port_counts[p] = port_counts.get(p, 0) + 1
    print(f"\n  Top 5 ports dans les anomalies :")
    for port, cnt in sorted(port_counts.items(), key=lambda x: -x[1])[:5]:
        label = {22:"SSH", 3306:"MySQL", 5432:"PostgreSQL",
                 6379:"Redis", 27017:"MongoDB"}.get(port, "")
        print(f"    Port {port:5d} ({label:12s}) : {cnt} flows")


# ══════════════════════════════════════════════════════════════════════════════
# 3. EXPLICATION DU CALCUL DES SCORES
# ══════════════════════════════════════════════════════════════════════════════

def explain_scores():
    print(f"\n\n{'═'*70}")
    print("  EXPLICATION DU CALCUL DES SCORES")
    print(f"{'═'*70}")

    print("""
┌─────────────────────────────────────────────────────────────────────┐
│  COUCHE 1 — detector_score  (0-100, par source)                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  HTTP (Random Forest) :                                             │
│    proba_scan × 60 + proba_attack × 100                             │
│    → pondère les scans moins lourdement que les attaques directes   │
│                                                                     │
│  SSH (Règles) :                                                     │
│    10s : ≥ 3 échecs  → score 95   (brute-force immédiat)            │
│    1h  : ≥ 15 échecs → score 80   (campagne lente)                  │
│    24h : ≥ 40 échecs → score 65   (attaque très silencieuse)        │
│    Partiel : proportionnel au taux d'échec observé                  │
│                                                                     │
│  NETWORK (Isolation Forest) :                                       │
│    raw_score = clf.decision_function(x)  [valeur négative = anomal] │
│    normalized = max(0, min(1, (-raw + 0.1) / 0.6)) × 100           │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  COUCHE 2 — behavioral_score  (0-100, par IP)                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  SSH  = win_10s/3×60 + win_1h/15×25 + win_24h/40×15               │
│  HTTP = win_10s/20×40 + win_1h/100×35 + win_24h/500×25             │
│  + profil : taux d'échec, diversité agents/ports, agent malveillant │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  COUCHE 3 — risk_score  (0-100, global)                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  raw_risk = detector_score × 0.70 + behavioral_score × 0.30        │
│  confidence_mult = 1.0 - confidence_penalty   (Twist 1)            │
│  risk_score = raw_risk × confidence_mult                            │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  COUCHE 3 — confidence_penalty  (0.0-1.0)                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  + 0.40 si hash SHA-256 invalide (log falsifié)                     │
│  + jusqu'à 0.35 si log trop tardif (linéaire sur 10×seuil)          │
│  + jusqu'à 0.25 si champs manquants (0.05 par champ absent)         │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  COUCHE 3 — fp_cost_score  (0-100)  Twist 3                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  + 80 si IP whitelistée (jamais bloquer)                            │
│  + 55 si IP interne (personnel humanitaire)                         │
│  + 20 si win_24h > 100 (utilisateur très actif)                     │
│  + 25 si dernière action = "Accepted publickey"                     │
│  + 15 si confidence_score < 50 (log peu fiable)                     │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  COUCHE 4 — decision_score  →  réponse graduée                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  decision_score = risk_score - fp_cost × 0.5                        │
│                                                                     │
│  < 50   → NIVEAU 1 : SURVEILLER  (log + observation)               │
│  ≥ 50   → NIVEAU 2 : ALERTER     (notification humaine)            │
│  ≥ 65   → NIVEAU 3 : RALENTIR    (rate limiting)                   │
│  ≥ 75   → NIVEAU 4 : BLOQUER     (iptables DROP)                   │
│                                                                     │
│  Exception : IP whitelistée → maximum NIVEAU 2, jamais BLOCK        │
└─────────────────────────────────────────────────────────────────────┘
""")


# ══════════════════════════════════════════════════════════════════════════════
# 4. EXEMPLE CONCRET
# ══════════════════════════════════════════════════════════════════════════════

def show_example():
    print(f"{'═'*70}")
    print("  EXEMPLE CONCRET — IP 185.147.82.139 (attaquant externe)")
    print(f"{'═'*70}")

    # Simuler un record complet
    from src.scorer.risk_scorer import score as risk_score
    from src.scorer.cost_scorer import compute_fp_cost
    from src.responder.decision import decide

    record = {
        "ip":               "185.147.82.139",
        "source":           "apache",
        "ip_is_external":   True,
        "detector_score":   92.0,    # Random Forest → attack
        "behavioral_score": 78.0,    # Beaucoup d'événements en peu de temps
        "confidence_penalty": 0.0,   # Log frais, hash OK
        "win_24h":          5,
        "user":             "",
        "event":            "",
        "agent_malicious":  True,
        "path_sqli":        True,
        "path_traversal":   False,
        "path_sensitive":   False,
        "path":             "/api/users?id=1 OR 1=1",
        "user_agent":       "sqlmap/1.6",
        "rule_triggered":   None,
        "win_10s":          0, "win_1h": 0,
        "late_seconds":     0, "integrity_ok": True,
        "whitelisted":      False,
    }

    fp_cost = compute_fp_cost(record)
    scored  = risk_score(record)
    decided = decide(scored)

    print(f"""
  Input :
    detector_score    = {record['detector_score']}  (RF : classe "attack" à 92%)
    behavioral_score  = {record['behavioral_score']}  (nombreux events en peu de temps)
    confidence_penalty= {record['confidence_penalty']}    (log frais et intact)

  Calcul :
    raw_risk          = {record['detector_score']}×0.70 + {record['behavioral_score']}×0.30 = {record['detector_score']*0.70 + record['behavioral_score']*0.30:.1f}
    confidence_mult   = 1.0 - {record['confidence_penalty']} = {1.0 - record['confidence_penalty']}
    risk_score        = {(record['detector_score']*0.70 + record['behavioral_score']*0.30) * (1.0 - record['confidence_penalty']):.1f}

    fp_cost_score     = {fp_cost}  (IP externe inconnue → coût minimal)
    decision_score    = risk_score - fp_cost×0.5 = {scored['risk_score']:.1f} - {fp_cost}×0.5 = {scored['decision_score']:.1f}

  Résultat :
    ➜  DÉCISION : {decided['decision']}  (niveau {decided['response_level']})
    ➜  {decided['justification']}
""")

    print(f"{'═'*70}")
    print("  EXEMPLE — IP 10.0.0.50 (personnel interne suspect)")
    print(f"{'═'*70}")

    record2 = {**record,
        "ip": "10.0.0.50", "ip_is_external": False,
        "detector_score": 65.0, "behavioral_score": 40.0,
        "whitelisted": False,
    }
    fp2     = compute_fp_cost(record2)
    scored2 = risk_score(record2)
    decided2 = decide(scored2)

    print(f"""
  Input :
    detector_score    = {record2['detector_score']}  (SQL injection détectée)
    behavioral_score  = {record2['behavioral_score']}
    ip_is_external    = False  (IP interne 10.0.x.x)

  Calcul :
    raw_risk          = {record2['detector_score']}×0.70 + {record2['behavioral_score']}×0.30 = {record2['detector_score']*0.70 + record2['behavioral_score']*0.30:.1f}
    risk_score        = {scored2['risk_score']:.1f}
    fp_cost_score     = {fp2}   (IP INTERNE → coût élevé !)
    decision_score    = {scored2['risk_score']:.1f} - {fp2}×0.5 = {scored2['decision_score']:.1f}

  Résultat :
    ➜  DÉCISION : {decided2['decision']}  (niveau {decided2['response_level']})
    ➜  {decided2['justification']}
    ✅ TWIST 3 : personnel interne non bloqué automatiquement.
""")


if __name__ == "__main__":
    run_http_benchmark()
    run_network_benchmark()
    explain_scores()
    show_example()
    print("\n✅ Benchmark terminé.\n")
