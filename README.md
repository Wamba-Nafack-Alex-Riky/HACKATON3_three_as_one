
# 🛡️ Le Système qui se Défend Seul — HackVerse

> Projet réalisé dans le cadre du Hackathon HackVerse
> Équipe : Iness · Alex · Henri
> Thème : Sujet 06 — Le système qui se défend seul

---

## 📌 Contexte du projet

Une ONG humanitaire en Afrique centrale gère des données ultra-sensibles :
identités de réfugiés et localisations de personnel en zone de conflit.
Son budget sécurité est nul. Elle subit régulièrement des cyberattaques :
scans de ports, brute force SSH, injections SQL sur son portail web.

**Notre mission :** construire un système de détection et de réponse
automatique aux intrusions (IDS/IPS), léger, sans agent commercial,
déployable sur un VPS à 5€/mois.

---

## 🎯 Problématique

> Comment construire un système capable de détecter et bloquer
> automatiquement des intrusions, tout en restant fiable et défendable
> même quand les conditions d'exploitation ne sont pas idéales —
> et sans jamais bloquer ce qu'il est chargé de protéger ?

---

## 🧩 Découpage en sous-problèmes

| # | Sous-problème | Objectif |
|---|---|---|
| 1 | Collecte des données | Lire et normaliser les logs SSH, Apache/nginx, network flows |
| 2 | Détection des attaques | Modèles entraînés + règles heuristiques par source |
| 3 | Scoring de menace | Évaluer la gravité de chaque alerte |
| 4 | Réponse graduée | Surveiller / Alerter / Ralentir / Bloquer |
| 5 | Mode dégradé | Maintenir la cohérence avec des données imparfaites |
| 6 | Traçabilité | Produire des états défendables et auditables |
| 7 | Gestion des faux positifs | Ne jamais bloquer un acteur légitime |

---

## 🗂️ Données disponibles

| Fichier | Lignes | Labels | Attaques présentes |
|---|---|---|---|
| `apache_access_1.csv` | 14 340 | `legit` / `attack` / `scan` | SQLi, path traversal, outils de scan |
| `auth_ssh_1.csv` | 1 735 | `Accepted publickey` / `Failed password` | Brute force SSH |
| `network_flows_1.csv` | 2 000 | Aucun (non supervisé) | Connexions vers ports sensibles depuis IPs externes |

---

## 🤖 Modèles de détection retenus

### 1. Apache / HTTP — Random Forest (supervisé)

Les données Apache sont labellisées (`legit`, `attack`, `scan`).
Nous entraînons un **Random Forest** sur les features suivantes :

```
- ip_is_internal       → l'IP commence par 10.0 (interne) ou non
- http_method          → GET / POST encodé numériquement
- path_traversal       → le path contient ../ ou /etc/passwd
- path_sqli            → le path contient ' ou DROP ou SELECT
- path_sensitive       → accès à .env / .git / phpmyadmin / backup
- status_code          → 200 / 403 / 404 / 500
- bytes                → volume de la réponse
- user_agent_malicious → Nikto / sqlmap / Masscan détecté
```

Pourquoi Random Forest ?
- Gère les features mixtes (texte + numérique) sans preprocessing lourd
- Rapide à entraîner sur 14 000 lignes
- Explique ses décisions (feature importance) → défendable au jury
- Résistant aux données bruyantes ou incomplètes (mode dégradé)

---

### 2. SSH — Règles temporelles + seuils adaptatifs

Les données SSH sont simples et binaires :
les IPs externes (`185.x.x.x`) produisent quasi exclusivement
des `Failed password`. Un modèle ML serait ici superflu et moins
défendable qu'une règle explicite.

```
Règle SSH :
→ Fenêtre 10s  : plus de 5 Failed password depuis la même IP → ALERTE
→ Fenêtre 1h   : plus de 20 Failed password → BLOCAGE TEMPORAIRE
→ Fenêtre 24h  : plus de 50 Failed password → BLOCAGE LONG
→ IP interne avec Failed password répétés → ALERTE HUMAIN (Twist 3)
```

Les seuils sont configurables dans `config/config.yaml`
pour éviter les faux positifs sur des utilisateurs légitimes
qui se trompent de mot de passe.

---

### 3. Network Flows — Isolation Forest (non supervisé)

Le fichier `network_flows_1.csv` n'a pas de labels.
Nous utilisons **Isolation Forest**, un algorithme de détection
d'anomalies : il apprend ce qu'est un flux normal et isole
automatiquement ce qui s'en écarte.

```
Features utilisées :
- src_ip_is_external   → IP source hors du réseau 10.0.x.x
- dst_port             → ports sensibles : 3306 (MySQL),
                         5432 (PostgreSQL), 6379 (Redis), 22 (SSH)
- protocol_encoded     → TCP / UDP / ICMP encodé
- bytes_sent           → volume envoyé
- packets              → nombre de paquets
- duration_ms          → durée du flux
- flag_syn_only        → SYN sans ACK = potentiel scan de ports
```

Pourquoi Isolation Forest ?
- Aucun label requis
- Fonctionne bien sur des données réseau tabulaires
- Léger, déployable sur VPS à 5€/mois
- Paramètre `contamination` réglable pour contrôler
  la sensibilité et éviter les faux positifs (Twist 3)

---

## 🌐 API REST — Pourquoi et comment

### Pourquoi une API est nécessaire

Sans API, le système tourne en ligne de commande et le jury
voit du texte dans un terminal. Avec une API Flask légère :

- Le tableau de bord interroge le système en temps réel
- L'administrateur consulte les alertes depuis n'importe où
- Le jury peut auditer les décisions via des appels HTTP simples
- Le système est un vrai service déployable sur VPS,
  exactement ce que le sujet demande

### Endpoints exposés

| Méthode | Route | Description |
|---|---|---|
| `GET` | `/api/status` | État général du système |
| `GET` | `/api/alerts` | Liste des alertes en cours |
| `GET` | `/api/alerts/<ip>` | Détail des alertes pour une IP |
| `GET` | `/api/journal` | Journal complet des décisions (JSON) |
| `GET` | `/api/blocked` | Liste des IPs actuellement bloquées |
| `POST` | `/api/unblock/<ip>` | Déblocage manuel d'une IP |
| `POST` | `/api/whitelist/<ip>` | Ajout d'une IP en whitelist |
| `GET` | `/api/confidence/<ip>` | Score de confiance et de risque d'une IP |

### Format de réponse standard

```json
{
  "ip": "185.147.82.139",
  "score_risque": 87,
  "score_confiance": 92,
  "score_cout_faux_positif": 8,
  "decision": "BLOCAGE",
  "niveau_reponse": 4,
  "preuves": [
    "15 Failed SSH en 30s",
    "IP externe inconnue",
    "Connexion port 3306 détectée",
    "User-agent Nikto détecté sur Apache"
  ],
  "whitelist": false,
  "integrite_log": "verified",
  "mode_degrade": false,
  "timestamp": "2026-04-25T03:21:14Z"
}
```

---

## 🏗️ Architecture en couches

```
┌──────────────────────────────────────────┐
│  Couche 5 — Visibilité + API REST        │  ← Dashboard + endpoints HTTP
├──────────────────────────────────────────┤
│  Couche 4 — Réponse graduée              │  ← Surveiller/Alerter/Ralentir/Bloquer
├──────────────────────────────────────────┤
│  Couche 3 — Décision / Scoring           │  ← Score risque + confiance + coût FP
├──────────────────────────────────────────┤
│  Couche 2 — Détection (3 modèles)        │  ← Random Forest / Règles / Isolation Forest
├──────────────────────────────────────────┤
│  Couche 1 — Collecte + Intégrité         │  ← Logs SSH, Apache, network flows
└──────────────────────────────────────────┘
             ↕ transversal
        [ Mode dégradé ]  ← surveille toutes les couches
        [ Whitelist ]     ← protège toutes les couches
```

---

## 🔄 Pipeline de traitement

```
[Logs bruts]
  → [Collecte + Intégrité + Hachage]     ← Twist 1
  → [Détection : RF / Règles / IsoForest]← Twist 2
  → [Scoring : risque + confiance + coût]← Twist 3
  → [Décision graduée + Whitelist check]  ← Twist 3
  → [Blocage iptables + Journal JSON]
  → [API REST]
  → [Dashboard temps réel]
```

---

## 🗂️ Structure finale du projet

```
threesentinel/
│
├── README.md
│
├── config/
│   ├── config.yaml              ← seuils, fenêtres de temps, niveaux de réponse
│   └── whitelist.yaml           ← IP critiques à ne jamais bloquer (Twist 3)
│
├── src/
│   │
│   ├── collector/
│   │   ├── log_reader.py        ← lit SSH (auth.log), Apache (CSV), network flows
│   │   ├── normalizer.py        ← format uniforme pour tous les logs
│   │   └── integrity.py         ← hachage SHA256 + double horodatage (Twist 1)
│   │
│   ├── detector/
│   │   ├── http_classifier.py   ← Random Forest sur logs Apache
│   │   ├── ssh_rules.py         ← règles temporelles sur logs SSH
│   │   ├── network_anomaly.py   ← Isolation Forest sur network flows
│   │   ├── behavior.py          ← profilage comportemental par IP (Twist 2)
│   │   └── time_windows.py      ← analyse sur 10s / 1h / 24h (Twist 2)
│   │
│   ├── models/
│   │   ├── train_http.py        ← entraînement Random Forest (apache_access_1.csv)
│   │   ├── train_network.py     ← entraînement Isolation Forest (network_flows_1.csv)
│   │   ├── http_model.pkl       ← modèle HTTP sérialisé (généré à l'entraînement)
│   │   └── network_model.pkl    ← modèle réseau sérialisé (généré à l'entraînement)
│   │
│   ├── scorer/
│   │   ├── risk_scorer.py       ← score de risque global par IP (0 à 100)
│   │   ├── confidence.py        ← score de confiance du log source (Twist 1)
│   │   └── cost_scorer.py       ← score de coût du faux positif (Twist 3)
│   │
│   ├── responder/
│   │   ├── decision.py          ← décision graduée selon risque + coût (Twist 3)
│   │   ├── firewall.py          ← iptables réel avec mode dry-run pour tests
│   │   ├── rate_limiter.py      ← ralentissement avant blocage complet (Twist 3)
│   │   └── unban.py             ← déblocage automatique après délai configurable
│   │
│   ├── degraded/
│   │   ├── deduplicator.py      ← logs en doublon comptés une seule fois
│   │   ├── late_log.py          ← logs tardifs traités avec confiance réduite
│   │   └── silence_detector.py  ← absence de logs = alerte "silence suspect"
│   │
│   ├── journal/
│   │   ├── logger.py            ← écrit chaque décision en JSON structuré
│   │   └── schema.py            ← format du journal lisible par le jury
│   │
│   ├── api/
│   │   ├── app.py               ← API Flask : tous les endpoints REST
│   │   └── routes.py            ← définition des routes HTTP
│   │
│   └── dashboard/
│       ├── templates/
│       │   └── index.html       ← tableau de bord en temps réel
│       └── static/
│           └── style.css
│
├── data/
│   └── sample_logs/
│       ├── apache_access_1.csv  ← logs Apache fournis (14 340 lignes)
│       ├── auth_ssh_1.csv       ← logs SSH fournis (1 735 lignes)
│       └── network_flows_1.csv  ← network flows fournis (2 000 lignes)
│
├── tests/
│   ├── test_collector.py
│   ├── test_detector.py
│   ├── test_scorer.py
│   ├── test_responder.py
│   ├── test_api.py              ← tests des endpoints REST
│   └── test_false_positives.py  ← tests faux positifs (Twist 3)
│
├── docs/
│   └── architecture.md
│
├── requirements.txt             ← pandas, scikit-learn, flask, scapy, iptables
└── main.py                      ← point d'entrée : lance pipeline + API
```

---

## 🌀 Twist 1 — L'hypothèse cachée : "Les logs disent la vérité"

### Ce que le twist révèle

> **Notre système supposait que les logs sont fiables par nature.**

Cette hypothèse traverse toutes les couches. Le problème naît en
Couche 1 mais n'est visible qu'en Couche 5. Chaque couche transmet
l'erreur en la tenant pour vraie.

### Les 4 points d'intervention d'un attaquant

1. **À la source** — modifier le service qui écrit les logs
2. **Sur le disque** — éditer ou supprimer les fichiers logs
3. **En transit** — intercepter les logs pendant la transmission
4. **Dans le pipeline** — fabriquer des logs pour tromper les règles

| Scénario | Conséquence |
|---|---|
| IP falsifiée | Blocage d'une IP innocente |
| Faux logs générés | Système aveuglé |
| Timestamps manipulés | Scoring faussé |
| Logs supprimés | Traçabilité corrompue |

### Notre réponse

- **Hachage SHA256 à la réception** → détection de toute modification
- **Double horodatage** → heure déclarée vs heure de réception
- **Score de confiance par source** → log incomplet = score réduit
- **Fenêtres temporelles élargies** → détection des évasions sous seuil

---

## 🌀 Twist 2 — L'hypothèse cachée : "Ce qui est dangereux fait du bruit"

### Ce que le twist révèle

> **Notre système supposait qu'une attaque se remarque par son volume.**

Un attaquant silencieux reste sous tous nos seuils mais est méthodique
sur 24 heures. Le trafic chiffré est illisible mais ses métadonnées
trahissent l'attaquant.

### Notre réponse

- **Analyse multi-fenêtres** : 10 secondes · 1 heure · 24 heures
- **Isolation Forest** sur les network flows non labellisés
- **Profilage comportemental** : toute déviation du profil = suspicion
- **Analyse des métadonnées chiffrées** : timing, taille, volume, destination

```
Score final = Score d'intégrité (Twist 1) + Score comportemental (Twist 2)
```

---

## 🌀 Twist 3 — L'hypothèse cachée : "Bloquer est toujours la bonne réponse"

### Ce que le twist révèle

> **Notre système supposait que bloquer une IP suspecte est sans coût.**

Bloquer une IP légitime peut couper l'accès d'un travailleur humanitaire
en zone de conflit. Ce coût est invisible dans un système qui ne connaît
qu'une seule réponse : bloquer.

### Notre réponse — Réponse graduée à 4 niveaux

```
Niveau 1 — SURVEILLER  : score faible   → log, observation, aucune action
Niveau 2 — ALERTER     : score moyen    → notification, pas de blocage auto
Niveau 3 — RALENTIR    : score élevé    → rate limiting sur l'IP
Niveau 4 — BLOQUER     : score critique → blocage iptables + durée configurable
```

```
Score décision = Score risque - Score coût faux positif

Si score décision élevé ET IP dans whitelist   → jamais bloquer
Si score décision élevé ET historique légitime → alerter humain
Si score décision critique ET IP inconnue      → bloquer après confirmation
```

### Journal de décision (lisible par le jury)

```json
{
  "timestamp_reception": "2026-04-25T03:21:14Z",
  "timestamp_log": "2026-04-25T03:21:10Z",
  "ip_source": "185.147.82.139",
  "type_attaque": "brute_force_ssh + path_traversal",
  "preuves": [
    "15 Failed SSH en 30s",
    "IP externe inconnue",
    "GET /../../../etc/passwd détecté",
    "User-agent Nikto/2.1.6"
  ],
  "score_risque": 94,
  "score_confiance": 91,
  "score_cout_faux_positif": 6,
  "integrite_log": "verified",
  "whitelist": false,
  "decision": "BLOCAGE",
  "niveau_reponse": 4,
  "duree_blocage_minutes": 1440,
  "mode_degrade": false,
  "justification": "IP inconnue, score critique, coût faux positif faible"
}
```

### Ce que nous retenons

> Le système ne doit pas maximiser les blocages. Il doit minimiser
> le risque total : risque d'attaque ET risque de bloquer ce qu'il
> est chargé de protéger. Un système qui coupe l'accès aux populations
> vulnérables a échoué à sa mission, même s'il n'a jamais laissé
> passer une attaque.

---

## 📅 Répartition du travail

| Membre | Modules | Priorité |
|---|---|---|
| **Iness** | `config/` · `main.py` · `journal/` · `dashboard/` · `api/routes.py` | Architecture globale |
| **Alex** | `collector/` · `detector/` · `responder/` · `api/app.py` | Cœur technique |
| **Henri** | `models/` · `scorer/` · `degraded/` · `tests/` | Modèles et robustesse |

---

## ⏱️ Ordre de développement recommandé

```
Heure  1- 2 : collector/ + normalisation des 3 fichiers de données.
Heure  3- 4 : models/train_http.py (Random Forest Apache)
Heure  5- 6 : detector/ssh_rules.py + scorer/risk_scorer + journal/
Heure  7- 8 : integrity/ + confidence/ (Twist 1)
Heure  9-10 : models/train_network.py (Isolation Forest) + time_windows (Twist 2)
Heure 11-12 : cost_scorer/ + decision graduée + whitelist (Twist 3)
Heure 13-14 : api/ Flask (status, alerts, journal, block, unblock)
Heure 15-16 : degraded/ (mode dégradé)
Heure 17-18 : dashboard/ + tests/ + intégration complète
Heure    19 : démo, nettoyage, README final
```

---

## ⚙️ Stack technique

| Composant | Outil |
|---|---|
| Langage | Python 3.11 |
| Modèle HTTP | scikit-learn RandomForestClassifier |
| Modèle réseau | scikit-learn IsolationForest |
| Règles SSH | Python natif + compteurs temporels |
| Blocage | iptables (mode dry-run disponible) |
| API REST | Flask |
| Sérialisation modèles | joblib (.pkl) |
| Journal | JSON structuré |
| Déploiement | VPS Ubuntu, 5€/mois |
| Dépendances | pandas · scikit-learn · flask · scapy |

---

*Hackathon HackVerse — Équipe Iness · Alex · Henri*
