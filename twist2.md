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
> même quand les conditions d'exploitation ne sont pas idéales ?

---

## 🧩 Découpage en sous-problèmes

| # | Sous-problème | Objectif |
|---|---|---|
| 1 | Collecte des données | Lire et normaliser les logs SSH, Apache/nginx, pcap |
| 2 | Détection des attaques | Identifier les patterns d'intrusion connus |
| 3 | Scoring de menace | Évaluer la gravité de chaque alerte |
| 4 | Réponse automatique | Bloquer les IP malveillantes via iptables |
| 5 | Mode dégradé | Maintenir la cohérence avec des données imparfaites |
| 6 | Traçabilité | Produire des états défendables et auditables |

---

## 🏗️ Architecture en couches

```
┌──────────────────────────────────────┐
│  Couche 5 — Visibilité               │  ← Tableau de bord, audit
├──────────────────────────────────────┤
│  Couche 4 — Réponse                  │  ← Blocage iptables, logging
├──────────────────────────────────────┤
│  Couche 3 — Décision / Scoring       │  ← Score de menace + confiance
├──────────────────────────────────────┤
│  Couche 2 — Analyse / Détection      │  ← Règles + comportement
├──────────────────────────────────────┤
│  Couche 1 — Collecte                 │  ← Logs SSH, Apache, pcap
└──────────────────────────────────────┘
           ↕ transversal
      [ Mode dégradé ]  ← surveille toutes les couches
```

---

## 🔄 Pipeline de traitement

```
Logs bruts → [Collecte + Intégrité] → [Détection] → [Scoring] → [Réponse] → [Tableau de bord]
                     ↑                      ↑              ↑
               Twist 1 adressé        Twist 2 adressé   Mode dégradé
```

---

## ⚙️ Stack technique

- **Langage :** Python
- **Détection réseau :** Scapy
- **Blocage :** iptables
- **Référence IPS :** fail2ban (comme baseline)
- **Données :** CSV Apache/nginx · auth.log SSH · captures pcap légères
- **Déploiement :** VPS Linux à 5€/mois

---

## 🌀 Twist 1 — L'hypothèse cachée : "Les logs disent la vérité"

### Ce que le twist révèle

L'objectif apparent du projet est de détecter des intrusions et de réagir
automatiquement. Cependant, le premier twist nous force à questionner une
hypothèse fondamentale que nous avions acceptée sans la remettre en cause :

> **Notre système supposait que les logs sont fiables par nature.**

Cette hypothèse, tenue pour neutre au départ, devient en réalité une
dépendance destructrice qui traverse toutes les couches de notre architecture.

### Pourquoi c'est dangereux

Le problème naît en **Couche 1 (Collecte)** mais n'est visible qu'en
**Couche 5 (Visibilité)**. Entre les deux, chaque couche transmet l'erreur
en la tenant pour vraie, sans jamais la questionner.

| Scénario | Conséquence sur notre système |
|---|---|
| IP falsifiée dans un log | Blocage d'une IP innocente |
| Faux logs générés par l'attaquant | Système aveuglé |
| Timestamps manipulés | Scoring faussé |
| Logs d'intrusion supprimés | Traçabilité corrompue |
| Logs sous le seuil de détection | Attaque par évasion invisible |

### Les 4 points d'intervention d'un attaquant sur les logs

1. **À la source** — modifier le service qui écrit les logs
2. **Sur le disque** — éditer ou supprimer les fichiers logs directement
3. **En transit** — intercepter les logs pendant leur transmission réseau
4. **Dans le pipeline** — fabriquer des logs conçus pour tromper nos règles

L'effet n'est pas visible là où il se produit, mais là où l'on continue,
à tort, d'interpréter comme local un problème qui ne l'est déjà plus.

### Notre réponse architecturale

Nous avons intégré un mécanisme de **confiance à la source** dès l'entrée
du pipeline :

- **Hachage de chaque log à la réception** → détection de toute modification ultérieure
- **Double horodatage** → heure déclarée dans le log + heure de réception réelle
- **Score de confiance par source** → un log incomplet ou incohérent réduit automatiquement le score de l'alerte générée
- **Détection des fenêtres d'évasion** → analyse sur des intervalles de temps élargis pour détecter les attaques qui restent sous le seuil

### Impact sur l'architecture

```
[Couche 1 — Collecte]
      ↓ hachage + double horodatage
[Couche 2 — Analyse]
      ↓ score de confiance source
[Couche 3 — Décision]
      ↓ prise en compte de l'incertitude
[Couche 4 — Réponse]
      ↓ action tracée et justifiée
[Couche 5 — Visibilité]
      ↓ tableau de bord avec niveau de confiance affiché
```

### Ce que nous retenons

> Le livrable attendu n'est pas un système qui fonctionne dans un cas parfait,
> mais une structure qui reste suffisamment cohérente pour produire des états
> défendables, même quand les données sur lesquelles elle s'appuie ont été
> compromises.

---

## 🌀 Twist 2 — L'hypothèse cachée : "Ce qui est dangereux fait du bruit"

### Ce que le twist révèle

Après avoir adressé la fiabilité des logs, notre système reposait sur une
nouvelle hypothèse tenue pour neutre :

> **Notre système supposait qu'une attaque se remarque par son volume.**

Nos règles de détection étaient construites sur des seuils : trop de
tentatives SSH, trop de ports scannés, trop de requêtes suspectes.
Mais un attaquant intelligent peut être **silencieux et chiffré**.

### Le problème concret

```
Attaque bruyante (détectée facilement) :
→ 100 tentatives SSH en 5 secondes → ALERTE ✅

Attaque silencieuse (invisible pour nos règles) :
→ 1 tentative SSH à 08h00
→ 1 tentative SSH à 11h00
→ 1 tentative SSH à 15h00
→ 1 tentative SSH à 20h00
→ Chaque événement pris seul est normal.
  Ensemble sur 24h : c'est une attaque méthodique. ❌
```

### Le chiffrement comme camouflage

Un attaquant moderne chiffre son trafic. Dans les logs, cela ressemble à :

```
Trafic légitime HTTPS :
192.168.1.1 → serveur : [données chiffrées] port 443

Trafic attaquant HTTPS :
45.33.32.156 → serveur : [données chiffrées] port 443
```

Les deux lignes sont identiques en apparence.
Le contenu est illisible. Pourtant l'une est une attaque.

### Comment ça contamine toutes les couches

| Couche | Ce qui se passe |
|---|---|
| Couche 1 — Collecte | Log reçu normal en apparence, aucun signal |
| Couche 2 — Analyse | Aucune règle ne se déclenche |
| Couche 3 — Décision | Zéro alerte, zéro décision |
| Couche 4 — Réponse | Aucune action, l'attaquant passe librement |
| Couche 5 — Visibilité | Tableau de bord affiche "Système sain" ✅ (faux) |

### Notre réponse architecturale

**Travail 1 — Analyse multi-fenêtres temporelles**

```
Avant Twist 2 :
→ Fenêtre d'analyse = 10 secondes seulement

Après Twist 2 :
→ Fenêtre courte  = 10 secondes  (attaques bruyantes classiques)
→ Fenêtre moyenne = 1 heure      (attaques modérées)
→ Fenêtre longue  = 24 heures    (attaques lentes et silencieuses)
```

**Travail 2 — Profilage comportemental par IP**

Pour chaque IP nous construisons un profil de comportement normal :
- Heures de connexion habituelles
- Fréquence et volume quotidien
- Ports utilisés habituellement

Toute déviation du profil augmente le score de suspicion.
Une IP inconnue reçoit un score de suspicion élevé par défaut.

**Travail 3 — Analyse des métadonnées du trafic chiffré**

Même si le contenu est illisible, nous analysons ce qui est visible autour :

```
Signaux suspects détectables sans lire le contenu :
→ Trafic chiffré régulier vers IP inconnue à 3h du matin
→ Paquets de taille identique toutes les 30 secondes
  (signature caractéristique d'un outil automatisé)
→ Volume de données sortantes anormalement élevé
  (signe potentiel d'exfiltration de données)
```

**Travail 4 — Score de confiance étendu**

```
Score final = Score d'intégrité (Twist 1)
            + Score comportemental (Twist 2)

Exemple concret :
IP 45.33.32.156 :
- Log intègre et non modifié        → confiance haute
- IP jamais vue auparavant          → suspicion élevée
- Connexion à 3h du matin           → suspicion élevée
- Volume chiffré sortant élevé      → suspicion élevée
→ Score de suspicion total élevé    → ALERTE HAUTE 🚨
```

### Ce que nous retenons

> La destruction n'est pas nécessairement visible là où elle se produit,
> mais là où l'on continue, à tort, d'interpréter comme local un effet
> qui ne l'est déjà plus. Un attaquant silencieux et chiffré contamine
> toutes les couches sans jamais déclencher une seule règle basée sur
> le volume.

---

## 🗂️ Données fournies

| Élément | Détail |
|---|---|
| **Source** | Logs réseau synthétiques fournis par l'organisateur |
| **Format** | CSV Apache/nginx · auth.log SSH · captures pcap légères |
| **Accès** | Dataset synthétique dans le repo hackathon |
| **Outils** | scapy · fail2ban (référence) · iptables |

---

## 👥 Équipe

| Membre | Rôle |
|---|---|
| Iness | Chef de projet · Architecture |
| Alex | Développement backend · Détection |
| Henri | Pipeline de données · Scoring |

---

## 📎 Structure du dépôt

```
/
├── README.md               ← Ce fichier
├── src/
│   ├── collector.py        ← Couche 1 : collecte et intégrité des logs
│   ├── detector.py         ← Couche 2 : règles de détection + comportement
│   ├── scorer.py           ← Couche 3 : scoring de menace
│   ├── responder.py        ← Couche 4 : blocage iptables + logging
│   └── dashboard.py        ← Couche 5 : tableau de bord
├── data/
│   └── sample_logs/        ← Logs synthétiques de test
├── docs/
│   └── architecture.md     ← Détail de l'architecture
└── tests/
    └── test_detection.py   ← Tests unitaires
```

---


