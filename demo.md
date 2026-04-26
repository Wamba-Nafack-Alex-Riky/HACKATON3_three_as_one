# 🛡️ Guide de Démonstration : ThreeSentinel

Ce guide explique pas à pas comment tester et démontrer l'efficacité de **ThreeSentinel** en simulant des attaques réelles entre deux ordinateurs sur le même réseau.

---

## 🖥️ Étape 1 : Préparation du Serveur (Machine A)

L'ordinateur A sera le "Serveur Protégé".

1.  **Lancer ThreeSentinel** :
    ```bash
    # Lancement standard (Dashboard + API + Moteur IA)
    python main.py --fast
    ```
    *Note : Utilisez `--real-fw` si vous avez les droits root et voulez un vrai blocage iptables.*

2.  **Ouvrir le Tableau de Bord** :
    - Allez sur : `http://localhost:5000/dashboard`
    - Gardez cette page ouverte pour voir les alertes tomber en temps réel.

3.  **Récupérer l'IP du Serveur** :
    ```bash
    hostname -I
    ```
    *(Notez bien cette IP, ex: `172.24.203.61 `)*

---

## ⚔️ Étape 2 : Simulation des Attaques (Machine B)

L'ordinateur B sera "l'Attaquant".

### Scénario A : Brute Force SSH (Volume & Vitesse)
Simule une tentative d'accès forcé par répétition.
```bash
# Remplacez TARGET_IP par l'IP de la Machine A
for i in {1..10}; do ssh admin@TARGET_IP -o BatchMode=yes; done
```
💡 **Observation** : Vous verrez des alertes rouges apparaître sur le Dashboard dans la seconde.

### Scénario B : Injection SQL (Intelligence ML)
Simule une attaque applicative détectée par le modèle Random Forest.
```bash
# Tentative d'injection via paramètre URL
curl "http://TARGET_IP/api/users?id=' OR 1=1 --"
```
💡 **Observation** : Le modèle classifie la requête comme **ATTACK** et affiche la justification "SQL Injection detected".

### Scénario C : Path Traversal (Sécurité Fichiers)
Simule une tentative d'accès aux fichiers sensibles du système.
```bash
curl "http://TARGET_IP/download?path=../../../../etc/shadow"
```
💡 **Observation** : Le système détecte le motif suspect `../../` et augmente le score de risque.

---

## 🧐 Étape 3 : Analyse et Réponse (Machine A)

Une fois les attaques lancées, montrez les capacités de réponse du système :

1.  **Visualisation du SOC** :
    - Allez dans l'onglet **"Surveillance"** : montrez les graphes qui grimpent.
    - Allez dans **"Intervention"** : montrez l'IP de la Machine B qui est désormais bloquée.

2.  **Actions Manuelles** :
    - Cliquez sur **"Débloquer"** pour rendre l'accès à la Machine B.
    - Ajoutez l'IP de la Machine B en **"Whitelist"** pour prouver que le système peut ignorer un administrateur qui fait des tests.

3.  **Vérification de l'API** :
    - Montrez le format JSON propre au jury : `http://localhost:5000/api/confidence/<IP_ATTAQUANT>`

---

## 💎 Étape 4 : Bonus "Effet WOW" pour le Jury

Démontrez la robustesse (Twists) :
- **Intégrité (Twist 1)** : Ouvrez `journal.jsonl` et montrez les hashes SHA256 pour chaque ligne.
- **Mode Dégradé (Twist 2)** : Coupez le flux de logs (arrêtez la simulation de logs) et montrez l'alerte **"Silence Suspect"** qui apparaît sur la landing page.
- **Whitelist Intelligente (Twist 3)** : Tentez de bloquer une IP interne (ex: 127.0.0.1) et montrez que le système refuse le blocage pour protéger le service.

---
*Hackathon HackVerse — Sécurité Autonome ThreeSentinel*
