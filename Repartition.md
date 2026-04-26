# 📋 Répartition des Tâches — Équipe HackVerse

Ce document définit les responsabilités de chaque membre pour la phase finale du Hackathon afin d'éviter les conflits de code et d'assurer une couverture complète des objectifs (Twists 1, 2 et 3).

---

## 👩‍💻 Iness — Visibilité & UX (Layer 5)
**Focus :** Interface utilisateur, API et présentation au jury.

| Module | Fichier(s) | Description |
| :--- | :--- | :--- |
| **Dashboard** | `src/dashboard/` | Création d'une interface premium (HTML/CSS/JS) avec graphiques en temps réel. |
| **API REST** | `src/api/` | Finalisation des routes et intégration des données pour le dashboard. |
| **Journalisation** | `src/journal/` | Formatage du journal JSON pour qu'il soit "défendable" et lisible par le jury. |
| **Docs** | `README.md`, `docs/` | Synthèse finale, captures d'écran et schémas d'architecture. |

---

## 👨‍💻 Alex — Core Engine & Flux (Layers 1 & 4)
**Focus :** Pipeline de données, intégration système et réponses automatiques.

| Module | Fichier(s) | Description |
| :--- | :--- | :--- |
| **Collecte** | `src/collector/log_reader.py` | Lecture simulée en continu des CSV comme s'ils étaient des logs live. |
| **Orchestration** | `main.py` | Point d'entrée unique lançant le pipeline et l'API en parallèle. |
| **Réponse** | `src/responder/` | `rate_limiter.py` (ralentissement) et `unban.py` (déblocage auto). |
| **Pare-feu** | `src/responder/firewall.py` | Gestion réelle/simulée du blocage via iptables. |
| **Degraded Mode** | `src/degraded/silence_detector.py` | Détection d'arrêt de flux (Twist 2). |

---

## 👨‍💻 Henri — Data Science & Robustesse (Layers 2 & 3)
**Focus :** Modèles ML, scoring complexe et validation technique.

| Module | Fichier(s) | Description |
| :--- | :--- | :--- |
| **Modèles ML** | `src/models/` | Entraînement et génération des fichiers `.pkl` (Random Forest & Isolation Forest). |
| **Comportement** | `src/detector/behavior.py` | Profilage des IPs et analyse sur fenêtres temporelles (Twist 2). |
| **Confiance** | `src/collector/integrity.py` | Hachage et vérification d'intégrité à la source (Twist 1). |
| **Tests** | `tests/` | Tests unitaires et tests de faux-positifs (Twist 3). |
| **Degraded Mode** | `src/degraded/late_log.py` | Gestion des logs tardifs ou incohérents (Twist 1). |

---

## 🛠️ Règles de Travail pour éviter les Conflits Git

1. **Isolation :** Ne travaillez que dans vos répertoires assignés.
2. **Modifications transversales :** Si vous devez modifier `config/config.yaml` ou `src/collector/normalizer.py`, prévenez l'équipe sur le canal de communication.
3. **Push :** Faites des petits commits descriptifs. Faites un `git pull --rebase` avant chaque push.
4. **Main :** Seul **Alex** est responsable de la structure globale dans `main.py`.

---
*Hackathon HackVerse — Iness · Alex · Henri*
