# 📋 Récapitulatif : Interface & API ThreeSentinel

Ce document résume les travaux effectués pour transformer l'outil technique en une solution de cybersécurité de niveau entreprise ("Corporate Grade").

---

## 🎨 1. Frontend & Design (UI/UX)

### 💎 Identité Visuelle
- **Branding** : Migration complète vers le nom **ThreeSentinel**.
- **Design System** : Thème **Dark SOC** ultra-moderne utilisant le *Glassmorphism* (effets de transparence et flou).
- **Typographie** : Combinaison de `Montserrat` (titres institutionnels) et `Inter` (données techniques) pour une lisibilité maximale.
- **Micro-animations** : 
  - **Transitions** : Effet de fondu (`Fade-In`) fluide entre toutes les pages.
  - **Feedback** : Animations pulsantes pour le statut système et effets de survol interactifs sur les cartes.

### 🗺️ Architecture Multi-Pages
L'interface a été découpée en **5 pages distinctes** pour éviter l'encombrement :
1.  **Landing Page (`/`)** : Vitrine institutionnelle avec statistiques "Live" (Threats Neutralized).
2.  **Surveillance (`/dashboard`)** : Monitoring en temps réel des alertes IA et KPIs (IPs bloquées, Alertes actives).
3.  **Intervention (`/firewall`)** : Centre de contrôle manuel pour bloquer/débloquer des IPs et gérer la Whitelist.
4.  **Analyse (`/analysis`)** : Statistiques avancées, répartition des décisions et top des attaquants.
5.  **Aide (`/help`)** : Centre de documentation complet intégré pour l'utilisateur final.

---

## ⚙️ 2. Backend & API (Flask)

### 🔌 Interconnexion Temps Réel
- **Serveur unifié** : Flask sert à la fois les fichiers HTML et l'API REST sur le port `5000`.
- **Client API (`api_client.js`)** : Création d'une bibliothèque JavaScript centralisée pour gérer tous les appels asynchrones (`fetch`) de manière sécurisée et uniforme.
- **Endpoints principaux** :
  - `GET /api/status` : État de santé et KPIs globaux.
  - `GET /api/alerts` : Flux des dernières menaces détectées.
  - `GET /api/stats` : Données agrégées pour les graphiques d'analyse.
  - `POST /api/unblock/<ip>` : Commande de déblocage manuel.
  - `POST /api/whitelist/<ip>` : Ajout à la liste de confiance.

### 🧠 Intégration IA
- L'API est directement branchée sur le **Journal de Bord** alimenté par le moteur de détection IA (Random Forest / Heuristiques).
- **Mode Dégradé** : Détection automatique des silences suspects (Twist 2) remontée immédiatement sur l'interface.

---

## 🚀 3. Installation & Lancement

Le projet a été simplifié pour un déploiement rapide lors du hackathon :

```bash
# Une seule commande pour tout lancer (Backend + API + Front)
python main.py
```

- **Dashboard** : `http://localhost:8080/dashboard`
- **Mode Démo Rapide** : `python main.py --fast`

---
*Développé pour l'équipe HackVerse — Sécurité, Autonomie, Performance.*