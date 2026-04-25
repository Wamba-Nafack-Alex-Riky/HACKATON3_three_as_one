# Twist 1 — L'hypothèse cachée : "Les logs disent la vérité"

## Ce que le twist révèle

L'objectif apparent du projet est de détecter des intrusions 
et de réagir automatiquement. Cependant, le premier twist 
nous force à questionner une hypothèse fondamentale que nous 
avions acceptée sans la remettre en cause :

> **Notre système supposait que les logs sont fiables par nature.**

Cette hypothèse, tenue pour neutre au départ, devient en 
réalité une dépendance destructrice qui traverse toutes les 
couches de notre architecture.

---

## Pourquoi c'est dangereux

Le problème naît en **Couche 1 (Collecte)** mais n'est 
visible qu'en **Couche 5 (Visibilité)**. Entre les deux, 
chaque couche transmet l'erreur en la tenant pour vraie, 
sans jamais la questionner.

| Scénario | Conséquence sur notre système |
|---|---|
| IP falsifiée dans un log | Blocage d'une IP innocente |
| Faux logs générés par l'attaquant | Système aveuglé |
| Timestamps manipulés | Scoring faussé |
| Logs d'intrusion supprimés | Traçabilité corrompue |
| Logs sous le seuil de détection | Attaque par évasion invisible |

---

## Ce que nous avons compris

Un attaquant peut intervenir à 4 niveaux :

1. **À la source** — modifier le service qui écrit les logs
2. **Sur le disque** — éditer ou supprimer les fichiers logs
3. **En transit** — intercepter les logs pendant leur transmission
4. **Dans le pipeline** — fabriquer des logs conçus pour 
   tromper nos règles de détection

L'effet n'est pas visible là où il se produit, mais là où 
l'on continue, à tort, d'interpréter comme local un problème 
qui ne l'est déjà plus.

---

## Notre réponse architecturale

Nous avons intégré un mécanisme de **confiance à la source** 
qui s'applique dès l'entrée du pipeline :

- **Hachage de chaque log à la réception** → détection de 
  toute modification ultérieure
- **Double horodatage** → heure déclarée dans le log + heure 
  de réception réelle
- **Score de confiance par source** → un log incomplet ou 
  incohérent réduit automatiquement le score de l'alerte
- **Détection des fenêtres d'évasion** → analyse sur des 
  intervalles de temps élargis pour détecter les attaques 
  qui restent sous le seuil

---


## Impact sur notre architecture globale
Le mode dégradé et le score de confiance que nous avions 
prévus initialement restent pertinents, mais ils sont 
désormais alimentés par cette vérification d'intégrité 
à la source.

---

## Ce que nous retenons

> Le livrable attendu n'est pas un système qui fonctionne 
> dans un cas parfait, mais une structure qui reste 
> suffisamment cohérente pour produire des états défendables, 
> même quand les données sur lesquelles elle s'appuie 
> ont été compromises.