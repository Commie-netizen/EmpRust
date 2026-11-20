# File de travail d'Empreinte

Lue par la tâche planifiée « Empreinte : relance toutes les 3 h » et par toute session
qui reprend le projet. Une seule source de vérité pour ce qui reste à faire.

## Tâches

| Id | Tâche | Plan | État |
|---|---|---|---|
| T1 | Corriger les 12 constats de l'audit de la tête pensante | docs/plans/2026-11-16-corrections-tete.md | à faire |
| T2 | Connecteur d'IA et tâches planifiées | docs/plans/2026-11-20-connecteur-ia.md | à faire |
| T3 | Audit Codex en lecture seule de T1 et T2, puis corrections | ce fichier, section T3 | bloquée par T1 et T2 |
| T4 | Publier sur GitHub (dépôt privé Commie-netizen/empreinte) | ce fichier, section T4 | bloquée : dépôt à créer par le propriétaire |

États possibles : à faire, en cours, à vérifier, faite, bloquée (avec la raison).

## Protocole pour une reprise

1. Lire CLAUDE.md, docs/CONTEXT.md, puis ce fichier. Ne pas relire l'historique complet.
2. Prendre la première tâche qui n'est ni faite ni bloquée.
3. Réservation : si `.work-claims/<Id>.json` existe et a moins de 6 h, une autre session
   travaille dessus : passer à la suivante. Sinon écrire ce fichier (date, session) avant
   de commencer. Une réservation de plus de 6 h est abandonnée : reprendre le travail là où
   il est dans l'arbre, sans rien jeter de ce qui n'est pas validé.
4. Faire exécuter le plan par un agent Opus 5.5 (outil Agent, modèle opus), en lui donnant
   le chemin du plan et l'état constaté (git status, ce qui existe déjà).
5. Vérifier soi-même : suite Python complète, tests Rust sous WSL si du Rust a changé,
   `git diff` limité au périmètre du plan.
6. Si tout est vert : valider dans Git (message en français, se terminant par la ligne
   Co-Authored-By de l'assistant), pousser vers `origin main` si le dépôt existe, passer
   l'état à « faite », supprimer la réservation. Sinon : état « à vérifier » avec la raison.
7. Ajouter une ligne datée au journal ci-dessous.

## T3. Audit de contrôle
Codex en lecture seule (`codex exec -s read-only`, effort élevé) sur ce que T1 et T2 ont
changé ; rapport dans docs/reviews/. Constats graves corrigés par un agent Opus 5.5 avant
de marquer T3 faite. Codex partage son quota avec d'autres sessions : en cas de limite,
noter l'heure de réouverture et passer.

## T4. Publication
Le dépôt GitHub doit être créé par le propriétaire (privé, vide, sans README) :
https://github.com/new, nom `empreinte`, compte Commie-netizen. Le remote `origin` est déjà
configuré. Ensuite : `git push -u origin main`. Ne jamais rendre le dépôt public sans
accord explicite : les notes contiennent des chemins locaux.

## Règles permanentes
- Ne jamais contacter une autorité d'horodatage, ne jamais appeler `memory execute`.
- Ne jamais lire le Wiki (C:\Users\sawle\Documents\Wiki) ni ouvrir le coffre d'essai
  (C:\Users\sawle\.empreinte-essai).
- Préfixe `rtk` sur les commandes shell ; français, sans emojis ni tirets cadratins.

## Journal
- 2026-11-20 : file créée. Tout le travail en attente validé (commit a3ba33c). Remote
  `origin` configuré ; dépôt GitHub absent.
