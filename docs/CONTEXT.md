# Contexte court — Empreinte

## État au 14 novembre 2026

Archive Python chiffrée + registre signé + graphe/recherche + licences.
Code : `C:\Users\sawle\OneDrive\Desktop\ChargeGrinder\Empreinte`.
Python : `C:\Users\sawle\.venvs\empreinte\Scripts\python.exe`.
Pas de dépôt Git. Claude avait terminé le lot lecture/import ; les autres lots
ont été interrompus. Codex a intégré le verrouillage navigateur, les dialogues,
la chronologie et le calendrier. Validation de cette reprise : 247 tests passés.
Revue contradictoire complète du noyau restant à effectuer.
Après optimisation : **251 tests réussis en 54,36 s**, suite complète avec Node.
Mesure synthétique : 168 006 octets de source → 12 000 octets envoyés (-92,9 %).
Mesure de volume, pas de facturation réelle ni de tokens d'un modèle précis.

## État au 15 novembre 2026

Audit Codex constat par constat : `docs/reviews/2026-11-15-audit.md` (16 corrigés,
13 partiels, 1 non corrigé, 9 défauts nouveaux). Trois lots de corrections ont suivi
(noyau, serveur et interface, couche de lecture). **283 tests réussis**, essai de bout
en bout sur le coffre Obsidian réel dans un dossier jetable, vue graphique contrôlée
dans le navigateur (anneaux autour du moyeu, couleurs par groupe, étiquettes au zoom).
Audit de clôture demandé à Codex, interrompu par sa limite d'usage : s'il existe,
il est dans `docs/reviews/2026-11-15-audit-de-cloture.md` ; sinon il reste à faire.
Ancrage réel essayé le 15 novembre avec l'accord de l'utilisateur, sur le coffre d'essai
(`C:\Users\sawle\.empreinte-essai\coffre`) : jeton DigiCert RFC 3161 obtenu, état « proven »
(chaîne validée jusqu'aux racines certifi), confirmé par `tools/verify_bundle.py` et par
`openssl ts -verify` (OK avec la bonne empreinte, échec avec une fausse). Tout nouvel
ancrage reste une action explicite de l'utilisateur.
Codex ne lance Python que via `C:/Users/sawle/.codex-py` (`--add-dir`, PYTHONPATH=site;src).
Gemini : la CLI refuse le compte individuel ; il faut une clé `GEMINI_API_KEY`.

## Optimisation du contexte

- Ouvrir cette fiche, puis chercher le symbole/la fonctionnalité avec `rg`.
- Contrats : `src/empreinte/api.py`, `model.py`, `tests/vault_contract.py`.
- Coffre/registre : `vault.py`, `store.py`, `ledger.py`, `crypto.py`.
- Horodatage/licences : `anchor.py`, `licensing.py`, `tools/verify_bundle.py`.
- Lecture/import : `workspace.py`, `parse.py`, `search.py`, `importer.py`.
- Modèle/aperçus : `context.py`, `previews.py`, `localllm.py` ; tests `test_context.py`.
- Application : `server.py`, `cli.py`, `web/js/app.js`, `web/js/api.js`, `reader.js`.

Les chemins ci-dessus sont relatifs à `src/empreinte/`, sauf préfixe explicite.
Ne pas charger tout le corpus, toutes les sources ou l'historique de session pour
une tâche locale. Les originaux restent disponibles et font autorité.

## Budget des aperçus locaux

`compact_context` retire le frontmatter Markdown et les paragraphes identiques,
puis limite le document à 12 000 octets UTF-8, avec extraits début/milieu/fin.
Ce plafond est un budget de taille portable, pas un comptage exact des tokens.
Le prompt et l'interface signalent les aperçus partiels. Sortie : 512 tokens max.
Le contrôle des fuites utilise toujours le document entier. Les aperçus restent
des brouillons à approuver, stockés dans les données auxiliaires chiffrées.

Cache : engagement/version du document + modèle + politique de contexte.
Un aperçu inchangé est réutilisé sans appel au modèle ; `force=True` dans
`make_preview` régénère explicitement. Changer le modèle ou le document invalide
le cache ; incrémenter `CONTEXT_POLICY` si la sélection/le prompt change.
Un changement de poids servi sous le même nom de modèle exige `force=True`.

## Commandes

Depuis le projet : `python -m pytest -q` (Node requis pour les tests JS).
Démo : `python -m empreinte.cli demo` ; mot de passe fictif `demo`.
Format : `docs/FORMAT.md`. Détails de reprise :
`docs/reviews/2026-11-14-continuation.md`.
Ne pas assimiler une date « claimed » à « proven » ; racine authentifiée requise.
