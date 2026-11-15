# Contexte court — Empreinte

## État au 14 novembre 2026

Archive Python chiffrée + registre signé + graphe/recherche + licences.
Code : `C:\Users\sawle\OneDrive\Desktop\ChargeGrinder\Empreinte`.
Python : `C:\Users\sawle\.venvs\empreinte\Scripts\python.exe`.
(Historique : pas de dépôt Git à cette date ; voir l'état du 15 novembre.) Claude avait terminé le lot lecture/import ; les autres lots
ont été interrompus. Codex a intégré le verrouillage navigateur, les dialogues,
la chronologie et le calendrier. Validation de cette reprise : 247 tests passés.
Revue contradictoire complète du noyau restant à effectuer.
Après optimisation : **251 tests réussis en 54,36 s**, suite complète avec Node.
Mesure synthétique : 168 006 octets de source → 12 000 octets envoyés (-92,9 %).
Mesure de volume, pas de facturation réelle ni de tokens d'un modèle précis.

## État au 15 novembre 2026 (session 1 — Python/Web)

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

Lot suivant (même jour) : capture continue (`watch.py`, `empreinte watch`, suivi dans le
serveur), catalogue public (`catalogue.py`, `verify_bundle.py --catalogue`, FORMAT.md
section 15), enregistrements non couverts (`coverage()`, `/api/status`, vue Registre).

Dépôt Git (branche main, aucun dépôt distant, donc `.github/workflows/ci.yml` n'a jamais
tourné). Commits : `5cff883` état de référence ; `71b26d4` catalogue, capture continue et
le texte de l'audit de clôture (aucune correction) ; `aac5cd5` portage Rust partiel et CI.

Correction de l'audit de clôture (`docs/reviews/2026-11-15-audit-de-cloture.md`) et d'une
partie de la revue capture/catalogue (`2026-11-15-revue-capture-catalogue.md`, constats 3,
4, 7, 8 ; les autres sont confiés à Codex) : verrou `writer.lock` sans lien,
déverrouillage authentifié avant la reprise du verrou d'écrivain
(`Session.check_passphrase`, `Vault.check_passphrase`), ancres lues en flux
d'enregistrements bornés, `n_anchors` jamais réécrit avant validation, lectures bornées
sur la poignée, aperçus périmés refusés à l'enregistrement, ancrage HTTP hors du verrou
d'opération, racine du lot fixée et JSON ambigu refusé dans `tools/verify_bundle.py`
(code 1 pour tout catalogue altéré, verdict MATCH distinct), Content-Length absurde en
400, initialisation de la page interrompue par un verrouillage (`web/js/startup.js`),
colonnes de tableau plafonnées, liens propres à la version affichée
(`WorkspaceAPI.link_targets(entry_id, version)`), contrôle de fuite des aperçus
(multiplicité, CJK, traits d'union, chiffres), cache de couverture lié au contenu des
racines et à l'état des ancres, carte de couverture du Registre rafraîchie à chaque statut.
`tests/conftest.py` interdit tout accès réseau pendant les tests.

Portage Rust (`rust/`) : expérimental, compilé et testé sous WSL Ubuntu seulement. Le
travail non commité sur `rust/src/anchor.rs` déclare « proven » un jeton dont ni la
signature ni la chaîne ne sont vérifiées : décision du propriétaire en attente.

## Vérifications

- Suite principale : `python -m pytest -q` (Node requis pour les tests JavaScript).
- Interopérabilité Python et Rust, à part (WSL Ubuntu avec cargo requis, pas dans pytest) :
  compiler le pilote avec `wsl -d Ubuntu -- bash -lc "cd /mnt/c/Users/sawle/OneDrive/Desktop/ChargeGrinder/Empreinte/rust && cargo build --examples"`,
  puis depuis PowerShell, à la racine :
  `$env:PYTHONPATH='src'; python tools/test_rust_interop.py --driver /mnt/c/Users/sawle/OneDrive/Desktop/ChargeGrinder/Empreinte/rust/target/debug/examples/interop`.
  Le script ne crée que des coffres jetables (`--temp-root` pour choisir leur dossier).
  Depuis Git Bash, le chemin `/mnt/c/...` est réécrit : lancer depuis PowerShell.

## Optimisation du contexte

- Ouvrir cette fiche, puis chercher le symbole/la fonctionnalité avec `rg`.
- Contrats : `src/empreinte/api.py`, `model.py`, `tests/vault_contract.py`.
- Coffre/registre : `vault.py`, `store.py`, `ledger.py`, `crypto.py`.
- Horodatage/licences : `anchor.py`, `licensing.py`, `tools/verify_bundle.py`.
- Lecture/import : `workspace.py`, `parse.py`, `search.py`, `importer.py`, `watch.py`.
- Catalogue public : `catalogue.py` (partagé par `vault.py` et `testing.py`).
- Modèle/aperçus : `context.py`, `previews.py`, `localllm.py` ; tests `test_context.py`.
- Application : `server.py`, `cli.py`, `web/js/app.js`, `web/js/api.js`, `reader.js`,
  `web/js/startup.js` (entrée dans l'application, interrompue par un verrouillage).

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

## État au 15 novembre 2026 (session 2 — Portage Rust)

Dépôt Git initialisé. 4 commits. Rust : `rust/` porte le moteur natif complet.
**12 tests Rust passent** (9 cœur + 3 anchor RFC 3161). Interop Python↔Rust OK.

### Modules Rust complétés
| Module | Statut |
|---|---|
| `crypto.rs` | ✅ Complet (AES-256-GCM, Ed25519, SHA-256, KDF) |
| `vault.rs` | ✅ Complet (create, open, record, verify, proof) |
| `server.rs` | ✅ Complet (auth, session, page-token, host-lock) |
| `workspace.rs` | ✅ Complet (scan, stats) |
| `context.rs` | ✅ Complet (compact_context, budget UTF-8) |
| `anchor.rs` | ✅ **NOUVEAU** — parseur DER RFC 3161, evaluate_token(), make_request() |

### Modules Rust restants
- `catalogue.rs` — export catalogue public non-divulguant (FORMAT.md §15)
- `watch.rs` — capture continue : scan/read/commit, quiet period 60 s
- `licensing.rs` — création licence, royalties, public_id stable
- `anchor.rs` transport — `request_anchor()` HTTP POST DigiCert (gated, approbation requise)

### "Tête pensante" (harness)
**État de référence après relecture :** `docs/reviews/2026-11-15-rust-harness-hardening.md`.
42 tests, Clippy strict et tests CLI/MCP + interop Python/Rust réussis. SQLCipher
optionnel (`--database-key-env`), `encrypt-copy`, schéma 2 (ordre/messages vides),
verrou d'opération, `runs/recover`, oubli limité aux snapshots liés, index des chunks.
Les anciennes mentions « base toujours en clair »/« purge de tous les runs » ci-dessous
sont remplacées par ce jalon. Voir `docs/USER_HARNESS.md` pour les commandes.

Dernier jalon : `rust/src/harness.rs`, guide `docs/USER_HARNESS.md`.
Profils versionnés/retour, feedback et adaptation de style proposée ; plans d'appel
inspectables et hash approuvé, HTTPS distant optionnel, clé par variable d'environnement,
anti-double envoi, états persistants ; export/oubli avec tombstone anti-réimport.
36 tests Rust + test processus local passent. Aucun appel cloud réel ni import privé.
Limites : base en clair, pas de droits juridiques garantis, pas de shell autonome,
ni boucle multi-étapes. Oubli purge tous les snapshots/feedback, refuse si run running.

Mémoire commune IA ajoutée : `rust/src/conversations.rs`, CLI `memory`, SQLite
FTS5/BM25, chunks dédupliqués de 2048 octets, imports JSON ChatGPT/Claude/normalisé,
sync de dossier explicite avec suivi optionnel, MCP stdio en lecture seule,
appel de modèle local compatible OpenAI (loopback, sans proxy/redirection).
Guide : `docs/LOCAL_AI_MEMORY.md`. Préparation GitHub : `docs/GITHUB_PREPARATION.md`.
33 tests Rust passent ; test processus CLI/MCP/modèle HTTP factice réussi.
Mesure synthétique : 519000 octets source → 3820 octets de résultats (pas tokens).
Base locale en clair, hors dépôt par défaut ; aucun historique personnel importé.
La collecte nécessite des exports/adaptateurs ; pas d'accès universel aux comptes IA.
Pas de publication GitHub ni de configuration d'un client IA existant effectuée.

Suite : empreintes SHA-256 des sources locales enregistrées et revérifiées dans
`head recall` (`current/changed/unavailable/untracked`). 29 tests passent.
Limite de 1 Mio/source, journal plafonné à 16 Mio en lecture et écriture ; anciens
événements compatibles. Index/cache, schéma versionné et modèle restent à faire.
Première tranche implémentée dans `rust/src/head.rs` et `main.rs` : commandes
`head status/recall/record/propose-rule`, journal verrouillé, transitions validées,
recherche lexicale bornée et candidates inertes. 28 tests Rust passent.
Lire « Prototype disponible » dans `docs/THINKING_HEAD.md` pour le format et les
limites : hashes/fraîcheur/cache et modèle local ne sont pas encore implémentés.
Conception démarrée : `docs/THINKING_HEAD.md` (v0.1). Harness Rust de développement,
mémoire sourcée, récupération bornée, règles candidates évaluées et réversibles.
Première tranche : CLI locale de mémoire, sans modèle ni exécution autonome.
- `AGENTS.md` table des matières → `.agents/rules/` modules provables
- Hooks Git pré-commit, linters, scripts de jardinage auto-élagage
- Pas de dépendance Obsidian — **non encore commencé**

### Rust — environnement
- Build : `wsl -d Ubuntu -- cargo ... --target-dir /root/empreinte-target`
- Pas de cargo Windows natif.
- Interop driver : `/root/empreinte-target/debug/examples/interop`

### Reprise Codex — licences Rust (15 novembre 2026)

Ce point précise les mentions « complet » ci-dessus : la parité Python reste partielle.
`vault.rs` crée les licences et redevances chiffrées, exporte les versions choisies
avec manifeste signé. `server.rs` expose POST/GET licences et redevances, filtre
par licence, et POST `/api/licenses/<id>/export`. Exports en clair dans le dossier
voisin `<nom-du-coffre>-licences`, sans écrasement des exports précédents.

Validation : **26 tests Rust réussis** ; interop Python → Rust → Python et
Rust → Python réussie, y compris licence/redevance et bundle Rust validé par
`tools/verify_bundle.py`. Fixtures jetables uniquement, aucun import du Wiki.

Correction RFC 3161 : `anchor::evaluate_token` reste `claimed` après correspondance
de l'empreinte : signature TSA/chaîne de confiance non vérifiées. Ne pas présenter
le parseur comme une preuve d'heure authentifiée. Export avec ancres encore refusé.
Les modules catalogue/watch existent mais leur intégration API reste à faire.
`rust/src/licensing.rs` est un travail distinct non intégré : ne pas le confondre
avec les méthodes actives de `vault.rs`. Aperçus/modèle, récupération et parité
du parseur restent à porter. Voir `rust/README.md` pour lancer et tester.
