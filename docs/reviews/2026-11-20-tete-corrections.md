# T1. Corrections de l'audit de la tête pensante (20 novembre 2026)

Audit : `docs/reviews/2026-11-16-audit-tete-pensante.md` (12 constats). Plan :
`docs/plans/2026-11-16-corrections-tete.md`. Rien n'est commité.

Résultat : suite Rust sous WSL, `cargo test --all-targets --offline --locked`, **94 tests
réussis** sur cinq passages identiques, puis **95** au dernier passage (19 h 22) : une autre
session a ajouté entre-temps un test dans `rust/src/workspace.rs` et modifié
`rust/src/main.rs` hors des sous-commandes `head` (changement de phrase de passe, accès de
secours), ce qui n'est pas de cette tâche. Dont 54 pour la tête : 19 dans
`rust/src/head/tests.rs`, 20 dans `rust/tests/head_audit.rs` (un ou plusieurs par
constat), 15 dans `rust/tests/head_lifecycle.rs`. La suite Python n'a pas été relancée :
aucun fichier Python n'a changé dans cette tâche.

## Vu échouer d'abord (constats 1, 2, 3, 5)

Fichier `rust/tests/head_audit_before.rs`, écrit contre l'ancienne API et lancé sur
l'ancien code : 4 échecs sur 4, puis retiré (les mêmes scénarios sont dans
`head_audit.rs`) :
- 1 : un faux `cargo` placé en tête du PATH de l'appelant a été exécuté ;
- 2 : l'assistant `textconv` configuré dans le dépôt a été lancé par la sonde de révision ;
- 3 : lancé depuis `vendor/evil` (faux `.git` et `.agents` hostile), l'outil a choisi
  ce sous-dossier comme racine ;
- 5 : un arbre passé de A (échec) à B (réussite) pendant le contrôle, puis remis à A, a été
  certifié `verified`.

Pour les autres constats, les tests ont été écrits avec la correction ; pour le 6, un
test témoin montre que le même descendant survit quand rien ne le confine.

## Par constat

1. **Programme et environnement.** `checks.json` passe en version 2 : programme en chemin
   absolu (nom nu ou relatif refusé, git compris). Environnement construit, jamais hérité :
   `PATH=/usr/local/bin:/usr/bin:/bin`, `HOME=<cache>/home`, `CARGO_HOME` et `RUSTUP_HOME`
   dans le dossier personnel lu dans la base des comptes, `LANG`, `PYTHONDONTWRITEBYTECODE`,
   plus les variables que l'entrée liste avec leur valeur. Chaque résultat garde le chemin
   et le SHA-256 du programme et l'empreinte de la configuration d'exécution (dont les
   fichiers de configuration de Cargo) ; un changement les rend périmés. Tests :
   `finding_1_programs_are_absolute_and_the_environment_is_fixed`,
   `finding_1_a_changed_program_makes_the_result_stale`, et les cas refusés de
   `checks_file_must_keep_commands_and_directories_in_bounds`.
2. **Git.** Plus de `git diff` ni de `git status`, plus de `rev-parse` : seul
   `git ls-files -z --cached --others --exclude-standard`, confiné comme un contrôle,
   configuration système et globale désactivée, `core.fsmonitor`, `core.hooksPath`,
   `core.pager` neutralisés, `--git-dir` et `--work-tree` explicites. L'outil hache
   lui-même chaque fichier. Test : `finding_2_configured_git_helpers_are_never_executed`
   (textconv, diff.external, filtre clean, fsmonitor, pager).
3. **Confiance.** `head trust <chemin>` montre, `--confirm` enregistre dans
   `~/.config/empreinte/trusted-repos.json`, avec l'empreinte de `checks.json`. Ancêtre de
   confiance le plus proche, sinon refus ; liste de contrôles modifiée : refus. `.agents`
   et ses fichiers ouverts par `openat` sans suivre de lien (`fsafe.rs`). Tests :
   `finding_3_only_an_explicitly_trusted_root_is_used`,
   `finding_3_links_in_agents_are_refused`, `an_allow_list_changed_after_trust_is_refused`.
4. **Échec fermé.** Empreinte impossible (git absent, en échec, hors délai, sortie
   tronquée, fichier illisible) : résultat `incomplete`, rien de certifié. Les fichiers non
   suivis non ignorés sont hachés. Tests : `finding_4_no_fingerprint_no_certification`,
   `finding_4_untracked_content_is_fingerprinted`.
5. **Instantané.** Chaque contrôle tourne dans une copie en lecture seule sous
   `<cache>/snapshots`, empreinte calculée sur les octets écrits ; `verified` et `promote`
   exigent que l'arbre de travail ait cette empreinte au moment de l'engagement ; un
   contrôle qui modifie son instantané est `incomplete`. Tests : `finding_5_*` (trois).
6. **Confinement.** Espaces de noms utilisateur, réseau et processus sans privilège ; un
   gardien subreaper lance le programme en PID 1, le tue au délai, récupère tous les
   descendants et confirme le nettoyage. `passed` exige sortie 0, capture complète dans sa
   borne, confinement et nettoyage confirmés. Tests : `finding_6_*` (quatre, dont le témoin
   sans confinement ; aucun zombie toléré).
7. **Ligne ignorée.** Avant toute écriture, une dernière ligne sans fin de ligne est
   scellée par `~torn` (aucun JSON valide ne peut en sortir). Une promotion cite
   l'évaluation dont elle dépend ; la relecture vérifie qu'elle existe, précède, est la
   dernière de la règle, porte sur le même contenu et a réussi. Tests :
   `a_complete_line_without_newline_never_becomes_valid`,
   `finding_7_promotion_relies_on_the_latest_evaluation_and_replay_checks_it`.
8. **Transactions.** Mouvements de règles : intention `rule-transaction.json` écrite et
   synchronisée avant les fichiers, achevée ou annulée à l'ouverture ; un fichier dans un
   troisième état n'est jamais écrasé et bloque les écritures. Réparation : intention
   `repair-intent.json`, dossier synchronisé ; journal absent avec trace de réparation :
   refus, aucun journal vide créé. Tests :
   `finding_8_an_interrupted_rule_move_is_completed_or_undone_at_opening`,
   `an_interrupted_repair_never_leaves_an_empty_journal`.
9. **Verrou.** Avant chaque écriture, le verrou et le journal doivent être les fichiers
   ouverts (périphérique et inode). Test : `a_swapped_lock_is_detected_before_writing`.
   Limite : qui peut écrire dans le dossier peut forger le journal.
10. **États effectifs.** `recall` donne `effective` (`verified` ou `verified-stale`,
    `certifies` ou `does-not-certify`, avec raisons) ; les règles actives sont `active` ou
    `active-stale` avec l'état de leur évaluation. Test :
    `finding_10_recall_and_active_listings_show_staleness`.
11. **Amorçage.** `head register` fait entrer une règle comme candidate ; un fichier qui
    dit plus est remis à candidate dans le même mouvement ; `evaluate` exige
    l'enregistrement. Test :
    `finding_11_a_rule_enters_the_journal_by_registration_then_fresh_evaluation`.
12. **Réseau.** `requires_isolation` : sans isolation, pas de `passed`. L'espace réseau
    n'a que sa propre boucle locale (relevée pour que les tests qui écoutent sur
    127.0.0.1 marchent) : rien ne sort de la machine. `uncontained` : jamais `passed`. Règle
    réécrite pour ne dire que ce qui est appliqué. Tests :
    `finding_12_a_check_that_requires_isolation_has_no_network`,
    `finding_12_an_uncontained_check_never_passes`.

## Décisions prises

- **Environnement** : valeurs ci-dessus ; `CARGO_HOME` est celui du compte (registre de
  crates hors ligne), lu dans la base des comptes, pas dans l'environnement.
- **Instantané et cache** : instantané privé (0700) sous `~/.cache/empreinte/head`,
  supprimé après le contrôle ; `.agents/rules/` et `.empreinte-head/` exclus de
  l'empreinte. Cache Cargo `<cache>/cargo-target` (déclaré dans l'entrée) : un cache
  empoisonné suppose d'écrire dans le compte, hors du modèle ; à vider à la main en cas de
  doute.
- **Isolation** : toujours tentée sous Linux pour un contrôle confiné ; `python-tests` est
  `uncontained` (le Python Windows lancé depuis WSL ne démarre pas dans ces espaces).
- **Journal local** : l'ancien `.empreinte-head` est gardé tel quel en
  `.empreinte-head.avant-2026-11-20` (ignoré par Git) ; nouveau journal, dépôt déclaré de
  confiance dans la configuration du compte root de WSL.

## Règles livrées, réévaluées

- `tests-never-reach-network` (réfutée par `cargo-test`, isolation exigée) : enregistrée,
  évaluée deux fois ; la première a échoué (un test lisait `.agents/rules`, absent de
  l'instantané : corrigé), la seconde passe ; état local `evaluated`, fichier `evaluated`.
- `date-proven-only-when-authenticated` (réfutée par `python-tests`) : évaluation
  `incomplete` (non confiné ; de plus 3 tests Node échouent depuis un chemin
  `\\wsl.localhost`) ; reste `candidate`.

## Fichiers

Nouveaux : `rust/src/head/{trust,fsafe,contain,tree}.rs`, `rust/tests/head_audit.rs`,
`rust/tests/common/mod.rs`. Modifiés : `rust/src/head/{mod,checks,rules,tests}.rs`,
`rust/tests/head_lifecycle.rs`, `rust/src/main.rs` (sous-commandes `head` seulement : `trust`,
`register`, contexte de confiance), `.agents/checks.json`, `.agents/rules/*.json`,
`docs/THINKING_HEAD.md`. Fichier partagé : `.gitignore`, une ligne
(`.empreinte-head.*/`). `Cargo.toml`, `lib.rs`, `harness.rs` et `conversations.rs`
inchangés. Ce fichier existait déjà (écrit par une autre session pendant le travail, avec
des inexactitudes) ; il est remplacé.

## Ce qui n'est pas garanti

- **Linux** : qui écrit dans le compte (journal, confiance, cache, `~/.cargo`) peut tout
  forger ; Cargo lit les `.cargo/config.toml` des dossiers parents du cache ; les règles
  d'exclusion de Git du dépôt décident de ce qui entre dans l'empreinte ; un programme
  Windows lancé par WSL n'est jamais confiné.
- **Windows** : non compilé ni testé. Pas d'`openat` (course entre contrôle et ouverture),
  pas d'identité de fichier pour le verrou, pas de confinement ni d'isolation (il
  faudrait un Job Object `KILL_ON_JOB_CLOSE` et un AppContainer ou un pare-feu) : tout y
  serait `incomplete`, rien ne serait certifié.

## Prêt pour un planificateur ?

Oui pour recevoir des propositions comme données : rien de ce qu'un texte contient n'est
exécuté, seul un nom de contrôle de la liste de confiance choisit ce qui tourne, et une
certification exige un résultat confiné sur l'arbre exact. À deux conditions : le
planificateur n'écrit ni dans le journal, ni dans `.agents`, ni dans la liste de
confiance ou le cache (même compte : il faudrait l'exécuter sous un autre utilisateur), et
toute promotion reste une commande humaine.
