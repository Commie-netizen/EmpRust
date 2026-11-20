# Tête pensante — proposition v0.1

Statut : journal durci, évaluateur et cycle de vie des règles implémentés (étapes 1 à 3),
16 novembre 2026. Aucun agent autonome, aucun planificateur, aucun apprentissage
automatique : chaque mouvement est une commande lancée par une personne.

## Intention

### Prototype disponible

Code : `rust/src/head/mod.rs` (journal), `rust/src/head/checks.rs` (évaluateur),
`rust/src/head/rules.rs` (règles), tests dans `rust/src/head/tests.rs` (sans processus
lancé) et `rust/tests/head_lifecycle.rs` (contrôles, git et règles, dans un binaire de
test à part : un processus lancé pendant qu'un test d'un autre module tient un verrou
rendait ce verrou momentanément occupé). Commandes, toutes sous
`empreinte head [--repo <dépôt>] [--memory <dossier>]` :
`status`, `recall "Rust"`, `record evenement.json`, `propose-rule regle.json`,
`repair`, `checks`, `check <tâche> <contrôle>`, `rules`, `evaluate <règle>`,
`promote <règle>`, `rollback <règle>`, `retire <règle>`, `compare <a> <b>`. Le dépôt est par défaut le dépôt Git
qui contient le dossier courant ; le journal, `<dépôt>/.empreinte-head/` (ignoré par Git).

Exemple d'entrée (champs permis : event_id, task_id, kind, summary, source_refs,
evidence_refs, supersedes ; tout autre champ, horodatage, empreintes, résultat de
contrôle, commande ou permission, rend l'entrée invalide) :

```json
{"event_id":"task1-proposed","task_id":"task1","kind":"proposed","summary":"Ajouter la mémoire Rust","source_refs":["rust/src/head/mod.rs"],"evidence_refs":[]}
```

**Journal.** `events.jsonl`, en ajout seul, en clair : outil de développement, sans
document personnel. Chaque événement du schéma 2 porte `schema_version`, `timestamp`
(écrit par l'outil) et `supersedes` facultatif (un événement antérieur de la même
tâche). Les événements plus anciens, sans `schema_version`, restent lisibles et sont
marqués `legacy` ; ils ne sont jamais réécrits. Le verrou d'écrivain est un fichier
séparé, `events.lock`, jamais écrit (il ne peut rien tronquer), refusé s'il est un lien
ou n'est pas un fichier ordinaire, relâché à chaque échec ; une attente d'une seconde
au plus, puis refus. Le journal lié, ou à plusieurs noms (lien physique, contrôlé sous
Unix), est refusé.

**Lignes invalides.** Une ligne illisible, invalide, de plus de 256 Kio ou incomplète
(écriture interrompue) est écartée : `status` et `recall` fonctionnent sur les lignes
valides et indiquent combien de lignes sont écartées et leurs numéros. L'ajout suivant
commence sur une nouvelle ligne, la ligne incomplète reste telle quelle. `repair` est
la seule opération autre qu'un ajout : elle copie les lignes écartées, avec numéro,
raison et contenu brut, dans `events.quarantine.jsonl`, garde l'ancien journal entier
sous `events.before-repair-<date>.jsonl` et réécrit `events.jsonl` avec les lignes
valides, octet pour octet. Pour annuler : remettre la sauvegarde à la place du journal.
Le journal accepte des ajouts jusqu'à 16 Mio ; au-delà ils sont refusés, la lecture
reste possible.

**Sources.** Une source doit être un fichier ordinaire d'au plus 1 Mio situé dans le
dépôt après résolution des liens ; un lien final est refusé. Elle est enregistrée
relative à la racine du dépôt avec son SHA-256 : le journal ne contient ni nom
d'utilisateur, ni chemin extérieur, ni empreinte d'un fichier hors du dépôt. Les
anciens chemins absolus restent dans le fichier : `recall` les montre relatifs s'ils
sont dans le dépôt, sinon remplacés par `<hors du dépôt>` avec l'état `outside`, sans
relire le fichier. `recall` ne relit que les sources des résultats retenus dans le
budget et renvoie `current`, `changed`, `unavailable`, `untracked` ou `outside`.

**Recherche.** Lexicale, sur les résumés, plafond de 12 000 octets pour les
enregistrements JSON retenus, hors enveloppe. La sortie déclare les textes comme
données non fiables (`trust`, et `untrusted` sur chaque enregistrement).

**Évaluateur.** `.agents/checks.json`, versionné dans le dépôt, liste les contrôles
autorisés : nom, commande en vecteur d'arguments par plateforme (`unix`, `windows`),
répertoire de travail dans le dépôt, délai (1 à 7200 s), borne de sortie facultative.
Aucun shell n'est invoqué par l'outil. Seul le nom du contrôle vient de la ligne de
commande ; rien d'un enregistrement, d'une règle ou d'un texte retrouvé ne choisit le
programme, un argument, le répertoire ou l'environnement. L'environnement du contrôle
est vidé puis limité à une liste fixe de variables (`PASSTHROUGH` dans checks.rs).
Au délai, tout le groupe de processus est tué sous Unix. `check` écrit lui-même un
événement `check` : code de sortie, durée, empreinte de la sortie (jamais la sortie),
empreinte du fichier de contrôles et révision du dépôt (HEAD, arbre modifié ou non,
empreinte de `git status` et `git diff HEAD`). Le verrou du journal est relâché pendant
le contrôle. Contrôles livrés : `cargo-test` (`cargo test --offline --locked`) et
`python-tests` (pytest ; `tests/conftest.py` bloque tout accès réseau, coffres de test
temporaires).

**verified.** Une tâche n'est `verified` que si l'événement cite dans `evidence_refs`
un contrôle réussi écrit par l'outil pour cette tâche et encore à jour au moment de
l'enregistrement. Une affirmation libre s'enregistre comme `declared` et n'apparaît
jamais comme vérifiée. `status` affiche `verified-stale`, avec les raisons, dès que le
fichier de contrôles, la révision ou l'arbre de travail ont changé depuis le résultat.
Une tâche `verified` d'un ancien journal (sans contrôle) est affichée `declared` avec
`legacy`. Une tâche `running` s'affiche `interrupted` entre deux commandes, sans
réécrire l'événement. `propose-rule` reste une simple note `candidate` dans le
journal ; les règles versionnées sont décrites ci-dessous.

**Règles.** Une règle est un fichier `.agents/rules/<id>.json` : `version`, `id` (égal
au nom du fichier), `statement`, `scope` et `origin` (texte), `refuted_by` (un à huit
noms de contrôles, qui doivent exister dans `.agents/checks.json`), `replaces`
facultatif (la règle qu'elle remplacerait) et `state`. Tout autre champ (commande,
argument, chemin à lancer, variable d'environnement, permission) rend le fichier
invalide ; de même un lien, un fichier de plus de 16 Kio ou hors de ce dossier. Un
fichier invalide est signalé sans masquer les autres. Le texte d'une règle est une
donnée : rien n'en est exécuté ni lu comme une instruction ; une évaluation ne lance
que les contrôles nommés, avec les commandes, l'isolation et les délais de la liste.

États et seuls mouvements : candidate vers evaluated (évaluation réussie), evaluated
vers active (`promote`), active vers evaluated (`rollback`, qui annule la dernière
promotion), candidate, evaluated ou active vers retired (`retire`). Chaque mouvement
est un événement `rule` écrit par l'outil avec les empreintes des fichiers avant et
après et le texte exact d'avant ; le journal seul redonne l'état de chaque règle, et
un fichier en désaccord avec lui (état ou contenu modifié hors de l'outil, fichier
absent) est signalé par `rules` et `status` et bloque tout mouvement de cette règle.
Un événement `rule` incohérent avec ce qui précède est écarté à la relecture. L'outil
réécrit le fichier sous forme canonique (clés triées) quand il change son état.

`evaluate` lance les contrôles réfutants et enregistre, par contrôle, réussite, code,
durée et empreinte de sortie, avec l'empreinte du fichier de contrôles et la révision
du dépôt. L'évaluation est liée au contenu exact de la règle (empreinte sans l'état)
et à l'état du dépôt : elle est périmée dès que la règle, le fichier de contrôles,
HEAD ou l'arbre de travail changent. Les fichiers de `.agents/rules` sont exclus de
l'empreinte de l'arbre, pour qu'un changement d'état ne périme pas l'évaluation. Une
évaluation échouée est enregistrée et ne change pas l'état. `promote` exige une
évaluation réussie et à jour de ce contenu exact, retire dans le même mouvement la
règle remplacée si elle est active, et garde le verrou du journal du début à la fin :
deux promotions concurrentes ne peuvent pas réussir toutes les deux. `rollback`
remet chaque fichier modifié par la promotion octet pour octet, si personne ne l'a
changé depuis. `compare` met côte à côte les mesures de deux règles (contrôles
réussis, échecs, durée totale, péremption) et les octets qu'une règle active ajoute
à `status` et `recall` ; il ne décide rien et ne promeut rien.

**Ce que signifie active.** Une règle active est listée par `status` et `recall`
(marquée données non fiables) pour qu'une personne ou un assistant qui commence un
travail la lise. Rien ne consomme ni n'applique une règle automatiquement : active ne
veut pas dire appliquée. Aucune règle ne peut élargir une permission : elle ne peut
citer que des contrôles déjà autorisés.

Règles livrées, tirées de l'histoire du projet : `date-proven-only-when-authenticated`
(réfutée par `python-tests` ; le moteur Rust est hors de sa portée faute de test qui le
réfute) et `tests-never-reach-network` (`python-tests` et `cargo-test`). Elles ont été
évaluées avec les vrais contrôles sous WSL et laissées à l'état evaluated : la
promotion revient au propriétaire.

Limites explicites : le journal en clair n'est pas infalsifiable (un fichier modifié à
la main peut contenir un faux résultat de contrôle ou un faux mouvement de règle
cohérent ; aucune chaîne de hachage) ; il ne doit contenir aucun secret, ce qui n'est
pas contrôlé. Les règles sont indicatives tant que rien ne les consomme. Ce n'est pas
un planificateur : rien ne propose, ne choisit ni ne lance un travail de lui-même.
Pas encore d'index ni de cache ; pas de seuils de promotion chiffrés (`compare`
rapporte, une personne décide). L'empreinte de l'arbre de travail couvre les fichiers
suivis par Git (`git status` et `git diff HEAD`) ; d'un fichier non suivi, elle ne
voit que le nom : modifier un fichier non suivi ne périme ni un résultat ni une
évaluation tant qu'il n'est pas ajouté à Git.
Sous Windows : pas d'ouverture sans suivi de lien (`O_NOFOLLOW`), donc les contrôles
de lien et de taille d'une source se font avant l'ouverture et une course reste
possible ; le nombre de liens physiques du journal n'est pas contrôlé ; au délai, seul
le processus direct du contrôle est tué, pas ses descendants. Le binaire n'a pas été
compilé ni testé sous Windows : validation Linux/WSL uniquement.
Validation : 72 tests Rust passent (`cargo test --all-targets`), dont 33 pour la tête
(15 dans `rust/src/head/tests.rs`, 18 dans `rust/tests/head_lifecycle.rs`). Les deux
contrôles livrés ont été lancés par `head check` et `head evaluate` sous WSL sur ce
dépôt et réussissent.

### Critères d'acceptation, état

1. Reprise sans doubler une tâche ni annoncer un faux succès : fait (doublons refusés,
   `verified` exige un contrôle réel ; tests `free_text_never_verifies`,
   `a_passing_check_run_by_the_tool_verifies_and_goes_stale_when_checks_change`).
2. Récupération déterministe, plafond UTF-8, chaque source citée : fait.
3. Invalidation lorsque la source change : l'état `changed` est recalculé ; pas de cache.
4. Événement mal formé rejeté, pas d'écriture concurrente : fait, et une ligne invalide
   ne bloque plus le journal.
5. Proposition de règle incapable d'accorder un outil ou une permission : fait.
6. Retour à une politique précédente sans perte de mémoire : fait pour les règles
   (`promote_then_rollback_gives_back_identical_files_and_state`,
   `the_journal_alone_rebuilds_every_state_and_mismatches_are_reported`). Il n'y a
   pas d'index à reconstruire : la recherche relit le journal.

Conformément aux notes de reprise, commencer par le harness de développement
d'Empreinte : aider Claude et Codex à reprendre, choisir une prochaine tâche,
vérifier le résultat et conserver les enseignements utiles. Le moteur sera Rust,
indépendant d'Obsidian. Une future assistance sur les documents personnels aura
un espace mémoire distinct ; elle ne sera pas mélangée aux règles du développeur.

Évoluer signifie améliorer une mémoire, des règles et des stratégies versionnées
à partir de résultats observés. Cela ne suppose ni modification des poids d'un
modèle ni autorisation générale de modifier son propre code.

## Boucle de fonctionnement

1. Observer : demande utilisateur, état Git, résultats de tests et références utiles.
2. Récupérer : assembler un contexte borné avec provenance et révision des sources.
3. Proposer : objectif concret, fichiers concernés, critère de réussite, coût estimé.
4. Exécuter : utiliser seulement les outils et actions autorisés pour cette tâche.
5. Vérifier : tests pertinents et comparaison avec le critère fixé avant l'exécution.
6. Retenir : enregistrer résultat et décision succincte ; proposer une leçon réutilisable.

Le raisonnement privé des modèles n'est pas stocké. La mémoire contient des faits,
des décisions justifiées brièvement et des preuves consultables.

## Composants Rust proposés

| Composant | Responsabilité | Sortie vérifiable |
|---|---|---|
| `head/state.rs` | État des tâches et transitions | tâche, statut, résultat |
| `head/memory.rs` | Journal local et index reconstruisible | événements versionnés |
| `head/retrieve.rs` | Recherche lexicale, fraîcheur, sélection | références et extraits bornés |
| `head/policy.rs` | Contraintes de l'utilisateur et capacités | action permise ou raison du refus |
| `head/planner.rs` | Adaptateur optionnel vers un modèle local | proposition structurée |
| `head/evaluate.rs` | Exécuter les contrôles et mesurer | preuves, durée, coût, régressions |
| `head/evolve.rs` | Comparer une règle candidate à la règle active | garder, rejeter ou revenir |

Le planificateur propose ; le moteur déterministe valide les transitions et
les capacités. Un texte récupéré dans le corpus reste une donnée, jamais une
instruction donnant de nouvelles permissions.

## Mémoire et coût de contexte

- `AGENTS.md` : futur index court, inférieur à 100 lignes ; règles chargées à la demande.
- `.agents/rules/` : règles stables, chacune avec portée, origine et contrôle associé.
- `.empreinte-head/events.jsonl` : journal local append-only des tâches et décisions.
- `.empreinte-head/index/` : cache dérivé, supprimable et reconstructible.
- `docs/CONTEXT.md` : point de reprise humain compact partagé avec Claude.

Schéma d'événement : `schema_version`, `event_id`, `task_id`, `kind`, `timestamp`,
`source_refs` (chemin + hash), `summary`, `evidence_refs`, `supersedes`.
États de tâche : `proposed → running → verified | failed | blocked | cancelled`.
Après interruption, une tâche `running` devient `interrupted`, jamais `verified`.

Premier budget proposé : 12 000 octets UTF-8 pour les extraits récupérés, avec
troncature explicite. Mesurer séparément les tokens si le modèle fournit un
tokenizer ; ne pas confondre octets et tokens. Charger l'index et les références
avant les documents ; ne jamais relire l'historique entier pour une reprise.
Clé de cache : requête normalisée + hashes des sources + version de politique.
Une source modifiée invalide ses extraits et les décisions qui en dépendent
sont marquées à revoir. Une synthèse conserve les liens vers ses événements.

Les données personnelles restent dans le stockage chiffré du coffre. Le journal
de développement ne contient pas d'extraits privés, de clés ni de mots de passe.
Le journal possède un verrou d'écrivain ; un événement incomplet après crash
est signalé et isolé avant toute reprise, sans suppression silencieuse de preuve.

## Évolution contrôlée

Une leçon passe par `candidate → evaluated → active → retired`.
Elle indique le problème observé, la règle proposée, les cas de validité et
les tests qui peuvent la réfuter. Une réussite unique ne crée pas une règle globale.

Évaluer les candidates sur des scénarios fixes et sur des cas nouveaux conservés
à part. Comparer réussite, erreurs, octets/tokens chargés, durée et interventions
humaines. Réduire les tokens ne suffit pas si la qualité baisse. Les seuils de
promotion seront fixés après une mesure initiale, avant les essais de candidates.

Toute promotion est un changement versionné et réversible. Au premier jalon,
elle reste une proposition présentée au développeur. Les préférences explicites
de l'utilisateur priment ; aucune candidate ne peut élargir ses permissions.
Les modifications de code suivent le processus normal de développement et de tests.
Le nettoyage compacte les index et archive les leçons obsolètes ; il ne détruit
pas automatiquement les sources ou les décisions historiques.

## Première tranche à implémenter

CLI locale sans modèle : `head status`, `head recall <requête>`,
`head record <fichier-json>`, `head propose-rule <fichier-json>`.
Commencer avec des fixtures publiques de développement ; aucun scan automatique
du Wiki. Le modèle local sera un adaptateur ajouté après validation du stockage.

Critères d'acceptation :

1. Reprise après interruption sans doubler une tâche ou annoncer un faux succès.
2. Récupération déterministe respectant le plafond UTF-8 et citant chaque source.
3. Invalidation du cache lorsque la source change.
4. Rejet d'un événement mal formé et absence de modification concurrente du journal.
5. Proposition de règle incapable d'accorder un outil ou une permission.
6. Reconstruction de l'index et retour à une politique précédente sans perte de mémoire.

Ensuite : adaptateur de modèle local, banc d'évaluation, puis propositions
d'amélioration. Le branchement aux documents personnels est une phase séparée.
