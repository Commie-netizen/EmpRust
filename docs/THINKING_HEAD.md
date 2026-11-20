# Tête pensante — proposition v0.1

Statut : journal, évaluateur et cycle de vie des règles implémentés (étapes 1 à 3), puis
corrigés après l'audit du 16 novembre (`docs/reviews/2026-11-16-audit-tete-pensante.md`,
corrections dans `docs/reviews/2026-11-20-tete-corrections.md`), 20 novembre 2026. Aucun
agent autonome, aucun planificateur, aucun apprentissage automatique : chaque mouvement
est une commande lancée par une personne.

## Intention

### Prototype disponible

Code : `rust/src/head/` : `mod.rs` (journal), `trust.rs` (dépôts de confiance),
`fsafe.rs` (ouverture sans suivre de lien), `checks.rs` (évaluateur), `contain.rs`
(confinement des processus), `tree.rs` (empreinte et instantané), `rules.rs` (règles).
Tests : `rust/src/head/tests.rs` (sans processus lancé), `rust/tests/head_lifecycle.rs` et
`rust/tests/head_audit.rs` (contrôles, git et règles, dans des binaires de test à part).
Commandes, toutes sous `empreinte head [--repo <dépôt>] [--memory <dossier>]` :
`trust <chemin> [--confirm]`, `status`, `recall "Rust"`, `record evenement.json`,
`propose-rule regle.json`, `repair`, `checks`, `check <tâche> <contrôle>`, `rules`,
`register <règle>`, `evaluate <règle>`, `promote <règle>`, `rollback <règle>`,
`retire <règle>`, `compare <a> <b>`. Le journal est par défaut `<dépôt>/.empreinte-head/`
(ignoré par Git).

**Confiance.** L'outil ne lit `.agents` et ne lance rien que dans un dépôt que la personne
a explicitement déclaré de confiance. La liste est hors de tout dépôt :
`~/.config/empreinte/trusted-repos.json` (Unix, dossier personnel lu dans la base des
comptes, pas dans l'environnement ; sous Windows, `%APPDATA%\Empreinte`). `head trust
<chemin>` montre la racine, le contenu de la liste de contrôles et les fichiers de règles ;
seul `--confirm` l'enregistre, avec l'empreinte de `.agents/checks.json`. Un `.git`
trouvé ne suffit jamais : une commande utilise l'ancêtre de confiance le plus proche du
dossier courant, ou refuse en disant comment faire confiance. Si la liste de contrôles
change, plus rien ne tourne avant une nouvelle confiance. `.git` doit être un dossier
ordinaire. `.agents`, `.agents/rules` et les fichiers qu'ils contiennent sont ouverts sous
le descripteur du dossier déjà ouvert, sans suivre de lien (`openat` avec `O_NOFOLLOW`) :
un lien à n'importe quel niveau est refusé.

**Journal.** `events.jsonl`, en ajout seul, en clair : outil de développement, sans
document personnel. Chaque événement du schéma 2 porte `schema_version`, `timestamp`
(écrit par l'outil) et `supersedes` facultatif. Les événements plus anciens restent
lisibles, marqués `legacy`, jamais réécrits. Le verrou d'écrivain est `events.lock`,
jamais écrit, refusé s'il est un lien ; avant chaque écriture, l'outil vérifie (Unix) que
le verrou et le journal sont toujours les fichiers qu'il a ouverts : un verrou ou un
journal remplacé par un autre processus arrête l'écriture. Un journal lié ou à plusieurs
noms est refusé.

**Lignes invalides.** Une ligne illisible, invalide, de plus de 256 Kio ou incomplète est
écartée : `status` et `recall` fonctionnent sur les lignes valides et disent combien de
lignes sont écartées et où. Avant toute écriture, une dernière ligne sans fin de ligne
est scellée par le suffixe `~torn` : aucun analyseur JSON ne l'accepte, elle ne peut donc
jamais devenir valide plus tard. `repair` est la seule opération autre qu'un ajout : il
copie les lignes écartées dans `events.quarantine.jsonl`, écrit le nouveau journal, puis
enregistre son intention (`repair-intent.json`) avant d'échanger les fichiers, en
synchronisant le dossier. Si `events.jsonl` manque alors qu'une réparation a laissé une
trace, l'outil refuse de créer un journal vide et dit comment remettre la sauvegarde.

**Sources.** Une source doit être un fichier ordinaire d'au plus 1 Mio situé dans le
dépôt après résolution des liens ; elle est enregistrée relative à la racine avec son
SHA-256. Les anciens chemins absolus hors du dépôt sont montrés `<hors du dépôt>`, jamais
relus. `recall` ne relit que les sources des résultats retenus.

**Recherche.** Lexicale, sur les résumés, plafond de 12 000 octets pour les
enregistrements retenus. Tout texte est marqué données non fiables. Chaque vérification
et chaque résultat de contrôle retourné porte son état effectif (`effective`) :
`verified` ou `verified-stale`, `certifies` ou `does-not-certify`, avec les raisons.

**Évaluateur.** `.agents/checks.json` (version 2) liste les contrôles autorisés. Le
programme est nommé par un chemin absolu ; un nom nu ou relatif est refusé, aucun chemin
de recherche n'est consulté. Les arguments sont un vecteur, sans shell. Seul le nom du
contrôle vient de la ligne de commande. L'environnement est construit, jamais hérité :
`PATH=/usr/local/bin:/usr/bin:/bin`, `HOME=<cache>/home` (dossier privé de l'outil),
`CARGO_HOME=<dossier personnel>/.cargo`, `RUSTUP_HOME=<dossier personnel>/.rustup`,
`LANG=C.UTF-8`, `PYTHONDONTWRITEBYTECODE=1`, plus les variables que l'entrée liste avec
leur valeur (`@cache` et `@home` y désignent le cache de l'outil et le dossier personnel).
`<cache>` est `~/.cache/empreinte/head` (Unix). Chaque résultat enregistre le chemin du
programme, le SHA-256 de son contenu et le SHA-256 de toute la configuration d'exécution
(arguments, dossier, environnement, bornes, isolation, fichiers de configuration de Cargo
sous `CARGO_HOME`) : un changement de l'un ou de l'autre rend le résultat périmé.

**Instantané.** Les entrées d'un contrôle sont les fichiers suivis par Git et les fichiers
non suivis non ignorés, hors `.agents/rules/` et `.empreinte-head/`. Git ne sert qu'à les
lister (`ls-files`), confiné comme un contrôle, configuration système et globale
désactivée, `core.fsmonitor`, `core.hooksPath` et `core.pager` neutralisés en ligne de
commande, `--git-dir` et `--work-tree` explicites ; `ls-files` ne lance ni diff, ni
conversion de texte, ni filtre, ni assistant d'identifiants. L'outil lit et hache lui-même
chaque fichier. Les fichiers sont copiés, en lecture seule, dans un instantané privé sous
`<cache>/snapshots`, et l'empreinte est calculée sur les octets écrits. Le contrôle tourne
dans l'instantané ; s'il le modifie, son résultat est incomplet. Si la liste ou la lecture
échoue (git absent, en échec, hors délai, sortie tronquée), rien n'est certifié : le
résultat est incomplet. Le cache de compilation de Cargo est `<cache>/cargo-target`
(variable `CARGO_TARGET_DIR` de l'entrée), hors de l'instantané.

**Confinement.** Sous Linux, un contrôle tourne dans de nouveaux espaces de noms
utilisateur, réseau et processus, créés sans privilège. Un gardien hors de l'espace des
processus devient « subreaper » et lance le programme, qui est le PID 1 de cet espace et
meurt avec le gardien. Quand il s'arrête, le noyau tue tout ce qui reste dans l'espace,
`setsid` compris ; le gardien les récupère tous et rapporte le statut et la confirmation
du nettoyage. Au délai, le gardien tue le PID 1. L'espace réseau n'a que sa propre
interface de bouclage. Un contrôle n'est `passed` que s'il est sorti avec 0 dans son délai,
que sa sortie a été lue entièrement dans sa borne, que le confinement et le nettoyage sont
confirmés, que l'instantané est intact et, s'il l'exige (`requires_isolation`), que le
réseau était isolé. Une sortie non nulle dans ces conditions est `failed` ; tout le reste
est `incomplete`. Une entrée `uncontained` (programme Windows lancé depuis WSL, qui ne peut
pas tourner dans ces espaces) tourne sans confinement : son résultat est toujours
`incomplete` et ne certifie rien.

**verified.** Une tâche n'est `verified` que si l'événement cite un résultat `passed` écrit
par l'outil pour cette tâche, dont l'instantané a l'empreinte de l'arbre de travail au
moment de l'enregistrement, avec la même liste de contrôles, le même programme et la même
configuration d'exécution. Une affirmation libre s'enregistre comme `declared`. `status`
et `recall` affichent `verified-stale`, avec les raisons, dès que l'un de ces éléments
change. Une tâche `verified` d'un ancien journal est affichée `declared`, `legacy`.

**Règles.** Fichiers `.agents/rules/<id>.json` : `version`, `id` (le nom du fichier),
`statement`, `scope`, `origin`, `refuted_by` (de un à huit contrôles de la liste
autorisée), `replaces` facultatif, `state`. Tout autre champ, un lien, plus de 16 Kio :
refusé, sans masquer les autres. Le texte d'une règle est une donnée. Une règle entre au
journal par `head register`, toujours comme candidate : si le fichier dit plus (evaluated,
active, retired, dans une copie fraîche du dépôt qui n'a pas de journal), `register` le
remet à candidate dans le même mouvement enregistré ; l'affirmation n'est jamais crue et
une nouvelle évaluation est nécessaire. Mouvements : candidate vers
evaluated (évaluation certifiante), evaluated vers active (`promote`), active vers
evaluated (`rollback`), vers retired (`retire`). Chaque mouvement est un événement `rule`
écrit par l'outil avec les empreintes avant et après et le texte d'avant. `evaluate` lance
les contrôles réfutants et n'est certifiante que si tous sont `passed` sur un même
instantané. `promote` exige que la dernière évaluation certifie l'état actuel et la cite
comme preuve ; la relecture vérifie que cette évaluation existe, précède la promotion, est
la dernière de la règle, porte sur le même contenu et a réussi, sinon l'événement est
écarté. Un mouvement qui modifie des fichiers enregistre d'abord son intention
(`rule-transaction.json`) ; à l'ouverture suivante, l'outil l'achève (fichiers écrits,
événement manquant) ou l'annule (il ne remet que les fichiers qu'il avait écrits) ; si un
fichier est dans un troisième état, les écritures sont refusées jusqu'à ce qu'une personne
décide. `rollback` remet les fichiers octet pour octet. `compare` rapporte et ne décide
rien.

**Ce que signifie active.** Une règle active est listée par `status` et `recall`, marquée
données non fiables, avec l'état de son évaluation : `active` si elle certifie encore
l'état actuel, `active-stale` sinon. Rien ne consomme ni n'applique une règle : active ne
veut pas dire appliquée. Une règle ne cite que des contrôles déjà autorisés.

**Règles livrées.** `date-proven-only-when-authenticated` (réfutée par `python-tests`,
qui sous WSL ne peut pas être confiné : elle reste candidate) et
`tests-never-reach-network` (réfutée par `cargo-test`, qui exige l'isolation réseau :
évaluée le 20 novembre dans le journal local de cette machine). Ni l'une ni l'autre n'est
active : la promotion revient au propriétaire.

### Modèle de confiance

L'outil suppose que la personne qui le lance est celle qui décide : son compte, son
dossier personnel, sa configuration de Cargo (`~/.cargo`) et le cache de l'outil sont à
elle et ne sont écrits par personne d'autre. Il suppose que le dépôt qu'elle a déclaré de
confiance, et sa liste de contrôles telle qu'elle l'a relue, contiennent ce qu'elle veut
exécuter ; les règles d'exclusion de Git du dépôt décident de ce qui entre dans
l'empreinte. Il suppose une machine saine : noyau, programmes du système (`/usr/bin/git`,
`/usr/bin/cargo`) et WSL non compromis.

Il défend contre : un dépôt non déclaré (y compris un sous-dossier avec un faux `.git`),
une liste de contrôles modifiée après la confiance, l'environnement de l'appelant (PATH,
HOME, CARGO_HOME), un programme ou une configuration d'exécution changés, une
configuration Git qui lancerait un assistant, un arbre modifié pendant ou après un
contrôle, un descendant qui fuit, une sortie tronquée, un accès réseau d'un contrôle qui
exige l'isolation (Linux), une ligne de journal coupée, un mouvement interrompu, un texte
de règle ou d'événement qui donnerait un ordre.

Il ne défend pas contre : quelqu'un qui peut écrire dans le dossier du journal, la liste
de confiance ou le cache (il peut forger le journal, une confiance ou un instantané) ; un
programme hostile du même compte ; la configuration personnelle de la personne (les
`.cargo/config.toml` des dossiers parents du cache sont lus par Cargo) ; un cache de
compilation empoisonné par quelqu'un qui peut l'écrire (il est privé, 0700, à supprimer
à la main en cas de doute : `~/.cache/empreinte/head/cargo-target`) ; ce que les tests
d'un dépôt de confiance font de leur plein gré dans leur espace (fichiers temporaires,
dossier personnel privé) ; Windows, où rien de ce confinement n'existe.

Limites explicites : le journal en clair n'est pas infalsifiable. Les règles sont
indicatives tant que rien ne les consomme. Ce n'est pas un planificateur. Pas d'index ni
de cache de recherche ; pas de seuils de promotion chiffrés. Sous Windows, non compilé ni
testé : pas d'`openat` (contrôles de lien par chemin, une course reste possible), pas
d'identité de fichier pour le verrou, pas de confinement (il faudrait un Job Object avec
`KILL_ON_JOB_CLOSE` pour les descendants et un AppContainer ou un pare-feu pour le réseau) :
tout résultat y serait `incomplete` et rien n'y serait certifié. Les chemins de la
confiance et du cache y viennent de l'environnement.
Validation : 95 tests Rust passent sous WSL le 20 novembre (`cargo test --all-targets`), dont 54 pour la
tête (19 dans `rust/src/head/tests.rs`, 20 dans `rust/tests/head_audit.rs`, 15 dans
`rust/tests/head_lifecycle.rs`).

### Critères d'acceptation, état

1. Reprise sans doubler une tâche ni annoncer un faux succès : fait (`verified` exige un
   contrôle `passed` sur l'arbre actuel).
2. Récupération déterministe, plafond UTF-8, chaque source citée, état effectif : fait.
3. Invalidation lorsque la source change : l'état `changed` est recalculé ; pas de cache.
4. Événement mal formé rejeté, pas d'écriture concurrente : fait ; une ligne invalide ne
   bloque pas le journal et ne devient jamais valide.
5. Proposition de règle incapable d'accorder un outil ou une permission : fait.
6. Retour à une politique précédente sans perte de mémoire : fait pour les règles ; pas
   d'index à reconstruire.

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
