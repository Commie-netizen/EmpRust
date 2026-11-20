# Préparation GitHub

Le dépôt Git local existe. Aucun remote n'était configuré lors de cette préparation.
Aucun push, publication ou dépôt GitHub créé par cette tâche.

- Workflow `.github/workflows/rust.yml` : format, tests, build release et test
  CLI/MCP/HTTP local synthétique sur Ubuntu, avec permissions de lecture seules.
- `Cargo.lock` conserve les dépendances résolues ; builds CI avec `--locked`.
- Bases SQLite, journaux de mémoire, `.env` et dossier d'exports sont ignorés.
- README portable avec commandes Rust et guide des formats/intégrations.

Avant publication : choisir le propriétaire/nom, la visibilité et une licence
de distribution ; inspecter l'ensemble du diff et de l'historique. Les notes de
développement contiennent des chemins locaux et ne sont pas anonymisées. Les
modifications Python préexistantes n'ont pas été incluses dans un commit global.
Les exclusions Git ne remplacent pas une revue de contenu déjà suivi.

Le transport MCP est initialement testé au niveau protocole/processus ; les
clients concrets et builds Windows natifs restent à qualifier. Les modules encore
partiels sont documentés dans `docs/CONTEXT.md`, sans promesse de parité complète.
