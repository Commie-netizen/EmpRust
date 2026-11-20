# Relecture et consolidation Rust — 15 novembre 2026

Périmètre : mémoire commune, harness utilisateur, persistance et reprise ; analyse
statique du crate entier. Cette passe ne certifie pas la sécurité du produit et ne
déclare pas la parité fonctionnelle Python complète.

## Défauts corrigés et fonctions complétées

- Mémoire chiffrable via SQLCipher, clé par variable d'environnement nommée,
  temporaire SQLite en mémoire. Tests de mauvais mot de passe, absence de marqueur
  privé dans le fichier et le WAL, réouverture et recherche.
- Migration par copie chiffrée complète, sans écrasement de destination ni suppression
  de la source ; profils et plans conservés, testés.
- Verrou système partagé par import, préparation, exécution, copie et oubli. Empêche
  une suppression/import simultané pendant l'envoi d'une requête approuvée.
- `memory recover` ne récupère que lorsqu'aucun exécuteur coopérant ne détient ce
  verrou : états abandonnés marqués `interrupted`, sans répétition d'un appel.
- Oubli limité aux plans qui référencent les extraits concernés ; les plans sans
  lien restent conservés. Les extraits partagés gardent leurs autres provenances.
- Schéma 2 : table des messages, conservation de l'ordre de première ingestion et
  des messages vides. Migration v1 testée ; ordre historique absent non inventé.
- Index des références par chunk, pour éviter les parcours complets sur chaque
  recherche/purge. Journal `head` bloqué après écriture incertaine jusqu'à réouverture.
- Corrections Clippy du crate et des exemples ; vérification stricte ajoutée en CI.

## Validation

- `cargo test --locked --all-targets` : **42 réussites**.
- `cargo clippy --all-targets -- -D warnings` : aucune erreur/aucun avertissement.
- Build `--release --locked` réussi ; parcours CLI/MCP/HTTP/chiffrement également
  validé sur `/root/empreinte-target/release/empreinte` (Ubuntu WSL).
- `tools/test_memory_cli.py` : CLI, MCP, modèle HTTP factice, approbation unique,
  feedback, retour de profil, oubli et copie chiffrée réussis.
- `tools/test_rust_interop.py` : Python → Rust → Python et Rust → Python réussis,
  incluant un bundle Rust validé par le vérificateur Python.
- Données synthétiques exclusivement ; aucun appel cloud réel, aucun coffre personnel
  créé et aucun import du Wiki.

## Limites et prochains travaux

- Chiffrement opt-in : les bases sans clé restent en clair, ainsi que les exports
  et réponses d'outils. Les anciennes sources/sauvegardes ne sont pas effacées.
- Clé d'environnement plutôt que trousseau système ; isolation multi-utilisateur
  et durcissement contre un programme malveillant du même compte non réalisés.
- Les verrous supposent que les clients passent par le harness ; les outils SQLite
  externes peuvent contourner les règles. Les suppressions physiques sur disque,
  sauvegardes ou chez les fournisseurs ne sont pas garanties.
- Annulation limitée aux plans préparés, pas d'arrêt réseau déjà lancé. Les appels
  incertains ne sont pas automatiquement réessayés.
- Agent général multi-étapes, exécuteurs isolés, intégrations catalogue/watch au
  serveur, modèle d'aperçus et preuve TSA authentifiée restent des chantiers distincts.
- Validation Linux/WSL. Build et tests Windows natifs non effectués.

Référence de compilation SQLCipher :
[rusqlite 0.32.1](https://docs.rs/crate/rusqlite/0.32.1).
