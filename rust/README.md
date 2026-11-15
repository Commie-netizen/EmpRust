# Empreinte Rust — portage en cours

Moteur natif Rust, sans interpréteur Python à l'exécution. L'interface web française
existante est intégrée dans le binaire à la compilation. **Ce jalon n'est pas encore
un remplacement fonctionnel complet de la version Python.**

## Lancer

Avec Rust/Cargo dans Ubuntu WSL, depuis Windows :

```powershell
wsl -d Ubuntu -- cargo run --manifest-path /mnt/c/Users/sawle/OneDrive/Desktop/ChargeGrinder/Empreinte/rust/Cargo.toml -- demo --port 18766
```

Phrase de passe de démonstration : `demo`. Les données sont fictives et temporaires.
L'adresse locale est affichée ; `Ctrl+C` arrête le serveur et ferme la session.
Pour éviter les fichiers de compilation dans OneDrive, utiliser `--target-dir`
avec un dossier de travail persistant hors OneDrive.

CLI disponible : `init`, `serve`, `import`, `list`, `verify`, `demo`.
Les commandes de coffre demandent la phrase de passe sans l'inscrire dans les arguments.
La création fournit une clé de secours au format v1 ; sa récupération se fait encore
avec la version Python. Les chemins d'import dans WSL sont de forme `/mnt/c/...`.

## Fonctions portées

- Argon2id, AES-256-GCM, HKDF, engagements salés et signatures Ed25519 au format v1.
- Création, ouverture, versions, lecture, retrait logique, stockage auxiliaire chiffré.
- Exclusion des écrivains par verrou système, détection d'une tête modifiée,
  blocage après écriture incertaine ; aucune réparation implicite à l'ouverture.
- Serveur en boucle locale, jetons de page/session, contrôles Host/Origin,
  expiration après 15 minutes, limite de corps et connexions bornées.
- Arborescence, lecture, liens de base, graphe, recherche textuelle, calendrier,
  registre et import manuel. Lecture des licences/redevances existantes.
- Budget UTF-8 de contexte disponible en bibliothèque.

## Écarts restant à porter

- Validation et émission RFC 3161 : capacités désactivées ; aucune date externe
  n'est présentée comme prouvée. `verify` signale qu'il ne peut conclure pour
  une archive comportant des ancres. Aucun service extérieur n'est appelé.
- Création/export de licences, redevances, catalogue public et surveillance continue.
- Appels au modèle, aperçus, approbation et politique de cache.
- Récupération après incident, rotation de phrase de passe/clé de secours.
- Parité du parseur (frontmatter/alias), classement BM25, mentions historiques,
  statistiques détaillées et résolution Unicode des liens.
- Compilation et tests natifs Windows : cette validation cible Linux/WSL.

Ne pas ouvrir le même coffre simultanément depuis Windows et WSL : l'interopérabilité
des verrous entre ces environnements n'est pas validée. Tester sur une copie ; conserver
la version Python pour les fonctions non migrées. Les plafonds actuels sont de 128 Mio
par fichier interne et 32 Mio par document importé. L'import signale les changements
de taille/date pendant la lecture mais ne fournit pas une photographie atomique du disque.

## Tests

```sh
cargo test --all-targets
cargo fmt --check
cargo build --examples
```

Depuis la racine Python avec ses dépendances installées :

```sh
python tools/test_rust_interop.py --driver /chemin/absolu/target/debug/examples/interop
```

Sous Windows, le script exécute le pilote dans Ubuntu WSL. Il crée exclusivement des
coffres jetables : Python → Rust → Python et Rust → Python, documents Unicode,
versions, engagements, signatures, licences/redevances existantes et données auxiliaires.
Le pilote de test utilise des identifiants publics et un KDF allégé ; il n'est pas une CLI utilisateur.
