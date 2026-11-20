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
avec `recover-access` en Rust. Les chemins d'import dans WSL sont de forme `/mnt/c/...`.

Gestion des accès (phrases et clés demandées sans les inscrire dans les arguments) :

```sh
empreinte change-passphrase /chemin/coffre
empreinte recover-access /chemin/coffre
empreinte rotate-recovery-key /chemin/coffre
```

Ces opérations réenveloppent la clé maître ; contenu, identité et registre restent
inchangés. La récupération d'accès ne répare pas un registre endommagé. La rotation
invalide l'ancienne clé pour le coffre actuel, pas pour ses anciennes sauvegardes.

## Fonctions portées

- Argon2id, AES-256-GCM, HKDF, engagements salés et signatures Ed25519 au format v1.
- Création, ouverture, versions, lecture, retrait logique, stockage auxiliaire chiffré.
- Exclusion des écrivains par verrou système, détection d'une tête modifiée,
  blocage après écriture incertaine ; aucune réparation implicite à l'ouverture.
- Serveur en boucle locale, jetons de page/session, contrôles Host/Origin,
  expiration après 15 minutes, limite de corps et connexions bornées.
- Arborescence, lecture, liens de base, graphe, recherche textuelle, calendrier,
  registre et import manuel. Création et lecture des licences/redevances.
- Export sélectif signé des versions licenciées, dans un dossier voisin
  `<nom-du-coffre>-licences`. Chaque export utilise un nouveau sous-dossier.
  Les documents exportés sont en clair ; les autres versions restent dans le coffre.
- Budget UTF-8 de contexte disponible en bibliothèque.

## Écarts restant à porter

- RFC 3161 : le parseur contrôle la structure et l'empreinte, mais ne valide pas
  la signature TSA ni sa chaîne de confiance. Statut maximal `claimed`, jamais
  `proven`. Les exports avec ancres sont refusés ; utiliser Python pour ceux-ci.
  Aucun service extérieur n'est appelé.
- Catalogue public et surveillance : modules présents, intégration API restante.
- Appels au modèle, aperçus, approbation et politique de cache.
- Réparation après incident du registre/catalogue (distincte de la récupération d'accès).
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
Il vérifie aussi une licence et une redevance créées en Rust, puis un export Rust
avec le vérificateur Python indépendant du moteur Rust.
Le pilote de test utilise des identifiants publics et un KDF allégé ; il n'est pas une CLI utilisateur.
