# Mémoire commune locale des conversations

Extension disponible : [harness utilisateur et cloud contrôlé](USER_HARNESS.md).
Les commandes ci-dessous restent locales ; `prepare`/`execute` ajoutent un parcours
distinct pour les fournisseurs HTTPS, avec divulgation sélectionnée et approbation.

Implémentation Rust : `src/conversations.rs`. SQLite FTS5/BM25, sans modèle
d'embedding ni service distant requis. Références de provenance conservées,
extraits de 2048 octets UTF-8, déduplication par SHA-256. Recherche indexée : le
corpus complet n'est pas envoyé au modèle. Recherche puis lecture ciblée.

## Utilisation

```sh
empreinte memory import conversation-exports/chatgpt.json --format chatgpt
empreinte memory import conversation-exports/claude.json --format claude
empreinte memory import conversation-exports/local.json --format normalized
empreinte memory stats
empreinte memory search "architecture Rust" --budget 4000
empreinte memory get <identifiant-extrait>
empreinte memory rebuild
empreinte memory sync /chemin/inbox
empreinte memory sync /chemin/inbox --follow
empreinte memory ask "Quelle architecture avons-nous choisie ?" --model <modele-local>
```

`--database /chemin/absolu/memoire.sqlite` se place entre `memory` et la commande.
Par défaut : `%LOCALAPPDATA%/Empreinte/conversations.sqlite` sous Windows,
`$HOME/.local/share/empreinte/conversations.sqlite` sous Linux/WSL. Utiliser un chemin absolu
commun pour que tous les clients consultent la même base.

Format normalisé, un objet ou une liste :

```json
{"provider":"local-model","id":"conversation-1","title":"Architecture","messages":[{"id":"message-1","role":"user","text":"Construire une mémoire locale."}]}
```

Adaptateurs d'import initiaux : export JSON ChatGPT (`mapping`, toutes les branches
textuelles) et Claude (`chat_messages`). Les pièces jointes, outils et contenus non
textuels ne sont pas importés. L'ordre des branches ChatGPT n'est pas une chronologie.
Les formats des fournisseurs peuvent évoluer ; un format inattendu est refusé.
Export limité à 64 Mio, message à 4 Mio. Les imports sont transactionnels et
réimportables : même fournisseur/conversation/message remplace ce message ; les
messages absents d'un nouvel export restent conservés pour permettre les imports
incrémentaux. Fournisseurs différents conservent leurs provenances séparées.

`sync` examine uniquement les fichiers `.json` du dossier explicitement désigné,
détecte les trois formats et saute les exports dont le hash n'a pas changé.
`--follow` recommence toutes les 10 secondes jusqu'à Ctrl+C. Déposer les exports
par renommage atomique ; un JSON incomplet est signalé et réessayé au prochain scan.
Ce suivi n'extrait pas les conversations des interfaces des fournisseurs : les
clients doivent exporter ou écrire le format commun dans ce dossier.

## Connecter une IA

Serveur MCP stdio, protocole initial 2025-06-18, trois outils en lecture seule :
`memory_search`, `memory_get`, `memory_stats`. Aucun outil shell ou écriture.

Exemple de configuration à adapter au client :

```json
{"mcpServers":{"empreinte":{"command":"/chemin/empreinte","args":["memory","--database","/chemin/memoire.sqlite","mcp"]}}}
```

Sous Windows avec le binaire WSL, utiliser `command: "wsl"` et préfixer `args`
par `-d`, `Ubuntu`, `--`, puis le chemin Linux du binaire. Les chemins de base
doivent être ceux vus par le processus. Compatibilité à tester avec chaque client ;
MCP ne donne pas accès à l'historique du client et ne capture pas automatiquement
les conversations. Un client sans MCP peut utiliser la CLI JSON ou produire le
format normalisé. Aucun raccordement à un compte cloud n'est installé ici.

Le stockage et la recherche sont locaux. Un client connecté à une IA cloud peut
envoyer les résultats des outils à cette IA : pour un fonctionnement entièrement
local, utiliser exclusivement un client et un modèle locaux.

## Modèles locaux

`memory ask` utilise le contrat HTTP compatible OpenAI `/v1/chat/completions`.
Endpoint par défaut : `http://127.0.0.1:11434/v1/chat/completions`.
Adapter `--endpoint` pour un autre serveur local. Modèle déjà installé requis.
IP loopback littérale uniquement, sans proxy, sans redirection, sans télémétrie
dans cette couche. Aucun téléchargement automatique de poids. Sortie demandée :
512 tokens maximum ; budget de contexte réglable entre 256 et 12000 octets.
Le serveur de modèle reste responsable de respecter ses paramètres et sa politique réseau.

## Coût et limites

Le budget borne le JSON compact de recherche, hors enveloppe MCP et prompt.
Un octet n'est pas un token. Les extraits sont courts et les résultats complets
se chargent à la demande ; pas de résumé génératif systématique ni d'appel modèle
lors des imports/recherches. Jusqu'à 40 candidats BM25 examinés par recherche.
Un résultat cite une provenance ; `get` en retourne jusqu'à 20.

Pas de promesse d'optimalité globale : mesurer pertinence, volume et latence sur
des conversations représentatives avant d'ajouter cache, reranker ou embeddings.
Les tests couvrent déduplication, mise à jour, budget, rollback, Unicode, adaptateurs
et RPC. `tools/test_memory_cli.py <binaire>` teste aussi les processus CLI/MCP
et un serveur HTTP local factice. Pas encore de test avec un vrai client MCP ou
un modèle installé.

Sans `--database-key-env`, cette base de recherche est **en clair**, distincte du coffre chiffré Empreinte.
Le mode SQLCipher et la migration par copie sont décrits dans [USER_HARNESS.md](USER_HARNESS.md).
Placer la base sur un volume protégé et hors synchronisation cloud pour une mémoire
strictement locale. Ne pas importer de données privées dans le dépôt OneDrive.
Les motifs Git ignorent les bases et exports usuels ; cela ne purge pas un historique
déjà commité. Aucun export personnel n'a été importé pendant le développement.

Références : [SQLite FTS5](https://www.sqlite.org/fts5.html),
[MCP tools 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/server/tools).
