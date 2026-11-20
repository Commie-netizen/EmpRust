# Harness évolutif piloté par l'utilisateur

Implémentation : `rust/src/harness.rs`, commandes `empreinte memory ...`.
Il s'agit d'un socle fonctionnel, pas d'un agent général capable de toutes les actions.
Tests Rust et scénario CLI/MCP/HTTP factice vérifiés. Aucun appel à un fournisseur
cloud réel pendant ce développement.

## Capacités actuelles

| Besoin | Implémentation |
|---|---|
| Mémoire partagée | Imports, provenance, déduplication, BM25, MCP |
| Préférences utilisateur | Profil versionné : langue, style, budgets contexte/sortie |
| Évolution | Feedback explicite, proposition de profil, activation et retour manuels |
| Planification d'appel | Destination, modèle, question et sélection précise d'extraits |
| Autorisation | Digest exact du plan, envoi unique, révocation avant exécution |
| Exécution | HTTP loopback ou HTTPS, sans proxy/redirection, timeout 90 s |
| Suivi | États persistants prepared/running/completed/failed/cancelled, usage fournisseur |
| Portabilité | Export JSON normalisé des conversations |
| Oubli | Suppression logique, blocage de réimport, purge des copies dans les plans |

## Profil et adaptation

```sh
empreinte memory profile
empreinte memory set-profile profile.json --reason "Préférence explicite utilisateur"
empreinte memory restore-profile 1
empreinte memory feedback <run-id> --rating -1 --note too_verbose
empreinte memory adapt
```

Exemple `profile.json` :

```json
{"language":"fr","style":"concise","context_bytes":4000,"output_tokens":512}
```

Styles : concise/balanced/detailed ; contexte 256–12000 octets, sortie demandée
64–4096 tokens. Aucune préférence ne contient de droit réseau ou d'outil.
`adapt` utilise le dernier feedback explicite `too_verbose` ou `too_brief` parmi
les 20 derniers retours. Il propose un style/budget, sans activation automatique.
Copier son champ `candidate` dans un fichier puis appeler `set-profile` pour accepter.
Les feedbacks en texte libre sont conservés mais ne déclenchent pas d'inférence
de traits personnels. Ce mécanisme n'entraîne pas les poids du modèle.

## Préparer puis envoyer une requête distante

Rechercher d'abord les extraits utiles avec `memory search`/`get`. Créer un plan :

```json
{"endpoint":"https://provider.example/v1/chat/completions","model":"chosen-model","question":"Expliquer cette décision","chunks":["SHA256_DE_L_EXTRAIT"]}
```

```sh
empreinte memory prepare plan.json
empreinte memory run <run-id>
empreinte memory execute <run-id> --approve <approval_digest> --key-env EMPREINTE_PROVIDER_KEY
empreinte memory cancel <run-id>
```

`prepare` ne fait aucun appel réseau. Sa sortie affiche le contenu exact : prompt,
modèle, endpoint, révision de profil et extraits. Les noms des fournisseurs d'origine,
titres et chemins de conversations ne sont pas transmis ; le texte peut néanmoins
contenir des informations personnelles. Aucun filtre ne garantit leur anonymisation.
Un tableau `chunks` vide envoie seulement la question et les consignes du profil.
La sélection trop grande est refusée, pas tronquée silencieusement.

Le hash d'approbation correspond à ce plan précis. Une mutation du profil après
préparation n'altère pas le plan. La clé API est lue depuis la variable d'environnement
nommée ; elle n'est pas enregistrée dans la base ni dans la sortie. Ce digest est
un mécanisme de revue, pas une authentification contre un programme local malveillant.

HTTPS et validation TLS requis hors loopback. Aucune redirection suivie, aucun proxy
hérité. Contrat fournisseur compatible OpenAI chat/completions uniquement ; les autres
API nécessitent des adaptateurs. Timeout et réponse limités ; pas de retry automatique,
car une réponse perdue ne signifie pas que le fournisseur n'a rien reçu ou facturé.
Un crash peut laisser `running` : utiliser `memory runs`, puis `memory recover`.
La récupération acquiert le même verrou système que l'exécuteur et refuse de
récupérer une exécution active. Elle marque les tâches abandonnées `interrupted`,
sans renvoi automatique. La livraison précédente reste incertaine.
`cancel` révoque un plan préparé ; ce n'est pas une annulation HTTP en cours.

`memory ask` conserve son fonctionnement local simplifié. Le MCP existant reste en
lecture seule ; il ne possède pas d'outil d'approbation ou d'envoi cloud. Un client
MCP cloud peut toutefois transmettre les résultats de recherche à son modèle.

## Contrôle et propriété des données

```sh
empreinte memory export
empreinte memory forget <provider> <conversation-id> --confirm
```

L'export écrit du JSON sur stdout, importable par le format normalisé. Il reconstruit
les messages textuels, pas la chronologie des branches ou les pièces jointes non importées.
L'oubli conserve un hash de l'identité pour refuser sa réimportation. Par prudence,
il purge les plans/résultats et feedbacks **référençant ses extraits**, y compris
les extraits partagés, et conserve les exécutions sans lien. Les textes recopiés
manuellement dans une question sans référence ne peuvent pas être identifiés ainsi.
Il refuse l'opération si une exécution est `running` : récupérer d'abord les tâches abandonnées.
Les chunks encore référencés par une autre conversation restent accessibles.

La suppression est logique : elle ne supprime ni exports d'origine, ni sauvegardes,
ni copies déjà reçues par un fournisseur. SQLite secure_delete est activé, sans
garantie d'effacement physique du disque/WAL. La base de mémoire et les plans
peuvent être chiffrés par SQLCipher ; le mode sans clé reste en clair pour
compatibilité. Le coffre de documents Empreinte reste distinct.

### Mémoire chiffrée et migration

```sh
empreinte memory --database /chemin/nouveau.sqlite --database-key-env EMPREINTE_MEMORY_KEY stats
empreinte memory --database /chemin/existant.sqlite encrypt-copy /chemin/chiffre.sqlite --new-key-env EMPREINTE_MEMORY_KEY
empreinte memory --database /chemin/chiffre.sqlite --database-key-env EMPREINTE_MEMORY_KEY search "Rust"
```

La variable contient une phrase de passe choisie par l'utilisateur (12–1024 octets).
Ne pas placer sa valeur dans les arguments ni dans Git. Pour MCP, fournir la variable
au processus et ajouter `--database-key-env NOM` avant `mcp`. SQLCipher chiffre aussi
le journal WAL ; les fichiers temporaires SQLite sont en mémoire. Le processus
déverrouillé, les exports et les sorties d'outils contiennent toujours du clair.
La perte de la clé rend la base inaccessible : aucune récupération automatique.

`encrypt-copy` copie conversations, profils, plans et feedback dans un nouveau
fichier chiffré, refuse une destination existante et laisse la source inchangée.
Une base en clair ne se transforme pas implicitement en ajoutant une clé.
La source en clair et ses sauvegardes restent à gérer après validation de la copie.
Le schéma 2 conserve l'ordre de première ingestion et les messages vides. L'ordre
absent des anciennes bases n'est pas reconstructible : migration par identifiant.

Le code fournit portabilité et contrôle technique local. Il ne peut attribuer des
droits juridiques ni modifier les contrats d'un fournisseur. Vérifier ses conditions
de rétention, d'entraînement et de propriété avant de lui transmettre des données.
Ni absence d'entraînement ni rétention zéro ne sont garanties par un simple flag HTTP.

## Prochaines briques d'un agent général

1. Séparation de plusieurs utilisateurs et intégration d'un gestionnaire de clés système.
2. Registre de capacités typées et exécuteurs isolés, avec autorisations par tâche.
3. Plans multi-étapes, checkpoints, annulation en cours et reprise avec leases.
4. Évaluation de pertinence sur corpus représentatif et budgets de coût monétaire.
5. Règles candidates évaluées sur cas retenus avant promotion, conflits et expiration.
6. Adaptateurs spécifiques de fournisseurs, rétention vérifiable et suppression distante.
7. Interface de revue des divulgations et tableau de bord utilisateur.

Ces éléments ne sont pas revendiqués comme déjà implémentés. Les instructions
récupérées dans une conversation ne deviennent jamais des permissions du harness.
