# Reprise de développement — 14 novembre 2026

## Point de départ

Reprise à partir de la mémoire Claude `empreinte-archive.md`, des deux revues
du 14 novembre et de la fin de sa session `9641d4fd-15c7-4ff5-b329-cdb405ea36ff`.
Le lot D était terminé ; les lots noyau et serveur/interface avaient été
interrompus par une limite d'utilisation. Leurs changements présents sur disque
ont été conservés. Le dossier n'est pas un dépôt Git.

La première exécution complète donnait **242 réussites et 2 échecs**. Les deux
échecs portaient sur les anciennes attentes du vérificateur : une autorité non
authentifiée était encore attendue comme preuve, alors que le nouveau contrat
distingue explicitement une date déclarée d'une date prouvée.

## Travail effectué

- Raccordement de l'invalidation des requêtes au verrouillage manuel et automatique.
  Le verrouillage côté navigateur est immédiat ; la requête serveur conserve le
  jeton nécessaire pour révoquer la session. Une erreur de verrouillage n'est plus
  présentée silencieusement comme une réussite confirmée.
- Nettoyage du graphe (voisinages et interaction en cours), des filtres, de la
  chronologie, des infobulles, des dialogues et des sauvegardes différées.
- Annulation des confirmations abandonnées et protection contre un événement
  `close` ancien reçu après l'ouverture d'un nouveau dialogue.
- Réinitialisation explicite du filtre temporel lorsque les données modifiées
  imposent de reconstruire toute la plage de la chronologie.
- Calcul des jours du calendrier indépendant du passage à l'heure d'été.
- Recentrage immédiat du graphe même lorsque sa simulation est au repos.
- Mise à jour des tests du vérificateur pour exiger une racine reconnue avant
  d'afficher `PROVEN`, et vérifier qu'une racine étrangère ne prouve aucune date.
- Régressions ajoutées : réponses tardives (réseau et décodage JSON), fermeture
  de dialogue, annulation d'une sauvegarde, purge du graphe, calendrier Paris,
  substitution d'un élément de licence par un doublon et chemin sortant du lot.

## Vérification visuelle

Validation finale : **247 tests réussis en 54,76 secondes**, suite complète
`python -m pytest -q`, avec Node disponible. Cela inclut les régressions du
rendu Markdown hostile et des sessions navigateur.

Serveur de démonstration local, données fictives : 352 fichiers, ouverture de la
note Index, verrouillage vers l'écran d'authentification puis nouveau
déverrouillage vers le graphe. Aucun service d'horodatage ni modèle externe
contacté. Le coffre réel de l'utilisateur n'a pas été modifié.

## Limites et suite

Cette reprise est une intégration testée, pas une nouvelle certification de
tous les constats des deux revues. La revue contradictoire complète du noyau
modifié et l'essai d'import sur un jeu représentatif restent utiles avant une
version destinée à des archives importantes. Les tests utilisent des autorités
d'horodatage fictives ; aucune validation réseau en production n'est revendiquée.

Le client conserve le mécanisme de Claude qui laisse les requêtes invalidées
sans résolution pour empêcher leurs continuations de repeupler l'interface.
Toute évolution vers des erreurs d'annulation explicites doit aussi protéger
les gestionnaires d'erreurs et les blocs `finally` de chaque vue.
