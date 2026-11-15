# Empreinte

Archive personnelle chiffrée : fichiers versionnés, registre signé, graphe de
liens, recherche et lots de divulgation pour des licences sélectives.
L'interface est en français et servie localement.

## Démonstration

Avec l'environnement Python existant sur cette machine :

```powershell
& 'C:\Users\sawle\.venvs\empreinte\Scripts\python.exe' -m empreinte.cli demo
```

La démonstration contient uniquement des données fictives en mémoire. Sa phrase
de passe est `demo`. L'adresse locale est affichée au démarrage ; `Ctrl+C` arrête
le serveur.

## Installation et tests

Python 3.11 ou supérieur, depuis ce dossier :

```powershell
python -m pip install -e '.[dev]'
python -m pytest -q
```

Node.js est nécessaire aux tests du rendu Markdown et des sessions navigateur.
Sans Node, ces tests sont signalés comme ignorés.

## Archive personnelle

```powershell
empreinte serve 'C:\chemin\vers\mon-archive'
```

Choisir un dossier vide pour une nouvelle archive, puis définir sa propre phrase
de passe dans l'interface. Conserver la clé de secours affichée lors de la création.
Les lots de licence exportés contiennent volontairement les documents sélectionnés
en clair ; ils sont distincts de l'archive chiffrée.

La date enregistrée par l'ordinateur prouve l'ordre des versions dans le registre,
pas à elle seule une date civile. Une date extérieure n'est présentée comme
prouvée que si l'autorité d'horodatage est authentifiée. L'horodatage externe
transmet une empreinte à un tiers et constitue une action séparée.

Format et limites : `docs/FORMAT.md`. Reprise et validation du 14 novembre :
`docs/reviews/2026-11-14-continuation.md`.

## Coût du contexte

Pour reprendre le développement avec Claude, commencer par `CLAUDE.md` et
`docs/CONTEXT.md`, puis ne charger que les sources nécessaires.

Les aperçus locaux réutilisent les résultats de la même version et du même
modèle. Les nouvelles générations envoient au plus 12 000 octets de document
compacté et demandent au plus 512 tokens en sortie. Les documents longs sont
échantillonnés : l'interface indique que l'aperçu repose sur des extraits.
Le plafond en octets n'est pas une mesure exacte des tokens du modèle.
La validation des fuites examine l'original complet ; rien n'est supprimé de
l'archive. Voir `docs/CONTEXT.md` pour l'invalidation et la régénération du cache.
