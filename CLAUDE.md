# Empreinte — reprise courte

Commencer par `docs/CONTEXT.md` (état, chemins, validations). Lire ensuite seulement
les fichiers utiles à la tâche via `rg`. Les longues sessions JSONL et les deux
revues initiales ne sont pas nécessaires à chaque reprise ; les consulter pour
une question historique ou un audit ciblé. Le dossier est un dépôt Git (branche
main, sans dépôt distant) ; ne rien commiter sans l'accord du propriétaire.
Le dossier `rust/` est un portage expérimental : ne pas le modifier sans
décision du propriétaire.

Le projet est l'archive personnelle chiffrée appelée aussi « dataset », pas
MindCorpus. Interface française, modèles locaux par défaut. Seule exception, décidée
par le propriétaire le 15 novembre 2026 : l'envoi d'extraits de conversations vers un
modèle distant par `memory prepare` puis `memory execute` est conservé, uniquement sur
action explicite avec plan et empreinte d'approbation ; ne pas le retirer, ne pas
l'élargir, ne jamais l'appeler de soi-même. Ne pas lancer
d'horodatage externe sans accord explicite ni créer le coffre personnel avec
une phrase de passe inventée. Ne pas modifier automatiquement le Wiki.
