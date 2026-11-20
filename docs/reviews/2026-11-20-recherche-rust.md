# Recherche Rust : reprise du 20 novembre

`workspace.rs` remplace le comptage des sous-chaînes par un classement BM25
sur les mots, avec normalisation des accents et de la casse. Les recherches
multimots privilégient les documents contenant tous les termes, puis utilisent
les correspondances partielles si aucun document ne les contient tous. L'extrait
est centré près du premier terme trouvé, sans couper les caractères UTF-8.

Test dédié : classement, accents, extrait tardif, recherche multimots, repli,
requête sans mots et limite nulle. Suite Rust complète exécutée avec succès.

Suite : la recherche accepte maintenant le préfixe du dernier mot non cité et
les expressions exactes entre guillemets, comme la version Python. Tests dédiés
et suite Rust complète réussis. Les expressions restent requises même quand la
recherche se replie sur des correspondances partielles.

Limites : le corpus est encore retokenisé à chaque recherche, donc ce n'est pas
un index inversé. Les bigrammes CJK et la parité complète avec le moteur Python restent à porter.
La normalisation utilise NFKD et la mise en minuscules Rust, pas un casefold complet.
Les modifications de la tête pensante appartiennent à une autre session en cours.
