# Pattern Scan Lab

Extrait public et autonome d'un projet C++17 de recherche binaire. Le projet
montre le moteur générique de recherche de signatures et ses tests sur une
mémoire **entièrement synthétique**. Il ne contient ni offsets de jeu, ni
signatures propriétaires, ni pilote, ni accès à un processus réel.

## Points techniques

- Motifs binaires avec jokers, même lorsque les octets incluent `0x00`.
- Lecture par blocs avec reprise par pages après une lecture incomplète.
- Résultats explicitement incomplets quand une page est illisible.
- Pas de faux motif construit à travers un trou de mémoire.
- Détection des motifs aux frontières des blocs et des pages.
- Bornes sur la taille, le nombre de résultats et l'arithmétique d'adresses.
- Lecture des sections exécutables d'une image PE64, avec vérification des bornes.

La différence entre « un candidat observé » et « une adresse unique prouvée »
est explicite dans l'API. Les 500 cas différentiels comparent le moteur à une
référence indépendante sur des données synthétiques.

## Compiler et tester

Avec CMake et un compilateur C++17 :

```sh
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Ce dépôt est volontairement limité à ce composant générique. Le projet complet
reste privé. Le code est consultable ici ; aucune licence de réutilisation
générale n'est accordée.
