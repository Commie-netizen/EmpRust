# Paquet Windows de test — 16 novembre 2026

Exécutable release compilé avec Rust 1.100 pour `x86_64-pc-windows-gnu` depuis WSL,
OpenSSL/SQLCipher embarqués. Dépendances PE inspectées : DLL système Windows seules.
Sans arguments, `empreinte.exe` lance la démo sur un port disponible et ouvre le
navigateur sous Windows. Les commandes CLI explicites restent disponibles.

Tests effectués nativement sur Windows : version, smoke CLI/MCP/HTTP synthétique,
copie chiffrée SQLCipher, puis démo HTTP/déverrouillage/quatre documents/verrouillage.
Aucun import personnel ou appel cloud réel. Le paquet reste non signé.

Sortie : `C:\Users\sawle\Documents\Codex\2026-11-14\c\outputs\Empreinte-Windows`.
Le ZIP daté et les guides sont disponibles à côté. Le paquet fonctionne sans WSL,
Python ni chaîne Rust sur la machine de destination ; navigateur requis pour la démo.
