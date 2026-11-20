# Handoff — Rust anchor RFC 3161 — 15 novembre 2026

## Ce qui a été fait

- `rust/src/anchor.rs` — parseur DER complet, encodeurs TLV, `make_request()`, `extract_token_node()`, `extract_tstinfo()`, `evaluate_token()`.
- `tools/openssl_resp.b64` — réponse OpenSSL TimeStampResp encodée base64 (fixture de test).
- `rust/src/lib.rs` — `pub mod anchor;` ajouté.
- `rust/src/vault.rs` — `verify()` et `proof()` appellent `crate::anchor::evaluate_token()`.
- **12 tests Rust passent** (commit `0bdf7c5`).
- Interop Python↔Rust toujours OK.

## Comportement de `evaluate_token(proof_b64, digest_hex, ts_before_ms)`

```rust
// Retourne un objet JSON :
// { "status": "proven" | "claimed" | "invalid",
//   "ts": <ms unix> | null, "hint": "..." }
//
// "proven"  = OID ContentInfo trouvé, SHA-256 du payload correspondant au digest,
//             timestamp dans la fenêtre [ts_before_ms, now+10s]
// "claimed" = pas de preuve vérifiable (pas de jeton, OID inconnu, digest absent)
// "invalid" = jeton structurellement invalide (DER corrompu, timestamps incohérents)
```

## Ce qu'il reste à faire (Rust)

### 1. `rust/src/catalogue.rs` — PRIORITAIRE

Exporter le catalogue public non-divulguant (FORMAT.md §15) :
- Struct `CatalogueEntry { public_id, title_hash, ts, anchor_ref }`
- `Vault::export_catalogue() -> Vec<CatalogueEntry>`
- Signe avec Ed25519 (déjà dans `crypto.rs` : `sign_bytes()`)
- JSON canonique (déjà dans `crypto.rs` : `canonical_json()`)
- Chaîne de preuve : digests corps du `seq` d'enregistrement jusqu'au `seq_upto` d'ancrage

### 2. `rust/src/watch.rs`

Capture continue : trois phases scan / read(due) / commit(vault, ready).
Quiet period 60 s. État dans `watch/state.v1/<sha256>` auxiliaire.
Référence Python : `src/empreinte/watch.py`.

### 3. `rust/src/licensing.rs`

Création licence, enregistrement royalties, `public_id` stable.
Référence Python : `src/empreinte/licensing.py`.

### 4. `anchor.rs` transport (`request_anchor`)

HTTP POST vers DigiCert (ou autre TSA). Stocker le jeton dans `anchors.jsonl`.
**JAMAIS auto-déclenché — toujours une action explicite de l'utilisateur.**

## "Tête pensante" (harness) — NON ENCORE COMMENCÉ

Conception attendue :
- `AGENTS.md` ≤ 100 lignes, table des matières → `.agents/rules/<nom>.md`
- Chaque règle appuyée par un script exécutable (hook, lint, test)
- Script de jardinage qui élimine les règles obsolètes
- Zéro dépendance Obsidian

## Rappels environnement

```powershell
# Rust (WSL uniquement)
wsl -d Ubuntu -- cargo test `
  --manifest-path /mnt/c/Users/sawle/OneDrive/Desktop/ChargeGrinder/Empreinte/rust/Cargo.toml `
  --target-dir /root/empreinte-target

# Python tests
Set-Location "C:\Users\sawle\OneDrive\Desktop\ChargeGrinder\Empreinte"
& "C:\Users\sawle\.venvs\empreinte\Scripts\python.exe" -m pytest -q
```
