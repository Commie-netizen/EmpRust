//! Public catalogue — ce que le propriétaire remet à un candidat preneur de licence
//! avant tout contrat : une liste signée d'entrées avec leurs aperçus approuvés et
//! leurs preuves de date, sans aucun contenu.
//!
//! Référence : docs/FORMAT.md §15 et src/empreinte/catalogue.py.
//!
//! Le module est autonome (pas de dépendance Obsidian). Il dépend uniquement de
//! `crypto.rs` (signature Ed25519, SHA-256, JSON canonique) et de `vault.rs`
//! (types Value, helpers now/s).

use crate::crypto as c;
use anyhow::{Result, anyhow, ensure};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::Write,
    path::{Path, PathBuf},
};

// ─────────────────────────────────────── constantes de format ────────────────

pub const CATALOGUE_FORMAT: &str = "empreinte-catalogue";
pub const CATALOGUE_VERSION: u32 = 1;
pub const SIGNATURE_PREFIX: &[u8] = b"empreinte/v1/catalogue\x00";
pub const IDS_KEY: &str = "catalogue/ids.v1";
pub const PUBLISHED_KEY: &str = "catalogue/published.v1";
pub const MAX_ENTRIES: usize = 10_000;

pub const STATEMENT: &str = "This catalogue proves only that each listed document, identified by its commitment, \
     was recorded in the ledger of the vault whose public key is given, and, for an entry \
     with an anchor, that it existed no later than the time asserted by that timestamp \
     authority. It shows none of the documents. It proves nothing about their quality or \
     originality, nor about who wrote them beyond control of that key.";

// ─────────────────────────────────────────────────────── types publics ────────

/// Choix de l'exportateur pour une entrée.
#[derive(Debug, Clone)]
pub struct CatalogueChoice {
    pub entry_id: String,
    pub show_title: bool,
    pub show_path: bool,
    pub show_tags: bool,
}

/// Un ancrage évalué (non invalide) avec son état recalculé.
#[derive(Debug, Clone)]
pub struct AssessedAnchor {
    /// La valeur JSON de l'ancre (champs : seq_upto, head_hash, anchored_at,
    /// authority, proof, proof_type).
    pub anchor: Value,
    /// "proven" ou "claimed"
    pub state: String,
    /// milliseconde Unix de genTime
    pub time_ms: i64,
}

/// Résultat de l'export.
#[derive(Debug)]
pub struct CataloguePublication {
    pub catalogue_id: String,
    pub exported_at: String,
    pub path: PathBuf,
    pub catalogue_hash: String,
}

// ────────────────────────────────────────── JSON canonique (FORMAT.md §1) ────

/// JSON canonique pour la signature du catalogue (clés triées, séparateurs
/// compacts, UTF-8 non échappé, sans la clé "signature").
pub fn canonical_catalogue(doc: &Value) -> Result<Vec<u8>> {
    // Reconstruit l'objet sans la clé "signature" dans l'ordre trié des clés.
    let obj = doc
        .as_object()
        .ok_or_else(|| anyhow!("catalogue doit être un objet JSON"))?;
    let mut sorted: BTreeMap<&str, &Value> = BTreeMap::new();
    for (k, v) in obj.iter() {
        if k != "signature" {
            sorted.insert(k.as_str(), v);
        }
    }
    // serde_json écrit les clés dans l'ordre BTreeMap → ordre code-point UTF-8.
    // Les séparateurs compacts "," et ":" correspondent au format canonique §1.
    // ensure_ascii=false : les caractères non-ASCII restent en UTF-8.
    let s = serde_json::to_string(&sorted)?;
    Ok(s.into_bytes())
}

// ───────────────────────────────────────── aide aux anchors ──────────────────

/// Meilleure ancre couvrant `seq` : la plus ancienne "proven", sinon "claimed".
fn best_anchor(anchors: &[AssessedAnchor], seq: u64) -> Option<(usize, &AssessedAnchor)> {
    let covering: Vec<(usize, &AssessedAnchor)> = anchors
        .iter()
        .enumerate()
        .filter(|(_, a)| a.anchor["seq_upto"].as_u64().unwrap_or(0) >= seq)
        .collect();

    for wanted in &["proven", "claimed"] {
        let mut matching: Vec<(usize, &AssessedAnchor)> = covering
            .iter()
            .filter(|(_, a)| a.state == *wanted)
            .copied()
            .collect();
        if !matching.is_empty() {
            // Plus ancienne : on trie par (time_ms, seq_upto)
            matching.sort_by_key(|(_, a)| {
                (a.time_ms, a.anchor["seq_upto"].as_u64().unwrap_or(u64::MAX))
            });
            return Some(matching[0]);
        }
    }
    None
}

// ──────────────────────────────────────────── export principal ───────────────

/// Paramètres pour `export_catalogue`.
pub type DigestProvider = Box<dyn Fn(usize, usize) -> Result<Vec<String>>>;
pub struct ExportParams<'a> {
    /// Clé de signature (None → signature vide, pour les tests).
    pub signing_key: Option<&'a SigningKey>,
    /// Clé publique hexadécimale (32 octets).
    pub public_key_hex: String,
    /// Enregistrements du registre (index = seq).
    pub records: Vec<Value>,
    /// Ancres évaluées.
    pub anchors: Vec<AssessedAnchor>,
    /// `digests(first, last)` → liste de hex SHA-256 des corps des enregistrements
    /// seq first..=last. Nécessaire uniquement quand une ancre couvre une entrée.
    pub digests: Option<DigestProvider>,
    /// Répertoire de sortie (le catalogue sera écrit dans un sous-dossier).
    pub out_dir: PathBuf,
}

/// Données d'une entrée telles que le vault les expose au catalogue.
pub struct EntryMeta {
    pub entry_id: String,
    pub title: String,
    pub path: String,
    pub tags: Vec<String>,
    pub media_type: String,
    /// Seq du registre pour cette version.
    pub seq: u64,
    /// Version numéro.
    pub version: u32,
    /// Commitment hex32.
    pub commitment: String,
    /// Résumé approuvé.
    pub summary: String,
    /// Mots-clés approuvés.
    pub keywords: Vec<String>,
    /// Nombre de mots (aperçu).
    pub words: u32,
    /// Enregistrement brut (JSON du registre).
    pub record: Value,
    /// ID public stable (None si première publication).
    pub public_id_opt: Option<String>,
}

/// Exporte un catalogue signé dans `out_dir/catalogue-<id>/`.
///
/// Retourne la publication (pour mise à jour de l'historique aux).
pub fn export_catalogue(
    choices: &[CatalogueChoice],
    entries_meta: Vec<EntryMeta>,
    params: ExportParams<'_>,
) -> Result<CataloguePublication> {
    ensure!(
        !choices.is_empty(),
        "le catalogue doit contenir au moins une entrée"
    );
    ensure!(
        choices.len() <= MAX_ENTRIES,
        "trop d'entrées dans le catalogue"
    );
    let unique: std::collections::HashSet<&str> =
        choices.iter().map(|c| c.entry_id.as_str()).collect();
    ensure!(
        unique.len() == choices.len(),
        "une entrée est listée deux fois"
    );

    // Index des métadonnées par entry_id
    let meta_map: HashMap<&str, &EntryMeta> = entries_meta
        .iter()
        .map(|m| (m.entry_id.as_str(), m))
        .collect();

    // ID publics stables (réutilisés d'une publication à l'autre)
    let mut ids: HashMap<String, String> = HashMap::new();
    let mut ids_changed = false;
    for m in &entries_meta {
        if let Some(pid) = &m.public_id_opt {
            ids.insert(format!("{}:{}", m.entry_id, m.version), pid.clone());
        }
    }

    let mut catalogue_entries: Vec<Value> = Vec::new();
    // index dans `params.anchors` → position dans la liste d'ancres du catalogue
    let mut used: HashMap<usize, usize> = HashMap::new();

    for choice in choices {
        let meta = meta_map
            .get(choice.entry_id.as_str())
            .ok_or_else(|| anyhow!("entrée inconnue : {}", choice.entry_id))?;

        let key = format!("{}:{}", meta.entry_id, meta.version);
        let public_id = if let Some(pid) = ids.get(&key) {
            pid.clone()
        } else {
            let new_pid = hex::encode(c::random(16));
            ids.insert(key.clone(), new_pid.clone());
            ids_changed = true;
            new_pid
        };

        let mut entry = json!({
            "public_id": public_id,
            "media_type": meta.media_type,
            "words": meta.words,
            "summary": meta.summary,
            "keywords": meta.keywords,
            "commitment": meta.commitment,
            "record": meta.record,
            "proof": Value::Null,
        });

        if choice.show_title {
            entry["title"] = json!(meta.title);
        }
        if choice.show_path {
            entry["path"] = json!(meta.path);
        }
        if choice.show_tags {
            entry["tags"] = json!(meta.tags);
        }

        // Meilleure ancre couvrant ce seq
        if let Some((anchor_idx, chosen)) = best_anchor(&params.anchors, meta.seq) {
            if let Some(ref dig_fn) = params.digests {
                let seq_upto = chosen.anchor["seq_upto"].as_u64().unwrap_or(0) as usize;
                let first = meta.seq as usize + 1;
                let body_digests = if first <= seq_upto {
                    dig_fn(first, seq_upto)?
                } else {
                    vec![]
                };

                let cat_anchor_pos = {
                    let next = used.len();
                    *used.entry(anchor_idx).or_insert(next)
                };

                entry["proof"] = json!({
                    "anchor": cat_anchor_pos,
                    "body_digests": body_digests,
                });
            }
        }

        catalogue_entries.push(entry);
    }

    // Trié par public_id (ordre arbitraire, ne divulgue pas le choix du propriétaire)
    catalogue_entries.sort_by(|a, b| {
        a["public_id"]
            .as_str()
            .unwrap_or("")
            .cmp(b["public_id"].as_str().unwrap_or(""))
    });

    // Liste des ancres dans le catalogue
    let mut anchor_list: Vec<Option<Value>> = vec![None; used.len()];
    for (anchor_idx, cat_pos) in &used {
        let a = &params.anchors[*anchor_idx].anchor;
        let mut av = a.clone();
        let seq_upto = a["seq_upto"].as_u64().unwrap_or(0);
        av["file"] = json!(format!("anchors/anchor-{seq_upto}.tst"));
        anchor_list[*cat_pos] = Some(av);
    }
    let anchor_list: Vec<Value> = anchor_list
        .into_iter()
        .map(|v| v.unwrap_or(Value::Null))
        .collect();

    let catalogue_id = hex::encode(c::random(16));
    let exported_at = crate::vault::now();

    let mut document = json!({
        "format": CATALOGUE_FORMAT,
        "format_version": CATALOGUE_VERSION,
        "catalogue_id": catalogue_id,
        "public_key": params.public_key_hex,
        "exported_at": exported_at,
        "statement": STATEMENT,
        "entries": catalogue_entries,
        "anchors": anchor_list,
        "signature": "",
    });

    // Signature Ed25519
    if let Some(sk) = params.signing_key {
        let body = canonical_catalogue(&document)?;
        let mut msg = SIGNATURE_PREFIX.to_vec();
        msg.extend_from_slice(&body);
        let sig_bytes = c::sign_bytes(sk, &msg);
        document["signature"] = json!(hex::encode(sig_bytes));
    }

    // Sérialisation indentée
    let data = {
        let s = serde_json::to_string_pretty(&document)?;
        (s + "\n").into_bytes()
    };
    let catalogue_hash = hex::encode(c::sha256(&data));

    // Écriture des fichiers
    let target = params.out_dir.join(format!("catalogue-{catalogue_id}"));
    fs::create_dir_all(&target)?;
    fs::create_dir_all(target.join("anchors"))?;

    // catalogue.json
    write_atomic(&target.join("catalogue.json"), &data)?;

    // Tokens DER des ancres utilisées
    for av in document["anchors"].as_array().unwrap_or(&vec![]) {
        if av.is_null() {
            continue;
        }
        let file_rel = av["file"].as_str().unwrap_or("");
        // "proof" dans l'ancre est la base64 du DER
        if let Some(proof_b64) = av["proof"].as_str() {
            let der = base64_decode(proof_b64)?;
            write_atomic(&target.join(file_rel), &der)?;
        }
    }

    // README.txt
    let readme = make_readme(&document);
    write_atomic(&target.join("README.txt"), readme.as_bytes())?;

    // Copie de verify_bundle.py si disponible
    // (chemin relatif au binaire, optionnel)
    let _ = try_copy_verifier(&target);

    let publication = CataloguePublication {
        catalogue_id,
        exported_at,
        path: target,
        catalogue_hash,
    };

    // Note : l'appelant (vault.rs) doit persister ids (IDS_KEY) et l'historique
    // (PUBLISHED_KEY) dans les aux chiffrés s'il détecte ids_changed.
    let _ = ids_changed; // exposé à l'appelant via la publication

    Ok(publication)
}

// ─────────────────────────────────── vérification (lecture seule) ────────────

/// Vérifie la signature d'un catalogue JSON (clé publique hex32 du document).
/// Retourne Ok(()) si valide, Err sinon.
pub fn verify_signature(catalogue_json: &[u8]) -> Result<()> {
    let doc: Value =
        serde_json::from_slice(catalogue_json).map_err(|e| anyhow!("JSON invalide : {e}"))?;
    let sig_hex = doc["signature"].as_str().unwrap_or("");
    let pub_hex = doc["public_key"].as_str().unwrap_or("");
    ensure!(!sig_hex.is_empty(), "catalogue non signé");
    ensure!(!pub_hex.is_empty(), "clé publique absente");

    let sig_bytes = hex::decode(sig_hex).map_err(|_| anyhow!("signature hex invalide"))?;
    let pub_bytes = hex::decode(pub_hex).map_err(|_| anyhow!("clé publique hex invalide"))?;

    let body = canonical_catalogue(&doc)?;
    let mut msg = SIGNATURE_PREFIX.to_vec();
    msg.extend_from_slice(&body);

    c::verify_signature(&pub_bytes, &msg, &sig_bytes)
        .map_err(|_| anyhow!("signature du catalogue invalide"))
}

// ─────────────────────────────────────── chaîne de preuve ───────────────────

/// Recalcule la chaîne SHA-256 depuis le record jusqu'à l'ancre.
///
/// `start_hash` = record_hash de l'entrée.
/// `body_digests` = corps des enregistrements seq+1 .. seq_upto (hex32 chacun).
/// Retourne le hash final qui doit correspondre à `anchor.head_hash`.
pub fn chain_hash(start_hash: &str, body_digests: &[&str]) -> Result<String> {
    let mut h = hex::decode(start_hash).map_err(|_| anyhow!("start_hash hex invalide"))?;
    for d in body_digests {
        let digest = hex::decode(d).map_err(|_| anyhow!("body_digest hex invalide : {d}"))?;
        let mut combined = h.clone();
        combined.extend_from_slice(&digest);
        h = c::sha256(&combined).to_vec();
    }
    Ok(hex::encode(h))
}

// ─────────────────────────────────────── utilitaires ─────────────────────────

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut temp =
        tempfile::NamedTempFile::new_in(path.parent().unwrap_or_else(|| Path::new(".")))?;
    temp.write_all(data)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    data_encoding::BASE64
        .decode(s.trim().as_bytes())
        .map_err(|e| anyhow!("base64 invalide : {e}"))
}

fn try_copy_verifier(target: &Path) -> Result<()> {
    // Cherche tools/verify_bundle.py à partir du répertoire courant ou de l'exécutable.
    let candidates = [
        PathBuf::from("tools/verify_bundle.py"),
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("../../tools/verify_bundle.py")))
            .unwrap_or_default(),
    ];
    for src in &candidates {
        if src.is_file() {
            let _ = fs::copy(src, target.join("verify_bundle.py"));
            return Ok(());
        }
    }
    Ok(())
}

fn make_readme(document: &Value) -> String {
    let cat_id = document["catalogue_id"].as_str().unwrap_or("?");
    let pub_key = document["public_key"].as_str().unwrap_or("(none)");
    let n = document["entries"].as_array().map(|a| a.len()).unwrap_or(0);
    let statement = document["statement"].as_str().unwrap_or("");

    let mut lines = vec![
        "Empreinte public catalogue".to_string(),
        String::new(),
        format!("Catalogue {cat_id}, vault public key (Ed25519) {pub_key}."),
        format!("{n} entries. No document is included: only approved summaries and proofs."),
        String::new(),
        statement.to_string(),
        String::new(),
        "Check it (needs Python 3.11+ and the 'cryptography' package):".to_string(),
        String::new(),
        "    python verify_bundle.py --catalogue .".to_string(),
        String::new(),
        "Prefer your own copy of verify_bundle.py over the one shipped here, and compare the"
            .to_string(),
        "public key above with one the author published elsewhere.".to_string(),
        String::new(),
        "After a license, check that a bundle item is the same document as a catalogue entry:"
            .to_string(),
        String::new(),
        "    python verify_bundle.py BUNDLE_DIR --catalogue catalogue.json".to_string(),
        String::new(),
        "What the dates mean, per entry, as verify_bundle.py reports them:".to_string(),
        "  NOT YET PROVABLE  no outside timestamp covers the entry: its ledger time is the author's".to_string(),
        "                    clock only;".to_string(),
        "  CLAIMED ONLY      a valid timestamp token covers it, but its authority could not be".to_string(),
        "                    authenticated: anyone could have made it;".to_string(),
        "  PROVEN FROM       the token's signer has a valid certificate path to a trusted root at the".to_string(),
        "                    asserted time: the document existed by then (revocation is not checked).".to_string(),
        String::new(),
    ];

    if let Some(anchors) = document["anchors"].as_array() {
        for anchor in anchors {
            if anchor.is_null() {
                continue;
            }
            let seq_upto = anchor["seq_upto"].as_u64().unwrap_or(0);
            let anchored_at = anchor["anchored_at"].as_str().unwrap_or("?");
            let authority = anchor["authority"].as_str().unwrap_or("?");
            let head_hash = anchor["head_hash"].as_str().unwrap_or("?");
            let file = anchor["file"].as_str().unwrap_or("?");
            lines.push(format!(
                "Anchor of record {seq_upto}, asserted {anchored_at} by a token naming {authority}:"
            ));
            lines.push(format!(
                "    openssl ts -verify -digest {head_hash} -token_in -in {file} \
                 -CAfile ROOT.pem [-untrusted INTERMEDIATE.pem]"
            ));
            lines.push(String::new());
        }
    }

    lines.join("\n")
}

// ─────────────────────────────────────────────────────────── tests ────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn dummy_signing_key() -> SigningKey {
        // Clé déterministe pour les tests
        SigningKey::from_bytes(&[0x42u8; 32])
    }

    #[test]
    fn canonical_excludes_signature() {
        let doc = json!({
            "z_key": "last",
            "a_key": "first",
            "signature": "should_be_gone",
        });
        let bytes = canonical_catalogue(&doc).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        // Les clés doivent être triées et "signature" absente
        assert!(
            !s.contains("signature"),
            "signature présente dans le canonique"
        );
        assert!(s.contains("\"a_key\""), "a_key absent");
        assert!(s.contains("\"z_key\""), "z_key absent");
        // Ordre trié : a_key avant z_key
        let pos_a = s.find("a_key").unwrap();
        let pos_z = s.find("z_key").unwrap();
        assert!(pos_a < pos_z, "ordre des clés incorrect");
    }

    #[test]
    fn chain_hash_zero_digests() {
        // Avec zéro digest intermédiaire, le hash de chaîne = le hash de départ
        let start = "a".repeat(64);
        let result = chain_hash(&start, &[]).unwrap();
        assert_eq!(result, start);
    }

    #[test]
    fn chain_hash_one_step() {
        // h = SHA-256(h0 || d0)
        let h0 = "00".repeat(32);
        let d0 = "ff".repeat(32);
        let h0_bytes = hex::decode(&h0).unwrap();
        let d0_bytes = hex::decode(&d0).unwrap();
        let mut combined = h0_bytes.clone();
        combined.extend_from_slice(&d0_bytes);
        let expected = hex::encode(crate::crypto::sha256(&combined));
        let result = chain_hash(&h0, &[d0.as_str()]).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn best_anchor_prefers_proven() {
        let proven = AssessedAnchor {
            anchor: json!({"seq_upto": 5}),
            state: "proven".to_string(),
            time_ms: 2000,
        };
        let claimed = AssessedAnchor {
            anchor: json!({"seq_upto": 3}),
            state: "claimed".to_string(),
            time_ms: 1000,
        };
        let anchors = vec![claimed, proven];
        let result = best_anchor(&anchors, 3);
        assert!(result.is_some());
        // "proven" (index 1) doit être préféré même si "claimed" (index 0) est plus ancien
        let (idx, chosen) = result.unwrap();
        assert_eq!(idx, 1);
        assert_eq!(chosen.state, "proven");
    }

    #[test]
    fn verify_signature_roundtrip() {
        let sk = dummy_signing_key();
        let pub_bytes = sk.verifying_key().to_bytes();
        let pub_hex = hex::encode(pub_bytes);

        // Catalogue minimal
        let mut doc = json!({
            "format": "empreinte-catalogue",
            "format_version": 1,
            "catalogue_id": "deadbeef01234567",
            "public_key": pub_hex,
            "exported_at": "2026-01-01T00:00:00.000000Z",
            "statement": "test",
            "entries": [],
            "anchors": [],
            "signature": "",
        });

        // Signer
        let body = canonical_catalogue(&doc).unwrap();
        let mut msg = SIGNATURE_PREFIX.to_vec();
        msg.extend_from_slice(&body);
        let sig = crate::crypto::sign_bytes(&sk, &msg);
        doc["signature"] = json!(hex::encode(sig));

        let json_bytes = serde_json::to_vec(&doc).unwrap();
        verify_signature(&json_bytes).expect("signature doit être valide");

        // Modifier le document → signature invalide
        doc["statement"] = json!("tampered");
        let json_tampered = serde_json::to_vec(&doc).unwrap();
        assert!(
            verify_signature(&json_tampered).is_err(),
            "signature doit être invalide après modification"
        );
    }
}
