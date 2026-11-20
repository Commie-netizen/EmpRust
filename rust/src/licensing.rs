//! Bundles de divulgation : ce qu'un preneur de licence reçoit et peut vérifier
//! sans le vault.
//!
//! Un bundle contient :
//!   manifest.json        tout ce qui est nécessaire pour vérifier les items
//!   grant.json           les octets committés exacts du contrat
//!   items/NN_<entry_id>_v<version>.<ext>  les plaintextes licenciés
//!   anchors/anchor-<seq_upto>.tst         tokens DER d'horodatage (pour openssl)
//!   README.txt           comment vérifier, avec les commandes openssl
//!   verify_bundle.py     copie du vérificateur autonome (si disponible)
//!
//! Référence : src/empreinte/licensing.py et docs/FORMAT.md §13-14.

use anyhow::{Result, anyhow, ensure};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

// ─────────────────────────────────────── constantes ──────────────────────────

pub const BUNDLE_FORMAT: &str = "empreinte-bundle";
pub const BUNDLE_VERSION: u32 = 1;
pub const GRANT_SIGNATURE_PREFIX: &[u8] = b"empreinte/v1/grant\x00";

/// Extensions de fichier par type MIME.
pub fn extension_for(media_type: &str) -> &'static str {
    match media_type {
        "text/markdown" => ".md",
        "text/plain" => ".txt",
        "text/html" => ".html",
        "application/pdf" => ".pdf",
        "application/json" => ".json",
        _ => ".bin",
    }
}

// ─────────────────────────────────────── types ───────────────────────────────

/// Un item à inclure dans le bundle.
pub struct BundleItem {
    pub entry_id: String,
    pub version: u32,
    pub title: String,
    pub media_type: String,
    /// Sel de l'item (hex).
    pub salt: String,
    /// Octets du plaintext déchiffré.
    pub plaintext: Vec<u8>,
    /// Enregistrement du registre pour cette version (JSON).
    pub record: Value,
}

/// Paramètres pour `write_bundle`.
pub struct BundleParams<'a> {
    /// Clé de signature (Ed25519).
    pub signing_key: &'a SigningKey,
    /// Clé publique hexadécimale (32 octets).
    pub public_key_hex: String,
    /// ID de la licence (hex16).
    pub license_id: String,
    /// Octets committés du contrat (ce qui est signé).
    pub committed_grant: Vec<u8>,
    /// Sel du grant (hex).
    pub grant_salt: String,
    /// Enregistrement du registre pour le grant.
    pub license_record: Value,
    /// Items licenciés.
    pub items: Vec<BundleItem>,
    /// Tous les enregistrements du registre (index = seq).
    pub records: Vec<Value>,
    /// Ancres disponibles (JSON — champs : seq_upto, head_hash, anchored_at,
    /// authority, proof (base64 DER), proof_type).
    pub anchors: Vec<Value>,
    /// Répertoire de sortie (le bundle est écrit dans un sous-dossier).
    pub out_dir: PathBuf,
}

// ─────────────────────────────────────── signature grant ─────────────────────

/// Signe les octets committés du grant avec la clé Ed25519.
pub fn grant_signature(signing_key: &SigningKey, committed: &[u8]) -> String {
    use ed25519_dalek::Signer;
    let mut msg = GRANT_SIGNATURE_PREFIX.to_vec();
    msg.extend_from_slice(committed);
    let sig = signing_key.sign(&msg);
    hex::encode(sig.to_bytes())
}

// ─────────────────────────────────────── chaîne de digests ───────────────────

/// Recalcule les body digests des enregistrements first..=last.
///
/// body = SHA-256(canonical_body(record, public_key_hex))
/// où canonical_body est la même que dans vault.rs.
pub fn chain_digests(records: &[Value], public_key_hex: &str, first: usize) -> Vec<String> {
    records[first..]
        .iter()
        .map(|rec| body_digest(rec, public_key_hex))
        .collect()
}

fn body_digest(record: &Value, public_key_hex: &str) -> String {
    // Reconstruit le corps canonique tel que vault.rs le fait :
    // {cipher_hash, commitment, entry_id, format:1, key:<pub_key>, kind, seq, size, timestamp, version}
    // Seuls les champs présents dans l'enregistrement sont inclus.
    let mut body = serde_json::Map::new();
    for key in &[
        "cipher_hash", "commitment", "entry_id", "kind", "seq", "size", "timestamp", "version",
    ] {
        if let Some(v) = record.get(*key) {
            body.insert(key.to_string(), v.clone());
        }
    }
    body.insert("format".to_string(), json!(1));
    body.insert("key".to_string(), json!(public_key_hex));
    // Tri par clé (JSON canonique)
    let sorted: std::collections::BTreeMap<_, _> = body.iter().collect();
    let canonical = serde_json::to_string(&sorted).unwrap_or_default();
    hex::encode(crate::crypto::sha256(canonical.as_bytes()))
}

// ─────────────────────────────────────── write_bundle ────────────────────────

/// Écrit le bundle dans `out_dir/license-<license_id>/`.
/// Retourne `(bundle_path, sha256_hex_de_manifest.json)`.
pub fn write_bundle(params: BundleParams<'_>) -> Result<(PathBuf, String)> {
    let bundle = params.out_dir.join(format!("license-{}", params.license_id));

    // Nettoyage si existe déjà
    if bundle.exists() {
        ensure!(
            bundle.join("manifest.json").exists(),
            "le répertoire du bundle existe mais n'est pas un bundle Empreinte"
        );
        fs::remove_dir_all(&bundle)?;
    }
    fs::create_dir_all(bundle.join("items"))?;

    // Écriture des items
    let mut manifest_items: Vec<Value> = Vec::new();
    for (number, item) in params.items.iter().enumerate() {
        let ext = extension_for(&item.media_type);
        let name = format!("items/{:02}_{}_v{}{}", number + 1, item.entry_id, item.version, ext);
        write_atomic(&bundle.join(&name), &item.plaintext)?;
        manifest_items.push(json!({
            "file": name,
            "entry_id": item.entry_id,
            "version": item.version,
            "title": item.title,
            "media_type": item.media_type,
            "salt": item.salt,
            "record": item.record,
        }));
    }

    // grant.json
    write_atomic(&bundle.join("grant.json"), &params.committed_grant)?;

    // Ancres couvrant [first, head.seq]
    let head = params.records.last().ok_or_else(|| anyhow!("registre vide"))?;
    let head_seq = head["seq"].as_u64().unwrap_or(0) as usize;
    let head_record_hash = head["record_hash"].as_str().unwrap_or("");

    let first = {
        let license_seq = params.license_record["seq"].as_u64().unwrap_or(0) as usize;
        let item_seqs = params.items.iter().map(|i| {
            i.record["seq"].as_u64().unwrap_or(0) as usize
        });
        std::iter::once(license_seq).chain(item_seqs).min().unwrap_or(0)
    };

    let covering: Vec<&Value> = params.anchors.iter().filter(|a| {
        let seq_upto = a["seq_upto"].as_u64().unwrap_or(0) as usize;
        let ah = a["head_hash"].as_str().unwrap_or("");
        seq_upto >= first
            && seq_upto <= head_seq
            && params
                .records
                .get(seq_upto)
                .and_then(|r| r["record_hash"].as_str())
                .unwrap_or("")
                == ah
    }).collect();

    let mut manifest_anchors: Vec<Value> = Vec::new();
    if !covering.is_empty() {
        fs::create_dir_all(bundle.join("anchors"))?;
    }
    for anchor in &covering {
        let seq_upto = anchor["seq_upto"].as_u64().unwrap_or(0);
        let name = format!("anchors/anchor-{seq_upto}.tst");
        if let Some(proof_b64) = anchor["proof"].as_str() {
            let der = data_encoding::BASE64
                .decode(proof_b64.trim().as_bytes())
                .map_err(|e| anyhow!("base64 token invalide : {e}"))?;
            write_atomic(&bundle.join(&name), &der)?;
        }
        let mut a = (*anchor).clone();
        a["file"] = json!(name);
        manifest_anchors.push(a);
    }

    // Chaîne de digests
    let body_digests = chain_digests(&params.records, &params.public_key_hex, first);
    let prev_hash = params
        .records
        .get(first)
        .and_then(|r| r["prev_hash"].as_str())
        .unwrap_or("")
        .to_string();

    // Signature du grant
    let sig = grant_signature(params.signing_key, &params.committed_grant);

    // manifest.json
    let manifest = json!({
        "format": BUNDLE_FORMAT,
        "format_version": BUNDLE_VERSION,
        "license_id": params.license_id,
        "public_key": params.public_key_hex,
        "exported_at": crate::vault::now(),
        "grant": {
            "file": "grant.json",
            "salt": params.grant_salt,
            "signature": sig,
            "record": params.license_record,
        },
        "items": manifest_items,
        "chain": {
            "from_seq": first,
            "prev_hash": prev_hash,
            "body_digests": body_digests,
        },
        "head": {
            "seq": head_seq,
            "record_hash": head_record_hash,
            "signature": head["signature"],
        },
        "anchors": manifest_anchors,
    });

    let manifest_bytes =
        (serde_json::to_string_pretty(&manifest)? + "\n").into_bytes();
    let manifest_hash = hex::encode(crate::crypto::sha256(&manifest_bytes));

    write_atomic(&bundle.join("manifest.json"), &manifest_bytes)?;
    write_atomic(
        &bundle.join("README.txt"),
        make_readme(&manifest).as_bytes(),
    )?;

    // Copie optionnelle du vérificateur
    let _ = try_copy_verifier(&bundle);

    Ok((bundle, manifest_hash))
}

// ─────────────────────────────────────── utilitaires ─────────────────────────

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut temp = tempfile::NamedTempFile::new_in(
        path.parent().unwrap_or_else(|| Path::new(".")),
    )?;
    temp.write_all(data)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

fn try_copy_verifier(bundle: &Path) -> Result<()> {
    let candidates = [
        PathBuf::from("tools/verify_bundle.py"),
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("../../tools/verify_bundle.py")))
            .unwrap_or_default(),
    ];
    for src in &candidates {
        if src.is_file() {
            let _ = fs::copy(src, bundle.join("verify_bundle.py"));
            return Ok(());
        }
    }
    Ok(())
}

fn make_readme(manifest: &Value) -> String {
    let lic_id = manifest["license_id"].as_str().unwrap_or("?");
    let pub_key = manifest["public_key"].as_str().unwrap_or("?");
    let anchors = manifest["anchors"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);

    let mut lines = vec![
        "Empreinte disclosure bundle".to_string(),
        String::new(),
        format!("License {lic_id}, vault public key (Ed25519) {pub_key}."),
        String::new(),
        "1. Check everything (needs Python 3.11+ and the 'cryptography' package):".to_string(),
        String::new(),
        "       python verify_bundle.py .".to_string(),
        String::new(),
        "   Prefer your own copy of verify_bundle.py over the one shipped here.".to_string(),
        "   Compare the public key above with one the author published elsewhere.".to_string(),
        String::new(),
        "2. Check the outside timestamps independently with OpenSSL.".to_string(),
        String::new(),
    ];

    if anchors.is_empty() {
        lines.push(
            "   This bundle has no outside timestamp: the dates are the author's clock only."
                .to_string(),
        );
    } else {
        for anchor in anchors {
            let seq_upto = anchor["seq_upto"].as_u64().unwrap_or(0);
            let authority = anchor["authority"].as_str().unwrap_or("?");
            let anchored_at = anchor["anchored_at"].as_str().unwrap_or("?");
            let head_hash = anchor["head_hash"].as_str().unwrap_or("?");
            let file = anchor["file"].as_str().unwrap_or("?");
            lines.push(format!(
                "   Anchor of record {seq_upto}: {authority} asserts {anchored_at}:"
            ));
            lines.push(format!(
                "       openssl ts -verify -digest {head_hash} -token_in -in {file} \
                 -CAfile ROOT.pem [-untrusted INTERMEDIATE.pem]"
            ));
            lines.push(String::new());
        }
    }

    lines.push("What the dates mean:".to_string());
    lines.push("  NONE         no anchor: ledger time is the author's clock only;".to_string());
    lines.push("  CLAIMED ONLY a valid token, but authority not authenticated;".to_string());
    lines.push("  PROVEN       valid certificate path to a trusted root at the asserted time.".to_string());
    lines.push(String::new());

    lines.join("\n")
}

// ─────────────────────────────────────────────────────────── tests ────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn dummy_key() -> SigningKey {
        SigningKey::from_bytes(&[0x11u8; 32])
    }

    #[test]
    fn grant_signature_deterministic() {
        let sk = dummy_key();
        let committed = b"grant content test";
        let sig1 = grant_signature(&sk, committed);
        let sig2 = grant_signature(&sk, committed);
        assert_eq!(sig1, sig2, "signatures doivent être déterministes");
        assert_eq!(sig1.len(), 128, "signature Ed25519 = 64 octets = 128 hex");
    }

    #[test]
    fn grant_signature_prefix() {
        let sk = dummy_key();
        // La signature de "grant content" ≠ signature de GRANT_SIGNATURE_PREFIX + "grant content"
        // (vérification que le préfixe est bien inclus)
        let sig_with_prefix = grant_signature(&sk, b"hello");
        // Vérifier à la main
        use ed25519_dalek::Signer;
        let mut msg = GRANT_SIGNATURE_PREFIX.to_vec();
        msg.extend_from_slice(b"hello");
        let expected = hex::encode(sk.sign(&msg).to_bytes());
        assert_eq!(sig_with_prefix, expected);
    }

    #[test]
    fn extension_for_known_types() {
        assert_eq!(extension_for("text/markdown"), ".md");
        assert_eq!(extension_for("text/plain"), ".txt");
        assert_eq!(extension_for("application/pdf"), ".pdf");
        assert_eq!(extension_for("unknown/type"), ".bin");
    }

    #[test]
    fn chain_digests_empty() {
        let result = chain_digests(&[], "aa".repeat(32).as_str(), 0);
        assert!(result.is_empty());
    }

    #[test]
    fn chain_digests_one_record() {
        let pub_key = "bb".repeat(32);
        let record = json!({
            "seq": 0,
            "kind": "put",
            "entry_id": "abc",
            "version": 1,
            "commitment": "cc".repeat(32),
            "timestamp": "2026-01-01T00:00:00.000000Z",
            "size": 42,
        });
        let digests = chain_digests(&[record], &pub_key, 0);
        assert_eq!(digests.len(), 1);
        assert_eq!(digests[0].len(), 64, "digest doit être hex SHA-256 (64 chars)");
    }

    #[test]
    fn write_bundle_creates_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let sk = dummy_key();
        let pub_bytes = sk.verifying_key().to_bytes();
        let pub_hex = hex::encode(pub_bytes);
        let committed = b"grant content".to_vec();
        let salt = "aa".repeat(16);
        let record0 = json!({
            "seq": 0, "kind": "put", "entry_id": "e1",
            "version": 1, "commitment": "cc".repeat(32),
            "timestamp": "2026-01-01T00:00:00.000000Z", "size": 5,
            "prev_hash": "00".repeat(32), "record_hash": "dd".repeat(32),
            "signature": "ee".repeat(64), "cipher_hash": "ff".repeat(32),
        });
        let license_record = json!({
            "seq": 1, "kind": "license", "entry_id": "e1",
            "version": 1, "commitment": "cc".repeat(32),
            "timestamp": "2026-01-01T00:00:01.000000Z", "size": 13,
            "prev_hash": "dd".repeat(32), "record_hash": "11".repeat(32),
            "signature": "22".repeat(64), "cipher_hash": "33".repeat(32),
        });
        let params = BundleParams {
            signing_key: &sk,
            public_key_hex: pub_hex,
            license_id: "cafebabe01234567".to_string(),
            committed_grant: committed,
            grant_salt: salt,
            license_record: license_record.clone(),
            items: vec![BundleItem {
                entry_id: "e1".to_string(),
                version: 1,
                title: "Test Item".to_string(),
                media_type: "text/plain".to_string(),
                salt: "bb".repeat(16),
                plaintext: b"hello".to_vec(),
                record: record0.clone(),
            }],
            records: vec![record0, license_record],
            anchors: vec![],
            out_dir: dir.path().to_path_buf(),
        };
        let (bundle_path, hash) = write_bundle(params).unwrap();
        assert!(bundle_path.join("manifest.json").exists());
        assert!(bundle_path.join("grant.json").exists());
        assert!(bundle_path.join("items/01_e1_v1.txt").exists());
        assert!(bundle_path.join("README.txt").exists());
        assert_eq!(hash.len(), 64, "hash SHA-256 = 64 hex");
    }
}
