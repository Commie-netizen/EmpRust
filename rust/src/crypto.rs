//! Empreinte v1 primitives, byte-compatible with docs/FORMAT.md.
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use anyhow::{Result, anyhow, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

pub fn random(n: usize) -> Vec<u8> {
    let mut b = vec![0; n];
    OsRng.fill_bytes(&mut b);
    b
}
pub fn hash(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
pub fn canonical(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).expect("JSON serialization")
}
pub fn bytes(v: &Value) -> Result<Vec<u8>> {
    Ok(hex::decode(
        v.as_str().ok_or_else(|| anyhow!("hexadecimal attendu"))?,
    )?)
}
pub fn hkdf(key: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(vec![0; 32]);
    Hkdf::<Sha256>::new(Some(salt), key)
        .expand(info, &mut out)
        .expect("32-byte HKDF");
    out
}
pub fn subkey(master: &[u8], id: &[u8], label: &str) -> Zeroizing<Vec<u8>> {
    hkdf(
        master,
        id,
        format!("empreinte/v1/subkey/{label}").as_bytes(),
    )
}
pub fn passkey(pass: &str, kdf: &Value) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(!pass.is_empty(), "phrase de passe vide");
    ensure!(kdf["name"] == "argon2id", "KDF non pris en charge");
    let number = |k: &str, lo: u64, hi: u64| -> Result<u32> {
        let n = kdf[k]
            .as_u64()
            .ok_or_else(|| anyhow!("paramètre KDF invalide"))?;
        ensure!((lo..=hi).contains(&n), "paramètre KDF hors limites");
        Ok(n as u32)
    };
    let t = number("iterations", 1, 16)?;
    let p = number("lanes", 1, 16)?;
    let m = number("memory_cost", 8, 2 * 1024 * 1024)?;
    ensure!(m >= 8 * p, "mémoire Argon2 insuffisante");
    let salt = bytes(&kdf["salt"])?;
    ensure!((16..=64).contains(&salt.len()), "sel KDF invalide");
    let params = Params::new(m, t, p, Some(32)).map_err(|e| anyhow!("{e}"))?;
    let normalized = Zeroizing::new(pass.nfc().collect::<String>());
    let mut key = Zeroizing::new(vec![0; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(normalized.as_bytes(), &salt, &mut key)
        .map_err(|e| anyhow!("{e}"))?;
    Ok(key)
}
pub fn aad(purpose: &str, id: &[u8], extra: &[u8]) -> Vec<u8> {
    [
        format!("empreinte/v1/wrap/{purpose}\0").as_bytes(),
        id,
        extra,
    ]
    .concat()
}
pub fn wrap(key: &[u8], secret: &[u8], aad: &[u8]) -> Result<Value> {
    let nonce = random(12);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| anyhow!("clé invalide"))?
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: secret, aad })
        .map_err(|_| anyhow!("chiffrement impossible"))?;
    Ok(json!({"alg":"AES-256-GCM","nonce":hex::encode(nonce),"ciphertext":hex::encode(cipher)}))
}
pub fn unwrap(key: &[u8], value: &Value, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(value["alg"] == "AES-256-GCM", "format de clé invalide");
    let nonce = bytes(&value["nonce"])?;
    ensure!(nonce.len() == 12, "nonce invalide");
    let cipher = bytes(&value["ciphertext"])?;
    Ok(Zeroizing::new(
        Aes256Gcm::new_from_slice(key)
            .map_err(|_| anyhow!("clé invalide"))?
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: &cipher, aad })
            .map_err(|_| anyhow!("authentification cryptographique en échec"))?,
    ))
}
pub fn seal(key: &[u8], kind: u8, plain: &[u8], id: &[u8], label: &str) -> Result<Vec<u8>> {
    let salt = random(32);
    let nonce = random(12);
    let header = [b"EMPB".as_slice(), &[1, kind], &salt, &nonce].concat();
    let derived = hkdf(key, &salt, b"empreinte/v1/blob-key");
    let aad = [
        b"empreinte/v1/blob\0".as_slice(),
        &header,
        id,
        label.as_bytes(),
    ]
    .concat();
    let cipher = Aes256Gcm::new_from_slice(&derived)
        .unwrap()
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plain,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("chiffrement impossible"))?;
    Ok([header, cipher].concat())
}
pub fn open(
    key: &[u8],
    kind: u8,
    data: &[u8],
    id: &[u8],
    label: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        data.len() >= 66 && &data[..4] == b"EMPB" && data[4] == 1 && data[5] == kind,
        "format du blob invalide"
    );
    let derived = hkdf(key, &data[6..38], b"empreinte/v1/blob-key");
    let aad = [
        b"empreinte/v1/blob\0".as_slice(),
        &data[..50],
        id,
        label.as_bytes(),
    ]
    .concat();
    Ok(Zeroizing::new(
        Aes256Gcm::new_from_slice(&derived)
            .unwrap()
            .decrypt(
                Nonce::from_slice(&data[38..50]),
                Payload {
                    msg: &data[50..],
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow!("blob altéré ou déplacé"))?,
    ))
}
pub fn pack(meta: &Value, body: &[u8]) -> Zeroizing<Vec<u8>> {
    let m = canonical(meta);
    Zeroizing::new([&(m.len() as u32).to_be_bytes()[..], &m, body].concat())
}
pub fn unpack(data: &[u8]) -> Result<(Value, Zeroizing<Vec<u8>>)> {
    ensure!(data.len() >= 4, "payload tronqué");
    let n = u32::from_be_bytes(data[..4].try_into()?) as usize;
    ensure!(n <= data.len() - 4, "métadonnées tronquées");
    Ok((
        serde_json::from_slice(&data[4..4 + n])?,
        Zeroizing::new(data[4 + n..].to_vec()),
    ))
}
/// Retourne les 32 octets bruts du SHA-256 de `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Signe `msg` avec `sk` (Ed25519) ; retourne les 64 octets de signature.
pub fn sign_bytes(sk: &ed25519_dalek::SigningKey, msg: &[u8]) -> [u8; 64] {
    use ed25519_dalek::Signer;
    sk.sign(msg).to_bytes()
}

/// Vérifie une signature Ed25519. `pub_bytes` : 32 octets, `sig_bytes` : 64 octets.
pub fn verify_signature(pub_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let key_arr: [u8; 32] = pub_bytes
        .try_into()
        .map_err(|_| anyhow!("clé publique : 32 octets attendus"))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow!("signature : 64 octets attendus"))?;
    let vk =
        VerifyingKey::from_bytes(&key_arr).map_err(|e| anyhow!("clé publique invalide : {e}"))?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(msg, &sig)
        .map_err(|_| anyhow!("signature invalide"))
}

pub fn recovery_text(raw: &[u8]) -> String {
    let sum = Sha256::digest(raw);
    let text = data_encoding::BASE32_NOPAD.encode(&[raw, &sum[..2]].concat());
    text.as_bytes()
        .chunks(5)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}
pub fn parse_recovery(text: &str) -> Result<Zeroizing<Vec<u8>>> {
    use subtle::ConstantTimeEq;
    ensure!(text.len() <= 100, "clé de secours trop longue");
    let normalized = Zeroizing::new(
        text.chars()
            .filter(|c| *c != '-' && !c.is_ascii_whitespace())
            .collect::<String>()
            .to_ascii_uppercase(),
    );
    let decoded = Zeroizing::new(data_encoding::BASE32_NOPAD.decode(normalized.as_bytes())?);
    ensure!(decoded.len() == 34, "longueur de clé de secours invalide");
    let checksum = Sha256::digest(&decoded[..32]);
    ensure!(
        bool::from(decoded[32..].ct_eq(&checksum[..2])),
        "somme de contrôle invalide"
    );
    Ok(Zeroizing::new(decoded[..32].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn blob_binds_identity_and_location() {
        let key = random(32);
        let id = random(16);
        let b = seal(&key, 1, b"secret", &id, "content:a:1").unwrap();
        assert_eq!(&*open(&key, 1, &b, &id, "content:a:1").unwrap(), b"secret");
        assert!(open(&key, 1, &b, &id, "content:a:2").is_err());
        assert!(open(&key, 1, &b, &random(16), "content:a:1").is_err());
        let mut damaged = b;
        damaged[60] ^= 1;
        assert!(open(&key, 1, &damaged, &id, "content:a:1").is_err());
    }
    #[test]
    fn kdf_bounds() {
        assert!(passkey("pw",&json!({"name":"argon2id","iterations":999999,"lanes":1,"memory_cost":8,"salt":"00".repeat(16)})).is_err());
    }
}
