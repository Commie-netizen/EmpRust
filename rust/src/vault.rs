//! Native v1 vault. Fail closed on recovery discrepancies; never repair on open.
use crate::crypto as c;
use anyhow::{Context, Result, anyhow, ensure};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use fs2::FileExt;
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

const MAX_FILE: u64 = 128 * 1024 * 1024;
pub fn now() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}
pub fn s(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap_or("").to_owned()
}
fn zeros() -> String {
    "0".repeat(64)
}
pub fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.custom_flags(0x00200000);
    }
    let f = opts.open(path)?;
    ensure!(
        f.metadata()?.is_file() && !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "fichier non régulier ou lien refusé"
    );
    let mut out = Vec::new();
    f.take(limit + 1).read_to_end(&mut out)?;
    ensure!(out.len() as u64 <= limit, "fichier trop volumineux");
    Ok(out)
}
fn atomic(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| anyhow!("répertoire absent"))?;
    fs::create_dir_all(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(data)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| e.error)?;
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn wipe_json(v: &mut Value) {
    match v {
        Value::String(t) => t.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe_json),
        Value::Object(m) => m.values_mut().for_each(wipe_json),
        _ => {}
    }
}

pub struct Vault {
    pub path: PathBuf,
    pub header: Value,
    pub catalog: Value,
    pub records: Vec<Value>,
    pub anchors: Vec<Value>,
    master: Zeroizing<Vec<u8>>,
    id: Vec<u8>,
    signer: SigningKey,
    writer: File,
    poisoned: bool,
}
impl Drop for Vault {
    fn drop(&mut self) {
        wipe_json(&mut self.catalog);
        let _ = FileExt::unlock(&self.writer);
    }
}

impl Vault {
    pub fn create(path: &Path, pass: &str, test_kdf: bool) -> Result<(Self, Zeroizing<String>)> {
        ensure!(
            !path.exists() || fs::read_dir(path)?.next().is_none(),
            "le dossier doit être vide"
        );
        fs::create_dir_all(path)?;
        fs::create_dir(path.join("blobs"))?;
        fs::create_dir(path.join("aux"))?;
        let id = c::random(16);
        let master = Zeroizing::new(c::random(32));
        let recovery = Zeroizing::new(c::random(32));
        let seed = Zeroizing::new(c::random(32));
        let signer = SigningKey::from_bytes(seed.as_slice().try_into()?);
        let kdf = json!({"name":"argon2id","iterations":if test_kdf{1}else{3},"lanes":if test_kdf{1}else{4},"memory_cost":if test_kdf{8}else{262144},"salt":hex::encode(c::random(16))});
        let pk = c::passkey(pass, &kdf)?;
        let rk = c::hkdf(&recovery, &id, b"empreinte/v1/recovery-wrap");
        let identity = c::subkey(&master, &id, "identity");
        let header = json!({"format":"empreinte-vault","format_version":1,"vault_id":hex::encode(&id),"public_key":hex::encode(signer.verifying_key().as_bytes()),
            "master_key_wraps":{"passphrase":c::wrap(&pk,&master,&c::aad("passphrase",&id,&c::canonical(&kdf)))?,"recovery":c::wrap(&rk,&master,&c::aad("recovery",&id,&[]))?},
            "identity":c::wrap(&identity,&seed,&c::aad("identity",&id,&[]))?,"kdf":kdf});
        let catalog = json!({"format_version":1,"n_records":0,"head_hash":zeros(),"public_key":header["public_key"],"n_anchors":0,"entries":[],"licenses":[],"royalties":[]});
        let key = c::subkey(&master, &id, "metadata");
        atomic(
            &path.join("catalog.bin"),
            &c::seal(&key, 2, &c::canonical(&catalog), &id, "catalog")?,
        )?;
        atomic(&path.join("ledger.jsonl"), b"")?;
        atomic(&path.join("anchors.jsonl"), b"")?;
        atomic(&path.join("header.json"), &c::canonical(&header))?;
        let recovery_text = Zeroizing::new(c::recovery_text(&recovery));
        Ok((Self::open(path, pass)?, recovery_text))
    }
    pub fn open(path: &Path, pass: &str) -> Result<Self> {
        ensure!(
            !fs::symlink_metadata(path)?.file_type().is_symlink(),
            "racine liée refusée"
        );
        let path = path.canonicalize()?;
        let header: Value =
            serde_json::from_slice(&read_bounded(&path.join("header.json"), 64 * 1024)?)?;
        ensure!(
            header["format"] == "empreinte-vault" && header["format_version"] == 1,
            "format non pris en charge"
        );
        let id = c::bytes(&header["vault_id"])?;
        ensure!(id.len() == 16, "identité invalide");
        let pk = c::passkey(pass, &header["kdf"])?;
        let master = c::unwrap(
            &pk,
            &header["master_key_wraps"]["passphrase"],
            &c::aad("passphrase", &id, &c::canonical(&header["kdf"])),
        )
        .context("phrase de passe incorrecte ou en-tête altéré")?;
        ensure!(master.len() == 32, "clé maître invalide");
        let identity = c::subkey(&master, &id, "identity");
        let seed = c::unwrap(
            &identity,
            &header["identity"],
            &c::aad("identity", &id, &[]),
        )?;
        let signer = SigningKey::from_bytes(seed.as_slice().try_into()?);
        ensure!(
            header["public_key"] == hex::encode(signer.verifying_key().as_bytes()),
            "identité incohérente"
        );
        // OS-held exclusion, shared with the current Python implementation. No truncation.
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            opts.custom_flags(0x00200000);
        }
        let writer = opts.open(path.join("writer.lock"))?;
        ensure!(
            writer.metadata()?.is_file()
                && !fs::symlink_metadata(path.join("writer.lock"))?
                    .file_type()
                    .is_symlink(),
            "verrou non régulier"
        );
        writer
            .try_lock_exclusive()
            .context("archive déjà ouverte par un autre processus")?;
        let key = c::subkey(&master, &id, "metadata");
        let plain = c::open(
            &key,
            2,
            &read_bounded(&path.join("catalog.bin"), MAX_FILE)?,
            &id,
            "catalog",
        )?;
        let catalog = serde_json::from_slice(&plain)?;
        let records = read_lines(&path.join("ledger.jsonl"))?;
        let anchors = read_lines(&path.join("anchors.jsonl"))?;
        let vault = Self {
            path,
            header,
            catalog,
            records,
            anchors,
            master,
            id,
            signer,
            writer,
            poisoned: false,
        };
        vault.check_structure()?;
        Ok(vault)
    }
    pub fn head(&self) -> String {
        self.records
            .last()
            .map(|r| s(r, "record_hash"))
            .unwrap_or_else(zeros)
    }
    fn check_structure(&self) -> Result<()> {
        ensure!(
            self.catalog["format_version"] == 1,
            "version de catalogue non prise en charge"
        );
        ensure!(
            self.catalog["public_key"] == self.header["public_key"],
            "clé du catalogue incohérente"
        );
        check_chain(&self.records, &s(&self.header, "public_key"))?;
        ensure!(
            self.catalog["n_records"].as_u64() == Some(self.records.len() as u64)
                && self.catalog["head_hash"] == self.head(),
            "catalogue désynchronisé : récupération explicite nécessaire"
        );
        ensure!(
            self.catalog["n_anchors"].as_u64() == Some(self.anchors.len() as u64),
            "ancres manquantes ou catalogue désynchronisé"
        );
        for a in &self.anchors {
            let seq = a["seq_upto"]
                .as_u64()
                .ok_or_else(|| anyhow!("ancre invalide"))? as usize;
            ensure!(
                self.records.get(seq).map(|r| &r["record_hash"]) == Some(&a["head_hash"]),
                "ancre hors chaîne"
            );
        }
        let mut ids = std::collections::HashSet::new();
        let mut paths = std::collections::HashSet::new();
        ensure!(
            self.catalog["licenses"].is_array() && self.catalog["royalties"].is_array(),
            "catalogue incomplet"
        );
        for entry in self.catalog["entries"]
            .as_array()
            .ok_or_else(|| anyhow!("catalogue invalide"))?
        {
            let id = s(entry, "entry_id");
            ensure!(
                hex_id(&id, 32) && ids.insert(id.clone()),
                "identifiant dupliqué ou invalide"
            );
            logical_path(&s(entry, "path"))?;
            ensure!(
                entry["tags"].is_array()
                    && entry["versions"].as_array().is_some_and(|a| !a.is_empty()),
                "entrée invalide"
            );
            if entry["removed"] != true {
                ensure!(paths.insert(s(entry, "path")), "chemin dupliqué");
            }
            for (i, v) in entry["versions"]
                .as_array()
                .ok_or_else(|| anyhow!("versions invalides"))?
                .iter()
                .enumerate()
            {
                let seq = v["seq"]
                    .as_u64()
                    .ok_or_else(|| anyhow!("séquence invalide"))?
                    as usize;
                let r = self
                    .records
                    .get(seq)
                    .ok_or_else(|| anyhow!("version absente du registre"))?;
                ensure!(
                    r["kind"] == "put" && r["entry_id"] == id && v["version"] == i + 1,
                    "version incohérente"
                );
                for field in ["version", "commitment", "cipher_hash", "size", "timestamp"] {
                    ensure!(
                        r[field] == v[field],
                        "catalogue/registre incohérents : {field}"
                    );
                }
            }
        }
        Ok(())
    }
    fn writable(&self) -> Result<()> {
        ensure!(
            !self.poisoned,
            "écriture incertaine : fermer et diagnostiquer l'archive"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let held = self.writer.metadata()?;
            let current = fs::symlink_metadata(self.path.join("writer.lock"))?;
            ensure!(
                held.dev() == current.dev() && held.ino() == current.ino(),
                "verrou remplacé : réouvrir l'archive"
            );
        }
        let disk = read_lines(&self.path.join("ledger.jsonl"))?;
        ensure!(disk == self.records, "registre modifié par un autre auteur");
        ensure!(
            serde_json::from_slice::<Value>(&read_bounded(
                &self.path.join("header.json"),
                64 * 1024
            )?)? == self.header,
            "en-tête modifié"
        );
        Ok(())
    }
    fn save_catalog(&self) -> Result<()> {
        let key = c::subkey(&self.master, &self.id, "metadata");
        let plain = Zeroizing::new(c::canonical(&self.catalog));
        atomic(
            &self.path.join("catalog.bin"),
            &c::seal(&key, 2, &plain, &self.id, "catalog")?,
        )
    }
    fn append(&mut self, mut record: Value) -> Result<Value> {
        record["seq"] = json!(self.records.len());
        record["prev_hash"] = json!(self.head());
        let body = body_digest(&record, &s(&self.header, "public_key"));
        let hash = c::hash(&[hex::decode(self.head())?, body].concat());
        record["record_hash"] = json!(hash);
        record["signature"] = json!(hex::encode(
            self.signer
                .sign(
                    &[
                        b"empreinte/v1/record\0".as_slice(),
                        &hex::decode(s(&record, "record_hash"))?
                    ]
                    .concat()
                )
                .to_bytes()
        ));
        // Any I/O failure leaves this instance permanently unwritable.
        self.poisoned = true;
        let path = self.path.join("ledger.jsonl");
        ensure!(
            !fs::symlink_metadata(&path)?.file_type().is_symlink(),
            "registre lié refusé"
        );
        let mut f = OpenOptions::new().append(true).open(path)?;
        f.write_all(&[c::canonical(&record), b"\n".to_vec()].concat())?;
        f.sync_all()?;
        self.records.push(record.clone());
        self.catalog["n_records"] = json!(self.records.len());
        self.catalog["head_hash"] = json!(self.head());
        Ok(record)
    }
    pub fn entries(&self) -> Vec<Value> {
        let mut out = self.catalog["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["removed"] != true)
            .map(entry_meta)
            .collect::<Vec<_>>();
        out.sort_by_key(|e| s(e, "path"));
        out
    }
    pub fn entry(&self, id: &str) -> Result<&Value> {
        self.catalog["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["entry_id"] == id)
            .ok_or_else(|| anyhow!("entrée introuvable"))
    }
    pub fn version(&self, id: &str, number: Option<usize>) -> Result<&Value> {
        let list = self.entry(id)?["versions"]
            .as_array()
            .ok_or_else(|| anyhow!("versions invalides"))?;
        let n = number.unwrap_or(list.len());
        ensure!(n > 0, "version invalide");
        list.get(n - 1)
            .ok_or_else(|| anyhow!("version introuvable"))
    }
    pub fn versions(&self, id: &str) -> Result<Vec<Value>> {
        Ok(self.entry(id)?["versions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| public_version(id, v))
            .collect())
    }
    pub fn read(&self, id: &str, number: Option<usize>) -> Result<Zeroizing<Vec<u8>>> {
        let v = self.version(id, number)?;
        let hash = s(v, "cipher_hash");
        let data = read_bounded(&self.blob_path(&hash)?, MAX_FILE)?;
        ensure!(c::hash(&data) == hash, "hachage du blob invalide");
        let key = c::subkey(&self.master, &self.id, "content");
        let plain = c::open(
            &key,
            1,
            &data,
            &self.id,
            &format!("content:{id}:{}", v["version"]),
        )?;
        let (meta, body) = c::unpack(&plain)?;
        ensure!(
            meta["salt"] == v["salt"]
                && c::hash(&[c::bytes(&v["salt"])?, body.to_vec()].concat()) == v["commitment"],
            "engagement invalide"
        );
        ensure!(
            body.len() as u64 == v["size"].as_u64().unwrap_or(u64::MAX),
            "taille incohérente"
        );
        Ok(body)
    }
    fn blob_path(&self, hash: &str) -> Result<PathBuf> {
        ensure!(hex_id(hash, 64), "hachage invalide");
        Ok(self.path.join("blobs").join(&hash[..2]).join(hash))
    }
    pub fn put(
        &mut self,
        path: &str,
        body: &[u8],
        media: &str,
        mtime: Option<&str>,
    ) -> Result<Value> {
        self.writable()?;
        logical_path(path)?;
        ensure!(body.len() as u64 <= MAX_FILE - 8192, "document trop grand");
        let existing = self.catalog["entries"]
            .as_array()
            .unwrap()
            .iter()
            .position(|e| e["path"] == path && e["removed"] != true);
        if let Some(i) = existing {
            let id = s(&self.catalog["entries"][i], "entry_id");
            if &*self.read(&id, None)? == body {
                return Ok(public_version(&id, self.version(&id, None)?));
            }
        }
        let id = existing
            .map(|i| s(&self.catalog["entries"][i], "entry_id"))
            .unwrap_or_else(|| hex::encode(c::random(16)));
        let number = existing
            .map(|i| {
                self.catalog["entries"][i]["versions"]
                    .as_array()
                    .unwrap()
                    .len()
                    + 1
            })
            .unwrap_or(1);
        let default_title = Path::new(path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(path);
        let title = existing
            .map(|i| s(&self.catalog["entries"][i], "title"))
            .unwrap_or_else(|| default_title.to_owned());
        let kind = if crate::workspace::is_text(media) {
            "note"
        } else {
            "file"
        };
        let salt = c::random(32);
        let commitment = c::hash(&[salt.as_slice(), body].concat());
        let timestamp = now();
        let meta = json!({"path":path,"title":title,"kind":kind,"tags":[],"media_type":media,"salt":hex::encode(&salt),"source_mtime":mtime});
        let key = c::subkey(&self.master, &self.id, "content");
        let packed = c::pack(&meta, body);
        let blob = c::seal(
            &key,
            1,
            &packed,
            &self.id,
            &format!("content:{id}:{number}"),
        )?;
        let hash = c::hash(&blob);
        atomic(&self.blob_path(&hash)?, &blob)?;
        let r=self.append(json!({"kind":"put","entry_id":id,"version":number,"commitment":commitment,"cipher_hash":hash,"size":body.len(),"timestamp":timestamp}))?;
        let v = json!({"version":number,"seq":r["seq"],"timestamp":timestamp,"size":body.len(),"commitment":commitment,"salt":hex::encode(salt),"cipher_hash":hash,"source_mtime":mtime});
        if let Some(i) = existing {
            let e = &mut self.catalog["entries"][i];
            e["versions"].as_array_mut().unwrap().push(v.clone());
            e["media_type"] = json!(media);
            e["kind"] = json!(kind);
            e["tags"] = json!([]);
        } else {
            self.catalog["entries"].as_array_mut().unwrap().push(json!({"entry_id":id,"path":path,"title":title,"kind":kind,"media_type":media,"tags":[],"removed":false,"versions":[v.clone()]}));
        }
        self.save_catalog()?;
        self.poisoned = false;
        Ok(public_version(&id, &v))
    }
    pub fn remove(&mut self, id: &str) -> Result<()> {
        self.writable()?;
        let e = self.entry(id)?;
        ensure!(e["removed"] != true, "entrée déjà retirée");
        let n = e["versions"].as_array().unwrap().len();
        self.append(json!({"kind":"remove","entry_id":id,"version":n,"commitment":"","cipher_hash":"","size":0,"timestamp":now()}))?;
        for e in self.catalog["entries"].as_array_mut().unwrap() {
            if e["entry_id"] == id {
                e["removed"] = json!(true);
            }
        }
        self.save_catalog()?;
        self.poisoned = false;
        Ok(())
    }
    pub fn verify(&self) -> Value {
        let result = (|| -> Result<usize> {
            self.check_structure()?;
            self.writable()?;
            let key = c::subkey(&self.master, &self.id, "metadata");
            let disk = c::open(
                &key,
                2,
                &read_bounded(&self.path.join("catalog.bin"), MAX_FILE)?,
                &self.id,
                "catalog",
            )?;
            ensure!(
                serde_json::from_slice::<Value>(&disk)? == self.catalog,
                "catalogue modifié sur disque"
            );
            ensure!(
                read_lines(&self.path.join("anchors.jsonl"))? == self.anchors,
                "ancres modifiées sur disque"
            );
            let mut count = 0;
            for e in self.catalog["entries"].as_array().unwrap() {
                for v in e["versions"].as_array().unwrap() {
                    self.read(&s(e, "entry_id"), v["version"].as_u64().map(|n| n as usize))?;
                    count += 1;
                }
            }
            for (field, kind, label) in [("licenses", 4, "license"), ("royalties", 5, "royalty")] {
                for item in self.catalog[field].as_array().unwrap() {
                    let seq = item["seq"]
                        .as_u64()
                        .ok_or_else(|| anyhow!("séquence de licence invalide"))?
                        as usize;
                    let record = self
                        .records
                        .get(seq)
                        .ok_or_else(|| anyhow!("licence absente du registre"))?;
                    ensure!(
                        record["kind"] == label && record["cipher_hash"] == item["cipher_hash"],
                        "licence incohérente"
                    );
                    let hash = s(item, "cipher_hash");
                    let data = read_bounded(&self.blob_path(&hash)?, MAX_FILE)?;
                    ensure!(c::hash(&data) == hash, "blob de licence altéré");
                    let key = c::subkey(&self.master, &self.id, "license");
                    let plain = c::open(&key, kind, &data, &self.id, &format!("{label}:{seq}"))?;
                    let (meta, body) = c::unpack(&plain)?;
                    ensure!(
                        meta["salt"] == item["salt"]
                            && body.as_slice() == s(item, "committed").as_bytes(),
                        "licence altérée"
                    );
                    ensure!(
                        c::hash(&[c::bytes(&item["salt"])?, body.to_vec()].concat())
                            == record["commitment"],
                        "engagement de licence invalide"
                    );
                    count += 1;
                }
            }
            ensure!(
                self.anchors.is_empty(),
                "validation RFC 3161 non encore portée : utiliser le vérificateur Python"
            );
            Ok(count)
        })();
        json!({"ok":result.is_ok(),"n_records":self.records.len(),"head_hash":self.head(),"signatures_checked":self.records.len(),"blobs_checked":result.as_ref().copied().unwrap_or(0),"anchors_checked":0,"errors":result.err().map(|e|vec![e.to_string()]).unwrap_or_default()})
    }
    pub fn proof(&self, id: &str, number: Option<usize>) -> Result<Value> {
        let v = self.version(id, number)?;
        let seq = v["seq"].as_u64().unwrap() as usize;
        check_chain(&self.records, &s(&self.header, "public_key"))?;
        Ok(
            json!({"record":self.records[seq],"public_key":self.header["public_key"],"head_hash":self.head(),"n_following":self.records.len()-seq-1,"anchors":[],"anchor_assessments":[],"proven_before":null,"claimed_before":null,"anchor_errors":if self.anchors.is_empty(){vec![]}else{vec!["Ancres existantes non validées par cette version Rust."]},"verified":true}),
        )
    }
    fn aux_path(&self, key: &str) -> (PathBuf, String) {
        let name_key = c::subkey(&self.master, &self.id, "aux-name");
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&name_key).unwrap();
        mac.update(key.as_bytes());
        let name = hex::encode(mac.finalize().into_bytes());
        (self.path.join("aux").join(&name[..2]).join(&name), name)
    }
    pub fn aux_get(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let (path, name) = self.aux_path(key);
        if !path.exists() {
            return Ok(None);
        }
        let k = c::subkey(&self.master, &self.id, "aux");
        Ok(Some(c::open(
            &k,
            3,
            &read_bounded(&path, 16 * 1024 * 1024)?,
            &self.id,
            &format!("aux:{name}"),
        )?))
    }
    pub fn aux_put(&self, key: &str, value: &[u8]) -> Result<()> {
        self.writable()?;
        ensure!(
            value.len() < 16 * 1024 * 1024,
            "valeur auxiliaire trop grande"
        );
        let (path, name) = self.aux_path(key);
        let k = c::subkey(&self.master, &self.id, "aux");
        atomic(
            &path,
            &c::seal(&k, 3, value, &self.id, &format!("aux:{name}"))?,
        )
    }
}
pub fn hex_id(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn logical_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && !path.starts_with('/')
            && !path.contains(['\\', ':', '\0'])
            && path
                .split('/')
                .all(|p| !p.is_empty() && p != "." && p != ".."),
        "chemin logique invalide"
    );
    Ok(())
}
pub fn read_lines(path: &Path) -> Result<Vec<Value>> {
    let bytes = read_bounded(path, MAX_FILE)?;
    ensure!(
        bytes.is_empty() || bytes.last() == Some(&b'\n'),
        "registre tronqué"
    );
    bytes
        .split(|b| *b == b'\n')
        .filter(|b| !b.is_empty())
        .map(|line| Ok(serde_json::from_slice(line)?))
        .collect()
}
pub fn body_digest(r: &Value, key: &str) -> Vec<u8> {
    hex::decode(c::hash(&c::canonical(&json!({"cipher_hash":r["cipher_hash"],"commitment":r["commitment"],"entry_id":r["entry_id"],"format":1,"key":key,"kind":r["kind"],"seq":r["seq"],"size":r["size"],"timestamp":r["timestamp"],"version":r["version"]})))).unwrap()
}
pub fn check_chain(records: &[Value], key: &str) -> Result<()> {
    let public = VerifyingKey::from_bytes(
        &hex::decode(key)?
            .try_into()
            .map_err(|_| anyhow!("clé publique invalide"))?,
    )?;
    let mut prev = zeros();
    for (i, r) in records.iter().enumerate() {
        ensure!(
            r["seq"].as_u64() == Some(i as u64) && r["prev_hash"] == prev,
            "chaîne discontinue"
        );
        let timestamp = s(r, "timestamp");
        let time = chrono::DateTime::parse_from_rfc3339(&timestamp)?;
        ensure!(
            time.with_timezone(&Utc)
                .format("%Y-%m-%dT%H:%M:%S%.6fZ")
                .to_string()
                == timestamp,
            "date non canonique"
        );
        let hash = c::hash(&[hex::decode(&prev)?, body_digest(r, key)].concat());
        ensure!(r["record_hash"] == hash, "hachage de registre invalide");
        let sig = Signature::from_slice(&c::bytes(&r["signature"])?)?;
        public.verify_strict(
            &[b"empreinte/v1/record\0".as_slice(), &hex::decode(&hash)?].concat(),
            &sig,
        )?;
        prev = hash;
    }
    Ok(())
}
pub fn public_version(id: &str, v: &Value) -> Value {
    json!({"entry_id":id,"version":v["version"],"seq":v["seq"],"timestamp":v["timestamp"],"size":v["size"],"commitment":v["commitment"],"source_mtime":v["source_mtime"]})
}
pub fn entry_meta(e: &Value) -> Value {
    let vs = e["versions"].as_array().unwrap();
    let first = &vs[0];
    let last = vs.last().unwrap();
    let earliest = vs.iter().filter_map(|v| v["source_mtime"].as_str()).min();
    json!({"entry_id":e["entry_id"],"path":e["path"],"title":e["title"],"kind":e["kind"],"media_type":e["media_type"],"tags":e["tags"],"n_versions":vs.len(),"size":last["size"],"created_at":first["timestamp"],"updated_at":last["timestamp"],"authored_at":earliest,"modified_at":last["source_mtime"]})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn create_reopen_version_lock_and_tamper() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault");
        let (mut v, recovery) = Vault::create(&path, "test", true).unwrap();
        assert_eq!(recovery.replace('-', "").len(), 55);
        let a = v
            .put("Notes/école.md", b"secret", "text/markdown", None)
            .unwrap();
        let id = s(&a, "entry_id");
        assert_eq!(
            v.put("Notes/école.md", b"secret", "text/markdown", None)
                .unwrap(),
            a
        );
        v.put("Notes/école.md", b"revision", "text/markdown", None)
            .unwrap();
        assert!(Vault::open(&path, "test").is_err());
        assert_eq!(v.verify()["ok"], true);
        drop(v);
        assert!(Vault::open(&path, "wrong").is_err());
        let v = Vault::open(&path, "test").unwrap();
        assert_eq!(&*v.read(&id, Some(1)).unwrap(), b"secret");
        assert_eq!(&*v.read(&id, None).unwrap(), b"revision");
        fs::write(path.join("ledger.jsonl"), b"").unwrap();
        assert_eq!(v.verify()["ok"], false);
        drop(v);
        assert!(Vault::open(&path, "test").is_err());
    }
    #[test]
    #[cfg(unix)]
    fn lock_symlink_never_truncates_target() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault");
        drop(Vault::create(&path, "test", true).unwrap());
        let victim = tmp.path().join("victim");
        fs::write(&victim, b"keep").unwrap();
        fs::remove_file(path.join("writer.lock")).unwrap();
        std::os::unix::fs::symlink(&victim, path.join("writer.lock")).unwrap();
        assert!(Vault::open(&path, "test").is_err());
        assert_eq!(fs::read(victim).unwrap(), b"keep");
    }
}
