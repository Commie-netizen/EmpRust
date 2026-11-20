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
    via_recovery: bool,
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
        Self::open_using(path, pass, false)
    }
    pub fn open_recovery(path: &Path, recovery: &str) -> Result<Self> {
        Self::open_using(path, recovery, true)
    }
    fn open_using(path: &Path, pass: &str, via_recovery: bool) -> Result<Self> {
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
        let master = if via_recovery {
            let raw = c::parse_recovery(pass)?;
            let key = c::hkdf(&raw, &id, b"empreinte/v1/recovery-wrap");
            c::unwrap(
                &key,
                &header["master_key_wraps"]["recovery"],
                &c::aad("recovery", &id, &[]),
            )?
        } else {
            let pk = c::passkey(pass, &header["kdf"])?;
            c::unwrap(
                &pk,
                &header["master_key_wraps"]["passphrase"],
                &c::aad("passphrase", &id, &c::canonical(&header["kdf"])),
            )
            .context("phrase de passe incorrecte ou en-tête altéré")?
        };
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
            via_recovery,
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
    pub fn change_passphrase(&mut self, old: &str, new: &str) -> Result<()> {
        use subtle::ConstantTimeEq;
        self.writable()?;
        let key = c::passkey(old, &self.header["kdf"])?;
        let master = c::unwrap(
            &key,
            &self.header["master_key_wraps"]["passphrase"],
            &c::aad("passphrase", &self.id, &c::canonical(&self.header["kdf"])),
        )?;
        ensure!(
            bool::from(master.as_slice().ct_eq(self.master.as_slice())),
            "phrase actuelle incorrecte"
        );
        self.replace_passphrase(new)
    }
    pub fn reset_passphrase(&mut self, new: &str) -> Result<()> {
        ensure!(self.via_recovery, "ouverture par clé de secours requise");
        self.replace_passphrase(new)
    }
    fn replace_passphrase(&mut self, new: &str) -> Result<()> {
        self.writable()?;
        let mut header = self.header.clone();
        header["kdf"]["salt"] = json!(hex::encode(c::random(16)));
        let key = c::passkey(new, &header["kdf"])?;
        header["master_key_wraps"]["passphrase"] = c::wrap(
            &key,
            &self.master,
            &c::aad("passphrase", &self.id, &c::canonical(&header["kdf"])),
        )?;
        self.poisoned = true;
        atomic(&self.path.join("header.json"), &c::canonical(&header))?;
        self.header = header;
        self.poisoned = false;
        self.via_recovery = false;
        Ok(())
    }
    pub fn rotate_recovery_key(&mut self) -> Result<Zeroizing<String>> {
        self.writable()?;
        let raw = Zeroizing::new(c::random(32));
        let key = c::hkdf(&raw, &self.id, b"empreinte/v1/recovery-wrap");
        let mut header = self.header.clone();
        header["master_key_wraps"]["recovery"] =
            c::wrap(&key, &self.master, &c::aad("recovery", &self.id, &[]))?;
        self.poisoned = true;
        atomic(&self.path.join("header.json"), &c::canonical(&header))?;
        self.header = header;
        self.poisoned = false;
        Ok(Zeroizing::new(c::recovery_text(&raw)))
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
            if self.read(&id, None)?.as_slice() == body {
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
        let result = (|| -> Result<(usize, usize)> {
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
            let mut anchors_checked = 0;
            for a in &self.anchors {
                let seq = a["seq_upto"]
                    .as_u64()
                    .ok_or_else(|| anyhow!("seq_upto manquant"))?
                    as usize;
                ensure!(seq < self.records.len(), "seq_upto dépasse le registre");
                let rec = &self.records[seq];
                let expected_head = s(rec, "record_hash");
                ensure!(
                    s(a, "head_hash") == expected_head,
                    "head_hash de l'ancre ne correspond pas au record_hash"
                );
                let proof_b64 = s(a, "proof");
                let head_bytes = hex::decode(expected_head)?;
                let eval = crate::anchor::evaluate_token(&proof_b64, &head_bytes)?;
                ensure!(
                    eval["status"] != "invalid",
                    "ancre invalide: {}",
                    eval["error"].as_str().unwrap_or("erreur de jeton")
                );
                anchors_checked += 1;
            }
            Ok((count, anchors_checked))
        })();
        let (blobs_checked, anchors_checked) = result.as_ref().copied().unwrap_or((0, 0));
        json!({
            "ok": result.is_ok(),
            "n_records": self.records.len(),
            "head_hash": self.head(),
            "signatures_checked": self.records.len(),
            "blobs_checked": blobs_checked,
            "anchors_checked": anchors_checked,
            "errors": result.err().map(|e| vec![e.to_string()]).unwrap_or_default()
        })
    }
    pub fn proof(&self, id: &str, number: Option<usize>) -> Result<Value> {
        let v = self.version(id, number)?;
        let seq = v["seq"].as_u64().unwrap() as usize;
        check_chain(&self.records, &s(&self.header, "public_key"))?;

        let mut matching_anchors = Vec::new();
        let mut anchor_assessments = Vec::new();
        let mut proven_before: Option<String> = None;
        let mut claimed_before: Option<String> = None;
        let mut anchor_errors = Vec::new();

        for a in &self.anchors {
            let a_seq = a["seq_upto"].as_u64().unwrap_or(0) as usize;
            if a_seq >= seq {
                matching_anchors.push(a.clone());
                let proof_b64 = s(a, "proof");
                if let Ok(head_bytes) = hex::decode(s(a, "head_hash")) {
                    if let Ok(eval) = crate::anchor::evaluate_token(&proof_b64, &head_bytes) {
                        let st = eval["status"].as_str().unwrap_or("invalid");
                        anchor_assessments.push(json!({
                            "seq_upto": a_seq,
                            "status": st,
                            "anchored_at": a["anchored_at"]
                        }));
                        if st == "proven" {
                            let t = s(a, "anchored_at").to_string();
                            if proven_before.is_none() || proven_before.as_deref() > Some(&t) {
                                proven_before = Some(t);
                            }
                        } else if st == "claimed" {
                            let t = s(a, "anchored_at").to_string();
                            if claimed_before.is_none() || claimed_before.as_deref() > Some(&t) {
                                claimed_before = Some(t);
                            }
                        } else if let Some(err) = eval["error"].as_str() {
                            anchor_errors.push(err.to_string());
                        }
                    }
                }
            }
        }

        Ok(json!({
            "record": self.records[seq],
            "public_key": self.header["public_key"],
            "head_hash": self.head(),
            "n_following": self.records.len() - seq - 1,
            "anchors": matching_anchors,
            "anchor_assessments": anchor_assessments,
            "proven_before": proven_before,
            "claimed_before": claimed_before,
            "anchor_errors": anchor_errors,
            "verified": true
        }))
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

    fn commit_document(&mut self, kind: &str, document: Value) -> Result<Value> {
        self.writable()?;
        let seq = self.records.len();
        let timestamp = now();
        let body = Zeroizing::new(c::canonical(&document));
        let salt = c::random(32);
        let key = c::subkey(&self.master, &self.id, "license");
        let blob = c::seal(
            &key,
            if kind == "license" { 4 } else { 5 },
            &c::pack(&json!({"salt":hex::encode(&salt)}), &body),
            &self.id,
            &format!("{kind}:{seq}"),
        )?;
        let cipher_hash = c::hash(&blob);
        atomic(&self.blob_path(&cipher_hash)?, &blob)?;
        self.append(json!({"kind":kind,"entry_id":"","version":0,"size":0,"commitment":c::hash(&[salt.as_slice(),body.as_slice()].concat()),"cipher_hash":cipher_hash,"timestamp":timestamp}))?;
        let state = json!({"seq":seq,"committed":std::str::from_utf8(&body)?,"salt":hex::encode(salt),"cipher_hash":cipher_hash,"bundle_hash":""});
        self.catalog[if kind == "license" {
            "licenses"
        } else {
            "royalties"
        }]
        .as_array_mut()
        .unwrap()
        .push(state);
        self.save_catalog()?;
        self.poisoned = false;
        Ok(document)
    }
    pub fn licenses(&self) -> Result<Vec<Value>> {
        self.catalog["licenses"]
            .as_array()
            .unwrap()
            .iter()
            .map(|state| {
                let mut grant: Value = serde_json::from_str(&s(state, "committed"))?;
                grant["bundle_hash"] = state["bundle_hash"].clone();
                Ok(grant)
            })
            .collect()
    }
    pub fn royalties(&self, license_id: Option<&str>) -> Result<Vec<Value>> {
        let all = self.catalog["royalties"]
            .as_array()
            .unwrap()
            .iter()
            .map(|state| serde_json::from_str::<Value>(&s(state, "committed")))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(all
            .into_iter()
            .filter(|e| license_id.is_none_or(|id| e["license_id"] == id))
            .collect())
    }
    pub fn grant(&mut self, request: &Value) -> Result<Value> {
        let licensee = bounded_text(request, "licensee", 1, 200)?;
        let usage = bounded_text(request, "usage", 1, 1000)?;
        let terms = bounded_text(request, "terms", 0, 20000)?;
        let raw = request["items"]
            .as_array()
            .ok_or_else(|| anyhow!("liste des documents requise"))?;
        ensure!(
            !raw.is_empty() && raw.len() <= 1000,
            "1 à 1000 documents requis"
        );
        let mut seen = std::collections::HashSet::new();
        let mut items = Vec::new();
        for item in raw {
            let id = s(item, "entry_id");
            let number = if item["version"].is_null() {
                None
            } else {
                Some(
                    item["version"]
                        .as_u64()
                        .ok_or_else(|| anyhow!("version invalide"))? as usize,
                )
            };
            let entry = self.entry(&id)?;
            let version = self.version(&id, number)?;
            ensure!(
                seen.insert((id.clone(), version["version"].as_u64().unwrap())),
                "document dupliqué dans la licence"
            );
            items.push(json!({"entry_id":id,"version":version["version"],"title":entry["title"],"commitment":version["commitment"]}));
        }
        let r = &request["royalty"];
        let model = r["model"].as_str().unwrap_or("none");
        ensure!(
            ["none", "flat", "per_use", "revenue_share"].contains(&model),
            "modèle de redevance invalide"
        );
        let amount = r["amount"].as_f64().unwrap_or(0.0);
        ensure!(
            amount.is_finite()
                && amount >= 0.0
                && amount
                    <= if model == "revenue_share" {
                        100.0
                    } else {
                        1e12
                    },
            "montant invalide"
        );
        let currency = r["currency"].as_str().unwrap_or("EUR");
        currency_ok(currency)?;
        let note = bounded_text(r, "note", 0, 500)?;
        let until = optional_date(&request["valid_until"])?;
        let doc = json!({"license_id":hex::encode(c::random(16)),"licensee":licensee,"usage":usage,"terms":terms,"items":items,"royalty":{"model":model,"amount":amount,"currency":currency,"note":note},"created_at":now(),"valid_until":until,"seq":self.records.len(),"bundle_hash":""});
        self.commit_document("license", doc)
    }
    pub fn record_royalty(&mut self, request: &Value) -> Result<Value> {
        let id = s(request, "license_id");
        ensure!(
            self.licenses()?.iter().any(|g| g["license_id"] == id),
            "licence inconnue"
        );
        let amount = request["amount"]
            .as_f64()
            .ok_or_else(|| anyhow!("montant numérique requis"))?;
        ensure!(
            amount.is_finite() && amount != 0.0 && amount.abs() <= 1e12,
            "montant invalide"
        );
        let currency = request["currency"].as_str().unwrap_or("EUR");
        currency_ok(currency)?;
        let day = optional_date(&request["received_on"])?
            .unwrap_or_else(|| Utc::now().format("%Y-%m-%d").to_string());
        let doc = json!({"license_id":id,"amount":amount,"currency":currency,"received_on":day,"period":bounded_text(request,"period",0,40)?,"note":bounded_text(request,"note",0,500)?,"seq":self.records.len()});
        self.commit_document("royalty", doc)
    }
    pub fn export_bundle(&mut self, id: &str, out: &Path) -> Result<Value> {
        self.writable()?;
        ensure!(hex_id(id, 32), "identifiant de licence invalide");
        ensure!(
            self.anchors.is_empty(),
            "export avec ancres RFC 3161 : utiliser encore la version Python"
        );
        let index = self.catalog["licenses"]
            .as_array()
            .unwrap()
            .iter()
            .position(|state| {
                serde_json::from_str::<Value>(&s(state, "committed"))
                    .is_ok_and(|g| g["license_id"] == id)
            })
            .ok_or_else(|| anyhow!("licence inconnue"))?;
        let state = self.catalog["licenses"][index].clone();
        let grant: Value = serde_json::from_str(&s(&state, "committed"))?;
        fs::create_dir_all(out)?;
        ensure!(
            !fs::symlink_metadata(out)?.file_type().is_symlink(),
            "répertoire de sortie lié refusé"
        );
        let root = out.canonicalize()?;
        ensure!(
            !root.starts_with(&self.path),
            "export en clair interdit dans le coffre"
        );
        // Unique destination: never erase or overwrite an earlier disclosure.
        let bundle = root.join(format!("license-{id}-{}", hex::encode(c::random(4))));
        fs::create_dir(&bundle)?;
        fs::create_dir(bundle.join("items"))?;
        let mut first = state["seq"].as_u64().unwrap() as usize;
        let mut manifest_items = Vec::new();
        for (i, item) in grant["items"].as_array().unwrap().iter().enumerate() {
            let entry_id = s(item, "entry_id");
            let n = item["version"]
                .as_u64()
                .ok_or_else(|| anyhow!("version invalide"))? as usize;
            let entry = self.entry(&entry_id)?;
            let version = self.version(&entry_id, Some(n))?;
            let seq = version["seq"].as_u64().unwrap() as usize;
            first = first.min(seq);
            ensure!(
                item["commitment"] == version["commitment"],
                "engagement de licence incohérent"
            );
            let ext = match entry["media_type"].as_str().unwrap_or("") {
                "text/markdown" => "md",
                "text/plain" => "txt",
                "application/json" => "json",
                "application/pdf" => "pdf",
                _ => "bin",
            };
            let name = format!("items/{:02}_{entry_id}_v{n}.{ext}", i + 1);
            atomic(&bundle.join(&name), &self.read(&entry_id, Some(n))?)?;
            manifest_items.push(json!({"file":name,"entry_id":entry_id,"version":n,"title":item["title"],"media_type":entry["media_type"],"salt":version["salt"],"record":self.records[seq]}));
        }
        let committed = Zeroizing::new(s(&state, "committed"));
        atomic(&bundle.join("grant.json"), committed.as_bytes())?;
        let head = self.records.last().unwrap();
        let key = s(&self.header, "public_key");
        let manifest = json!({"format":"empreinte-bundle","format_version":1,"license_id":id,"public_key":key,"exported_at":now(),
            "grant":{"file":"grant.json","salt":state["salt"],"signature":hex::encode(self.signer.sign(&[b"empreinte/v1/grant\0".as_slice(),committed.as_bytes()].concat()).to_bytes()),"record":self.records[state["seq"].as_u64().unwrap() as usize]},
            "items":manifest_items,"chain":{"from_seq":first,"prev_hash":self.records[first]["prev_hash"],"body_digests":self.records.iter().skip(first).map(|r|hex::encode(body_digest(r,&key))).collect::<Vec<_>>()},
            "head":{"seq":head["seq"],"record_hash":head["record_hash"],"signature":head["signature"]},"anchors":[]});
        let bytes = serde_json::to_vec_pretty(&manifest)?;
        let bundle_hash = c::hash(&bytes);
        atomic(&bundle.join("manifest.json"), &bytes)?;
        atomic(
            &bundle.join("verify_bundle.py"),
            include_bytes!("../../tools/verify_bundle.py"),
        )?;
        atomic(&bundle.join("README.txt"),b"Empreinte disclosure bundle. Contains ONLY the licensed document versions, in plaintext.\nNo external timestamps. Local ledger dates prove order, not civil time.\nVerify with an independently obtained copy of verify_bundle.py (Python + cryptography).\nCompare the public key with one obtained separately from the author.\n")?;
        self.catalog["licenses"][index]["bundle_hash"] = json!(bundle_hash);
        self.poisoned = true;
        self.save_catalog()?;
        self.poisoned = false;
        Ok(json!({"license_id":id,"path":bundle,"bundle_hash":bundle_hash}))
    }
}
fn bounded_text(value: &Value, key: &str, min: usize, max: usize) -> Result<String> {
    let text = if value[key].is_null() && min == 0 {
        ""
    } else {
        value[key]
            .as_str()
            .ok_or_else(|| anyhow!("texte requis : {key}"))?
    };
    ensure!(
        text.trim().chars().count() >= min && text.chars().count() <= max,
        "longueur invalide : {key}"
    );
    Ok(text.to_owned())
}
fn currency_ok(value: &str) -> Result<()> {
    ensure!(
        value.len() == 3 && value.bytes().all(|c| c.is_ascii_uppercase()),
        "devise invalide"
    );
    Ok(())
}
fn optional_date(value: &Value) -> Result<Option<String>> {
    if value.is_null() {
        return Ok(None);
    }
    let text = value.as_str().ok_or_else(|| anyhow!("date invalide"))?;
    let parsed = chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d")?;
    ensure!(
        parsed.format("%Y-%m-%d").to_string() == text,
        "date non canonique"
    );
    Ok(Some(text.to_owned()))
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
    fn access_rotation_preserves_content_and_revokes_old_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault");
        let (mut v, recovery) = Vault::create(&path, "old", true).unwrap();
        let item = v.put("a.md", b"preserved", "text/markdown", None).unwrap();
        let original_header = v.header.clone();
        let original_head = v.head();
        assert!(v.reset_passphrase("unauthorized").is_err());
        assert!(v.change_passphrase("wrong", "new").is_err());
        assert!(v.change_passphrase("old", "").is_err());
        assert_eq!(v.header, original_header);
        v.change_passphrase("old", "new").unwrap();
        drop(v);
        assert!(Vault::open(&path, "old").is_err());
        let v = Vault::open(&path, "new").unwrap();
        assert_eq!(v.head(), original_head);
        drop(v);
        let mut v = Vault::open_recovery(&path, &recovery).unwrap();
        v.reset_passphrase("recovered").unwrap();
        let new_recovery = v.rotate_recovery_key().unwrap();
        drop(v);
        assert!(Vault::open_recovery(&path, &recovery).is_err());
        let v = Vault::open_recovery(&path, &new_recovery.to_ascii_lowercase()).unwrap();
        assert_eq!(
            v.read(&s(&item, "entry_id"), None).unwrap().as_slice(),
            b"preserved"
        );
        assert_eq!(v.verify()["ok"], true);
        drop(v);
        assert!(Vault::open(&path, "new").is_err());
        assert!(Vault::open(&path, "recovered").is_ok());
        assert!(c::parse_recovery("invalid").is_err());
    }
    #[test]
    fn licensing_rejects_duplicates_and_exports_only_selected_version() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault");
        let (mut v, _) = Vault::create(&path, "test", true).unwrap();
        let item = v
            .put("selected.md", b"licensed version", "text/markdown", None)
            .unwrap();
        v.put("selected.md", b"private revision", "text/markdown", None)
            .unwrap();
        v.put("private.md", b"unlicensed", "text/markdown", None)
            .unwrap();
        let request = json!({"licensee":"Test","usage":"Evaluation","items":[{"entry_id":item["entry_id"],"version":1}]});
        let mut duplicate = request.clone();
        duplicate["items"]
            .as_array_mut()
            .unwrap()
            .push(request["items"][0].clone());
        let count = v.records.len();
        assert!(v.grant(&duplicate).is_err());
        assert_eq!(v.records.len(), count);
        let grant = v.grant(&request).unwrap();
        assert!(
            v.record_royalty(&json!({"license_id":grant["license_id"],"amount":0}))
                .is_err()
        );
        assert!(
            v.record_royalty(&json!({"license_id":"missing","amount":1}))
                .is_err()
        );
        assert!(
            v.export_bundle(&s(&grant, "license_id"), &path.join("exports"))
                .is_err()
        );
        let output = v
            .export_bundle(&s(&grant, "license_id"), &tmp.path().join("exports"))
            .unwrap();
        let files = fs::read_dir(Path::new(&s(&output, "path")).join("items"))
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(fs::read(files[0].path()).unwrap(), b"licensed version");
        assert_eq!(v.verify()["ok"], true);
        drop(v);
        let v = Vault::open(&path, "test").unwrap();
        assert_eq!(
            v.licenses().unwrap()[0]["bundle_hash"],
            output["bundle_hash"]
        );
    }
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
