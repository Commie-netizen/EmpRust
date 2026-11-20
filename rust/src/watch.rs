//! Capture continue : surveille des dossiers et enregistre les changements dans le vault.
//!
//! Référence : src/empreinte/watch.py et docs/FORMAT.md.
//!
//! Architecture à trois phases (compatible avec le verrou de session du serveur) :
//!   1. `scan(&mut Watcher)` — métadonnées uniquement (lstat), retourne les fichiers dus.
//!   2. `read_due(&Watcher, due)` — lit le contenu des fichiers stables (deux lectures concordantes).
//!   3. `commit(vault, ready)` — enregistre en batch, persiste l'état dans les aux chiffrés.
//!
//! Un fichier est « dû » quand sa taille et sa date de modification n'ont pas changé
//! depuis `quiet` secondes (60 par défaut). Un fichier nouvellement découvert dont la
//! modification est plus ancienne que `quiet` est dû immédiatement.
//!
//! L'état est persisté dans les aux chiffrés du vault :
//!   watch/folders.v1               liste des dossiers surveillés
//!   watch/state.v1/<sha256>        per folder : chemin relatif → [taille, mtime_µs]

use anyhow::{Result, anyhow, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

// ─────────────────────────────────────────── constantes ──────────────────────

pub const FOLDERS_KEY: &str = "watch/folders.v1";
pub const STATE_PREFIX: &str = "watch/state.v1/";
pub const DEFAULT_QUIET_SECS: f64 = 60.0;
pub const DEFAULT_INTERVAL_SECS: f64 = 3.0;
pub const MAX_BYTES: usize = 20_000_000;
pub const MAX_FOLDERS: usize = 32;

// ─────────────────────────────────────────── types ───────────────────────────

/// Un dossier surveillé : chemin absolu + préfixe logique dans l'archive.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WatchedFolder {
    pub path: PathBuf,
    pub prefix: String,
}

impl WatchedFolder {
    /// Clé aux chiffrée pour l'état de ce dossier.
    pub fn state_key(&self) -> String {
        let combined = format!("{}\0{}", self.path.display(), self.prefix);
        let digest = Sha256::digest(combined.as_bytes());
        format!("{STATE_PREFIX}{}", hex::encode(digest))
    }
}

/// Signature d'un fichier : (taille en octets, mtime en microsecondes depuis l'époque Unix).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileSig(pub u64, pub i64);

/// Un fichier candidat trouvé lors du scan.
#[derive(Debug, Clone)]
pub struct SourceFile {
    pub abs_path: PathBuf,
    /// Chemin relatif au dossier surveillé (séparateurs forward slash).
    pub rel_path: String,
    pub sig: FileSig,
    /// Date de modification réelle (mtime, secondes Unix).
    pub mtime_secs: f64,
}

/// Un fichier dû (quiet period écoulée).
#[derive(Debug)]
pub struct Due {
    pub folder: WatchedFolder,
    pub source: SourceFile,
}

/// Un fichier prêt à être commité (lu, stable, contenu en mémoire).
#[derive(Debug)]
pub struct Ready {
    pub folder: WatchedFolder,
    pub source: SourceFile,
    pub content: Vec<u8>,
}

/// Résultat d'une capture.
#[derive(Debug)]
pub struct Capture {
    pub folder_path: String,
    pub logical_path: String,
    pub entry_id: String,
    pub version: u32,
}

// ─────────────────────────────────────── état interne ────────────────────────

/// État interne par dossier surveillé.
#[derive(Debug, Default)]
struct FolderState {
    /// Dernière signature capturée pour chaque chemin relatif.
    known: HashMap<String, FileSig>,
    /// Fichiers en attente de quiet period : rel_path → (sig, since_secs).
    pending: HashMap<String, (FileSig, f64)>,
    dirty: bool,
}

impl FolderState {
    fn from_aux(raw: &[u8]) -> Self {
        let mut state = FolderState::default();
        if let Ok(data) = serde_json::from_slice::<Value>(raw) {
            if let Some(map) = data.as_object() {
                for (k, v) in map {
                    if let Some(arr) = v.as_array() {
                        if arr.len() >= 2 {
                            let size = arr[0].as_u64().unwrap_or(0);
                            let mtime = arr[1].as_i64().unwrap_or(0);
                            state.known.insert(k.clone(), FileSig(size, mtime));
                        }
                    }
                }
            }
        }
        state
    }

    fn to_json(&self) -> Vec<u8> {
        let obj: serde_json::Map<String, Value> = self
            .known
            .iter()
            .map(|(k, FileSig(sz, mt))| (k.clone(), json!([*sz, *mt])))
            .collect();
        serde_json::to_vec(&Value::Object(obj)).unwrap_or_default()
    }
}

// ─────────────────────────────────────────── Watcher ─────────────────────────

/// Surveille un ensemble de dossiers avec une logique de quiet period.
/// Non thread-safe (le verrouillage est géré par l'appelant, typiquement le serveur).
pub struct Watcher {
    pub quiet: f64,
    pub max_bytes: usize,
    folders: Vec<WatchedFolder>,
    states: HashMap<String, FolderState>, // clé = state_key du dossier
    pub captures: u64,
    pub last_capture: Option<String>,
    pub last_error: String,
}

impl Default for Watcher {
    fn default() -> Self {
        Self::new(DEFAULT_QUIET_SECS, MAX_BYTES)
    }
}
impl Watcher {
    pub fn new(quiet: f64, max_bytes: usize) -> Self {
        Watcher {
            quiet,
            max_bytes,
            folders: vec![],
            states: HashMap::new(),
            captures: 0,
            last_capture: None,
            last_error: String::new(),
        }
    }

    /// Charge les dossiers et leur état depuis les aux chiffrés du vault.
    pub fn load<F>(&mut self, aux_get: F)
    where
        F: Fn(&str) -> Option<Vec<u8>>,
    {
        let folders = load_folders_aux(&aux_get);
        let mut states = HashMap::new();
        for folder in &folders {
            let key = folder.state_key();
            let state = aux_get(&key)
                .map(|raw| FolderState::from_aux(&raw))
                .unwrap_or_default();
            states.insert(key, state);
        }
        self.folders = folders;
        self.states = states;
    }

    // ─────────────────────────────── phase 1 : scan ──────────────────────────

    /// Phase 1 : scan métadonnées uniquement. Retourne les fichiers dus.
    pub fn scan(&mut self) -> Vec<Due> {
        let now = unix_secs();
        let mut due = Vec::new();

        for folder in &self.folders {
            let key = folder.state_key();
            let state = self.states.entry(key.clone()).or_default();

            let files = match scan_dir(&folder.path) {
                Ok(f) => f,
                Err(e) => {
                    self.last_error = format!("dossier illisible : {e}");
                    continue;
                }
            };

            let seen: Vec<String> = files.iter().map(|f| f.rel_path.clone()).collect();

            for source in files {
                let rel = source.rel_path.clone();
                if source.sig.0 as usize > self.max_bytes {
                    state.pending.remove(&rel);
                    continue;
                }
                if state.known.get(&rel) == Some(&source.sig) {
                    state.pending.remove(&rel);
                    continue;
                }
                match state.pending.get(&rel).copied() {
                    None => {
                        let age = now - source.mtime_secs;
                        let since = if age >= self.quiet {
                            now - self.quiet
                        } else {
                            now
                        };
                        state.pending.insert(rel.clone(), (source.sig, since));
                    }
                    Some((prev_sig, _)) if prev_sig != source.sig => {
                        // encore en cours d'écriture : repart de zéro
                        state.pending.insert(rel.clone(), (source.sig, now));
                    }
                    _ => {}
                }
                if let Some((_, since)) = state.pending.get(&rel) {
                    if now - since >= self.quiet {
                        due.push(Due {
                            folder: folder.clone(),
                            source,
                        });
                    }
                }
            }

            // Fichiers supprimés ou renommés : on oublie (l'archive garde toutes les versions)
            let seen_set: std::collections::HashSet<&str> =
                seen.iter().map(|s| s.as_str()).collect();
            state.known.retain(|k, _| seen_set.contains(k.as_str()));
            state.pending.retain(|k, _| seen_set.contains(k.as_str()));
        }
        due
    }

    // ─────────────────────────────── phase 2 : read ──────────────────────────

    /// Phase 2 : lit le contenu des fichiers stables (deux lectures concordantes).
    pub fn read_due(&mut self, due: Vec<Due>) -> Vec<Ready> {
        let mut ready = Vec::new();
        for item in due {
            match stable_read(&item.source.abs_path, self.max_bytes) {
                Ok((content, final_sig)) if final_sig == item.source.sig => {
                    ready.push(Ready {
                        folder: item.folder,
                        source: item.source,
                        content,
                    });
                }
                _ => {
                    // Instable ou trop grand : repart de zéro pour la quiet period
                    let key = item.folder.state_key();
                    if let Some(state) = self.states.get_mut(&key) {
                        state
                            .pending
                            .insert(item.source.rel_path.clone(), (item.source.sig, unix_secs()));
                    }
                }
            }
        }
        ready
    }

    // ─────────────────────────────── phase 3 : commit ────────────────────────

    /// Phase 3 : enregistre en batch dans le vault, persiste l'état.
    ///
    /// `put_fn(logical_path, content, mtime_secs) -> Result<(entry_id, version)>`
    /// `aux_put(key, data)` persiste l'état chiffré.
    pub fn commit<P, A>(
        &mut self,
        ready: Vec<Ready>,
        mut put_fn: P,
        mut aux_put: A,
    ) -> Result<Vec<Capture>>
    where
        P: FnMut(&str, &[u8], f64) -> Result<(String, u32)>,
        A: FnMut(&str, &[u8]),
    {
        let mut captures = Vec::new();
        let mut captured: Vec<(WatchedFolder, SourceFile)> = Vec::new();

        for item in ready {
            let logical = if item.folder.prefix.is_empty() {
                item.source.rel_path.clone()
            } else {
                format!("{}/{}", item.folder.prefix, item.source.rel_path)
            };
            match put_fn(&logical, &item.content, item.source.mtime_secs) {
                Ok((entry_id, version)) => {
                    captures.push(Capture {
                        folder_path: item.folder.path.to_string_lossy().into_owned(),
                        logical_path: logical,
                        entry_id,
                        version,
                    });
                    captured.push((item.folder, item.source));
                }
                Err(e) => {
                    self.last_error = format!("put échoué : {e}");
                }
            }
        }

        // Mise à jour de l'état et persistance
        let mut to_save: Vec<(String, Vec<u8>)> = Vec::new();
        for (folder, source) in captured {
            let key = folder.state_key();
            let state = self.states.entry(key.clone()).or_default();
            state.known.insert(source.rel_path.clone(), source.sig);
            state.pending.remove(&source.rel_path);
            state.dirty = true;
        }
        for (folder_key, state) in &mut self.states {
            if state.dirty {
                to_save.push((folder_key.clone(), state.to_json()));
                state.dirty = false;
            }
        }
        for (key, data) in &to_save {
            aux_put(key, data);
        }

        self.captures += captures.len() as u64;
        if let Some(last) = captures.last() {
            self.last_capture = Some(crate::vault::now());
            let _ = last;
        }

        Ok(captures)
    }

    /// Poll en une seule passe (scan + read + commit).
    pub fn poll<P, A>(&mut self, put_fn: P, aux_put: A) -> Result<Vec<Capture>>
    where
        P: FnMut(&str, &[u8], f64) -> Result<(String, u32)>,
        A: FnMut(&str, &[u8]),
    {
        let due = self.scan();
        let ready = self.read_due(due);
        self.commit(ready, put_fn, aux_put)
    }

    /// Résumé de l'état pour l'API serveur.
    pub fn summary(&self) -> Value {
        let pending: usize = self.states.values().map(|s| s.pending.len()).sum();
        json!({
            "folders": self.folders.iter().map(|f| json!({
                "path": f.path.to_string_lossy(),
                "prefix": f.prefix,
            })).collect::<Vec<_>>(),
            "captures": self.captures,
            "last_capture": self.last_capture,
            "pending": pending,
            "quiet": self.quiet,
            "last_error": self.last_error,
        })
    }
}

// ─────────────────────────── gestion des dossiers persistés ──────────────────

/// Charge la liste des dossiers depuis les aux.
pub fn load_folders_aux<F>(aux_get: &F) -> Vec<WatchedFolder>
where
    F: Fn(&str) -> Option<Vec<u8>>,
{
    let raw = match aux_get(FOLDERS_KEY) {
        Some(r) => r,
        None => return vec![],
    };
    let data: Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    data.as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|d| {
            let path = d["path"].as_str()?;
            let prefix = d["prefix"].as_str().unwrap_or("").to_string();
            Some(WatchedFolder {
                path: PathBuf::from(path),
                prefix,
            })
        })
        .collect()
}

/// Persiste la liste des dossiers dans les aux.
pub fn save_folders_aux<F>(folders: &[WatchedFolder], mut aux_put: F)
where
    F: FnMut(&str, &[u8]),
{
    let data: Vec<Value> = folders
        .iter()
        .map(|f| json!({"path": f.path.to_string_lossy(), "prefix": f.prefix}))
        .collect();
    let bytes = serde_json::to_vec(&data).unwrap_or_default();
    aux_put(FOLDERS_KEY, &bytes);
}

/// Ajoute un dossier à la liste persistée. Vérifie les contraintes (chemin absolu,
/// pas de doublon, pas de préfixe en conflit, max 32 dossiers).
pub fn add_folder(
    path: &Path,
    prefix: &str,
    folders: &mut Vec<WatchedFolder>,
    forbidden: &[&Path],
) -> Result<()> {
    ensure!(path.is_absolute(), "le chemin doit être absolu");
    let resolved = path
        .canonicalize()
        .map_err(|_| anyhow!("ce dossier n'existe pas"))?;
    ensure!(resolved.is_dir(), "ce chemin n'est pas un dossier");

    for fb in forbidden {
        let fb = fb.canonicalize().unwrap_or_else(|_| fb.to_path_buf());
        if overlaps(&resolved, &fb) {
            return Err(anyhow!(
                "ce dossier contient l'archive ou ses exports, ou se trouve dedans ({fb:?})"
            ));
        }
    }
    for existing in folders.iter() {
        if existing
            .path
            .canonicalize()
            .unwrap_or_else(|_| existing.path.clone())
            == resolved
        {
            return Err(anyhow!("ce dossier est déjà suivi"));
        }
        if existing.prefix == prefix {
            return Err(anyhow!(
                "un autre dossier suivi est déjà rangé sous ce dossier logique : donnez-en un autre"
            ));
        }
    }
    ensure!(
        folders.len() < MAX_FOLDERS,
        "au plus {MAX_FOLDERS} dossiers suivis"
    );

    folders.push(WatchedFolder {
        path: resolved,
        prefix: prefix.to_string(),
    });
    Ok(())
}

fn overlaps(a: &Path, b: &Path) -> bool {
    a == b || a.starts_with(b) || b.starts_with(a)
}

// ─────────────────────────────────── utilitaires ─────────────────────────────

fn unix_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn unix_micros(mtime: SystemTime) -> i64 {
    match mtime.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_micros() as i64,
        Err(e) => -(e.duration().as_micros() as i64),
    }
}

/// Scan récursif d'un dossier (sans suivre les liens symboliques).
/// Exclut les fichiers cachés (nom commençant par '.') et les dossiers cachés.
fn scan_dir(root: &Path) -> Result<Vec<SourceFile>> {
    let mut out = Vec::new();
    scan_dir_inner(root, root, &mut out)?;
    Ok(out)
}

fn scan_dir_inner(root: &Path, dir: &Path, out: &mut Vec<SourceFile>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let fname = entry.file_name();
        let name = fname.to_string_lossy();
        if name.starts_with('.') {
            continue; // fichiers et dossiers cachés ignorés
        }
        let meta = entry.metadata()?;
        if meta.is_dir() {
            scan_dir_inner(root, &entry.path(), out)?;
        } else if meta.is_file() {
            let abs = entry.path();
            let rel = abs
                .strip_prefix(root)
                .unwrap_or(&abs)
                .to_string_lossy()
                .replace('\\', "/");
            let mtime = meta.modified().unwrap_or(UNIX_EPOCH);
            let mtime_us = unix_micros(mtime);
            let mtime_secs = mtime
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64();
            out.push(SourceFile {
                abs_path: abs,
                rel_path: rel,
                sig: FileSig(meta.len(), mtime_us),
                mtime_secs,
            });
        }
    }
    Ok(())
}

/// Lecture stable : deux lectures concordantes (taille + contenu identiques).
fn stable_read(path: &Path, max_bytes: usize) -> Result<(Vec<u8>, FileSig)> {
    let read_once = |p: &Path| -> Result<(Vec<u8>, FileSig)> {
        let meta = fs::metadata(p)?;
        ensure!(meta.len() as usize <= max_bytes, "fichier trop volumineux");
        let content = fs::read(p)?;
        let mtime = meta.modified().unwrap_or(UNIX_EPOCH);
        let sig = FileSig(meta.len(), unix_micros(mtime));
        Ok((content, sig))
    };
    let (content1, sig1) = read_once(path)?;
    let (content2, sig2) = read_once(path)?;
    ensure!(
        sig1 == sig2 && content1 == content2,
        "fichier instable entre les deux lectures"
    );
    Ok((content1, sig1))
}

// ─────────────────────────────────────────────────────────── tests ────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let p = dir.join(name);
        let mut f = fs::File::create(&p).unwrap();
        f.write_all(content).unwrap();
        f.sync_all().unwrap();
        p
    }

    #[test]
    fn scan_finds_files() {
        let dir = TempDir::new().unwrap();
        write_file(dir.path(), "hello.txt", b"hello");
        write_file(dir.path(), "world.md", b"world");

        let files = scan_dir(dir.path()).unwrap();
        assert_eq!(files.len(), 2);
        let names: Vec<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();
        assert!(names.contains(&"hello.txt"));
        assert!(names.contains(&"world.md"));
    }

    #[test]
    fn scan_ignores_hidden() {
        let dir = TempDir::new().unwrap();
        write_file(dir.path(), "visible.txt", b"ok");
        write_file(dir.path(), ".hidden", b"nope");
        let files = scan_dir(dir.path()).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].rel_path, "visible.txt");
    }

    #[test]
    fn stable_read_works() {
        let dir = TempDir::new().unwrap();
        let p = write_file(dir.path(), "test.txt", b"stable content");
        let (content, _sig) = stable_read(&p, 1_000_000).unwrap();
        assert_eq!(&content, b"stable content");
    }

    #[test]
    fn folder_state_roundtrip() {
        let mut state = FolderState::default();
        state
            .known
            .insert("a.txt".to_string(), FileSig(42, 1234567890));
        state
            .known
            .insert("b.md".to_string(), FileSig(100, 9876543210));
        let json = state.to_json();
        let restored = FolderState::from_aux(&json);
        assert_eq!(restored.known.get("a.txt"), Some(&FileSig(42, 1234567890)));
        assert_eq!(restored.known.get("b.md"), Some(&FileSig(100, 9876543210)));
    }

    #[test]
    fn add_folder_rejects_duplicate_path() {
        let dir = TempDir::new().unwrap();
        let mut folders = vec![];
        add_folder(dir.path(), "prefix1", &mut folders, &[]).unwrap();
        let err = add_folder(dir.path(), "prefix2", &mut folders, &[]);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("déjà suivi"));
    }

    #[test]
    fn add_folder_rejects_duplicate_prefix() {
        let dir1 = TempDir::new().unwrap();
        let dir2 = TempDir::new().unwrap();
        let mut folders = vec![];
        add_folder(dir1.path(), "same", &mut folders, &[]).unwrap();
        let err = add_folder(dir2.path(), "same", &mut folders, &[]);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("logique"));
    }

    #[test]
    fn watcher_scan_commit_cycle() {
        let dir = TempDir::new().unwrap();
        write_file(dir.path(), "doc.txt", b"content");

        let mut watcher = Watcher::new(0.0, MAX_BYTES); // quiet=0 → toujours dû
        watcher.folders.push(WatchedFolder {
            path: dir.path().to_path_buf(),
            prefix: String::new(),
        });
        watcher
            .states
            .insert(watcher.folders[0].state_key(), FolderState::default());

        let due = watcher.scan();
        assert_eq!(due.len(), 1, "un fichier doit être dû");

        let ready = watcher.read_due(due);
        assert_eq!(ready.len(), 1, "un fichier doit être prêt");
        assert_eq!(ready[0].content, b"content");

        let mut committed_paths: Vec<String> = vec![];
        let mut aux_stored: HashMap<String, Vec<u8>> = HashMap::new();

        let captures = watcher
            .commit(
                ready,
                |path, _content, _mtime| {
                    committed_paths.push(path.to_string());
                    Ok(("entry-id-test".to_string(), 1))
                },
                |key, data| {
                    aux_stored.insert(key.to_string(), data.to_vec());
                },
            )
            .unwrap();

        assert_eq!(captures.len(), 1);
        assert_eq!(captures[0].logical_path, "doc.txt");
        assert_eq!(watcher.captures, 1);

        // L'état est persisté dans les aux
        assert!(!aux_stored.is_empty(), "l'état doit être persisté");

        // Deuxième scan : le fichier ne doit plus être dû (déjà connu avec même signature)
        let due2 = watcher.scan();
        assert_eq!(due2.len(), 0, "rien de nouveau après le commit");
    }
}
