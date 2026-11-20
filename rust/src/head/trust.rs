//! Which repositories the head may read and run checks in: an explicit list kept outside
//! any repository, filled only by `head trust <path> --confirm`.
//!
//! Finding a `.git` marker is never enough: a command run below a trusted root uses the
//! nearest trusted ancestor of the working directory, and refuses everywhere else. The
//! entry pins the digest of the allow-list (`.agents/checks.json`) as it was shown when
//! trust was given; a different allow-list must be trusted again before anything runs.
//!
//! Paths: on Unix, the account's home directory comes from the account database, not
//! from the environment: `~/.config/empreinte/trusted-repos.json` for the list and
//! `~/.cache/empreinte/head` for snapshots, the build cache and the checks' HOME. On
//! Windows (not validated) they come from APPDATA and LOCALAPPDATA.
use super::checks;
use super::fsafe::Dir;
use anyhow::{Context as _, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const MAX_TRUST_FILE: u64 = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Settings {
    pub trust_file: PathBuf,
    pub cache_dir: PathBuf,
    /// The account's home directory (from the account database on Unix).
    pub user_home: PathBuf,
}

#[cfg(unix)]
fn account_home() -> Result<PathBuf> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt;
    let uid = unsafe { libc::getuid() };
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0 as libc::c_char; 16384];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let r = unsafe {
        libc::getpwuid_r(
            uid,
            &mut entry,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        )
    };
    ensure!(
        r == 0 && !result.is_null(),
        "compte introuvable dans la base des comptes"
    );
    let dir = unsafe { CStr::from_ptr(entry.pw_dir) };
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes())))
}

impl Settings {
    /// The paths for the current account (see the module documentation).
    pub fn for_current_user() -> Result<Self> {
        #[cfg(unix)]
        {
            let home = account_home()?;
            Ok(Self {
                trust_file: home.join(".config/empreinte/trusted-repos.json"),
                cache_dir: home.join(".cache/empreinte/head"),
                user_home: home,
            })
        }
        #[cfg(not(unix))]
        {
            let appdata = std::env::var_os("APPDATA").ok_or_else(|| anyhow!("APPDATA absent"))?;
            let local =
                std::env::var_os("LOCALAPPDATA").ok_or_else(|| anyhow!("LOCALAPPDATA absent"))?;
            let home =
                std::env::var_os("USERPROFILE").ok_or_else(|| anyhow!("USERPROFILE absent"))?;
            Ok(Self {
                trust_file: PathBuf::from(appdata).join("Empreinte/trusted-repos.json"),
                cache_dir: PathBuf::from(local).join("Empreinte/head"),
                user_home: PathBuf::from(home),
            })
        }
    }

    /// Settings rooted in one directory (tests, or a person who wants a separate state).
    pub fn in_dir(dir: &Path, user_home: &Path) -> Self {
        Self {
            trust_file: dir.join("trusted-repos.json"),
            cache_dir: dir.join("cache"),
            user_home: user_home.to_path_buf(),
        }
    }

    /// The private cache directory (0700 on Unix), created on first use.
    pub fn cache(&self) -> Result<PathBuf> {
        private_dir(&self.cache_dir)?;
        Ok(self.cache_dir.clone())
    }
}

/// Create a directory (and parents) readable only by its owner.
pub fn private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)?;
    let meta = std::fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "{} : dossier ordinaire requis",
        path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustEntry {
    pub root: String,
    pub checks_sha256: String,
    pub trusted_at: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustFile {
    version: u32,
    repos: Vec<TrustEntry>,
}

fn read_trust(settings: &Settings) -> Result<TrustFile> {
    let path = &settings.trust_file;
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Ok(TrustFile {
            version: 1,
            repos: Vec::new(),
        });
    };
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink(),
        "{} : fichier ordinaire requis",
        path.display()
    );
    let parent = Dir::open_root(
        path.parent()
            .ok_or_else(|| anyhow!("liste de confiance sans dossier"))?,
    )?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("nom invalide"))?;
    let bytes = parent.read(name, MAX_TRUST_FILE)?;
    let file: TrustFile = serde_json::from_slice(&bytes).context("liste de confiance illisible")?;
    ensure!(file.version == 1, "liste de confiance : version 1 attendue");
    Ok(file)
}

/// A trusted repository, opened for the head: its root, the pinned allow-list digest
/// and a handle on the root directory (paths below it are opened without following links).
#[derive(Clone)]
pub struct Context {
    pub root: PathBuf,
    pub settings: Settings,
    pub entry: TrustEntry,
    root_dir: Arc<Dir>,
}

impl Context {
    pub fn root_dir(&self) -> &Dir {
        &self.root_dir
    }

    /// `.agents`, a directory of the root, never a link.
    pub fn agents_dir(&self) -> Result<Dir> {
        self.root_dir.sub(".agents")
    }

    /// The allow-list bytes, refused when they differ from what was trusted.
    pub fn checks_bytes(&self) -> Result<Vec<u8>> {
        let bytes = self
            .agents_dir()?
            .read("checks.json", checks::MAX_CHECKS_FILE_BYTES)?;
        let digest = checks::sha256_hex(&bytes);
        ensure!(
            digest == self.entry.checks_sha256,
            "la liste des contrôles (.agents/checks.json) a changé depuis la confiance : la relire, puis « empreinte head trust {} --confirm »",
            self.root.display()
        );
        Ok(bytes)
    }
}

fn canonical_repo(path: &Path) -> Result<PathBuf> {
    let root = path
        .canonicalize()
        .with_context(|| format!("dossier introuvable : {}", path.display()))?;
    let dir = Dir::open_root(&root)?;
    let git = dir.sub(".git").with_context(|| {
        format!(
            "{} : pas de dossier .git ordinaire (un .git fichier ou lien n'est pas accepté)",
            root.display()
        )
    })?;
    drop(git);
    Ok(root)
}

/// `head trust <path>`: show what would be trusted; with `confirm`, record it.
pub fn trust(settings: &Settings, path: &Path, confirm: bool) -> Result<Value> {
    let root = canonical_repo(path)?;
    let dir = Dir::open_root(&root)?;
    let bytes = dir
        .sub(".agents")?
        .read("checks.json", checks::MAX_CHECKS_FILE_BYTES)?;
    let catalogue = checks::parse(&bytes, &root)?;
    let digest = checks::sha256_hex(&bytes);
    let rules: Vec<String> = dir
        .sub(".agents")
        .and_then(|a| a.sub("rules"))
        .and_then(|r| r.list())
        .unwrap_or_default();
    let shown = json!({
        "root": root.display().to_string(),
        "checks_sha256": digest,
        "checks": catalogue.describe(),
        "git": catalogue.git_program().map(|p| p.display().to_string()),
        "rule_files": rules,
        "trust_file": settings.trust_file.display().to_string(),
    });
    if !confirm {
        return Ok(json!({
            "trusted": false,
            "would_trust": shown,
            "next": format!("relire ce qui précède, puis « empreinte head trust {} --confirm »", root.display()),
        }));
    }
    let mut file = read_trust(settings)?;
    file.repos.retain(|e| Path::new(&e.root) != root);
    file.repos.push(TrustEntry {
        root: root.display().to_string(),
        checks_sha256: digest,
        trusted_at: super::now(),
    });
    file.version = 1;
    let parent = settings
        .trust_file
        .parent()
        .ok_or_else(|| anyhow!("liste de confiance sans dossier"))?;
    private_dir(parent)?;
    let name = settings
        .trust_file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("nom invalide"))?;
    Dir::open_root(&parent.canonicalize()?)?
        .write_atomic(name, &serde_json::to_vec_pretty(&file)?)?;
    Ok(json!({"trusted": true, "entry": shown}))
}

/// The trusted repository for a command: `repo` when given (it must be trusted), else the
/// nearest trusted ancestor of `cwd`.
pub fn resolve(settings: &Settings, repo: Option<&Path>, cwd: &Path) -> Result<Context> {
    let file = read_trust(settings)?;
    let find = |candidate: &Path| {
        file.repos
            .iter()
            .find(|e| Path::new(&e.root) == candidate)
            .cloned()
    };
    let (root, entry) = match repo {
        Some(path) => {
            let root = path
                .canonicalize()
                .with_context(|| format!("dossier introuvable : {}", path.display()))?;
            let entry = find(&root).ok_or_else(|| {
                anyhow!(
                    "{} n'est pas un dépôt de confiance : vérifier son contenu puis « empreinte head trust {} »",
                    root.display(),
                    root.display()
                )
            })?;
            (root, entry)
        }
        None => {
            let start = cwd.canonicalize()?;
            start
                .ancestors()
                .find_map(|p| find(p).map(|e| (p.to_path_buf(), e)))
                .ok_or_else(|| {
                    anyhow!(
                        "aucun dépôt de confiance pour {} : vérifier le dépôt puis « empreinte head trust <racine> »",
                        start.display()
                    )
                })?
        }
    };
    canonical_repo(&root)?;
    Ok(Context {
        root_dir: Arc::new(Dir::open_root(&root)?),
        root,
        settings: settings.clone(),
        entry,
    })
}
