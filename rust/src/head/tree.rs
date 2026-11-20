//! The inputs of a check, fingerprinted by content, and the snapshot a check runs in.
//!
//! The inputs are every file Git tracks plus every untracked file it does not ignore,
//! except `.agents/rules/` (a rule's state changes as it moves) and the head's own
//! journal directory. Git only lists names: it runs contained like a check, with its
//! system and global configuration disabled and every executable setting the listing could
//! reach overridden on the command line (fsmonitor, hooks, pager); `ls-files` runs no
//! diff, text conversion, filter or credential helper. The tool then reads and hashes each
//! file itself. Anything that cannot be listed or read completely is an error: no partial
//! fingerprint is ever returned.
//!
//! A snapshot copies those files into a private directory under the cache, read-only, and
//! its digest is computed from the very bytes written there. A check runs in the snapshot,
//! so what it tested is exactly what the digest describes.
use super::checks::Checks;
use super::contain::{self, RunSpec};
use super::trust::{Context, private_dir};
use anyhow::{Context as _, Result, anyhow, ensure};
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

const MAX_LISTING: u64 = 64 * 1024 * 1024;
const MAX_FILE: u64 = 512 * 1024 * 1024;
const EXCLUDED: [&str; 2] = [".agents/rules/", ".empreinte-head/"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeDigest {
    pub sha256: String,
    pub files: usize,
    pub bytes: u64,
}

/// The environment of the Git listing: fixed values only.
fn git_env(ctx: &Context) -> Result<Vec<(String, String)>> {
    let home = ctx.settings.cache()?.join("home");
    private_dir(&home)?;
    let mut env = vec![
        ("HOME".to_string(), home.display().to_string()),
        ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
        ("GIT_TERMINAL_PROMPT".into(), "0".into()),
        ("GIT_OPTIONAL_LOCKS".into(), "0".into()),
        ("LC_ALL".into(), "C".into()),
    ];
    if cfg!(unix) {
        env.push(("PATH".into(), "/usr/bin:/bin".into()));
        env.push(("GIT_CONFIG_GLOBAL".into(), "/dev/null".into()));
    } else {
        env.push(("PATH".into(), "C:\\Windows\\System32".into()));
        env.push(("GIT_CONFIG_GLOBAL".into(), "NUL".into()));
    }
    Ok(env)
}

fn valid_listed(path: &str) -> bool {
    let p = Path::new(path);
    !path.is_empty()
        && !path.contains('\\')
        && !p.is_absolute()
        && p.components().all(|c| matches!(c, Component::Normal(_)))
}

/// The input files, sorted, as listed by a contained Git with helpers disabled.
pub fn list_inputs(ctx: &Context, checks: &Checks) -> Result<Vec<String>> {
    let git = checks.git_program().ok_or_else(|| {
        anyhow!("aucun programme git déclaré pour cette plateforme dans .agents/checks.json")
    })?;
    let root = ctx.root.display().to_string();
    let mut args: Vec<String> = Vec::new();
    for setting in [
        "core.fsmonitor=false",
        "core.untrackedCache=false",
        "core.hooksPath=/dev/null",
        "core.pager=cat",
        "core.quotePath=false",
    ] {
        args.push("-c".into());
        args.push(setting.into());
    }
    args.push("-c".into());
    args.push(format!("safe.directory={root}"));
    args.push(format!("--git-dir={}", ctx.root.join(".git").display()));
    args.push(format!("--work-tree={root}"));
    for a in [
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
    ] {
        args.push(a.into());
    }
    let spec = RunSpec {
        program: git,
        args,
        cwd: ctx.root.clone(),
        env: git_env(ctx)?,
        timeout: Duration::from_secs(60),
        max_output: MAX_LISTING,
        contain: contain::available(),
        keep_stdout: true,
    };
    let outcome = contain::run(&spec).context("liste des fichiers par git impossible")?;
    ensure!(
        outcome.exit_code == Some(0) && !outcome.timed_out && outcome.capture_complete,
        "liste des fichiers par git incomplète ou en échec ({})",
        outcome.problems.join(" ; ")
    );
    ensure!(
        outcome.contained && outcome.cleanup_confirmed,
        "git n'a pas pu être confiné : empreinte refusée"
    );
    let mut names: Vec<String> = outcome
        .stdout
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| {
            String::from_utf8(s.to_vec())
                .map_err(|_| anyhow!("nom de fichier non UTF-8 dans le dépôt"))
        })
        .collect::<Result<_>>()?;
    for name in &names {
        ensure!(
            valid_listed(name),
            "nom de fichier inattendu dans la liste de git : {name}"
        );
    }
    names.retain(|n| !EXCLUDED.iter().any(|x| n.starts_with(x)));
    names.sort();
    names.dedup();
    Ok(names)
}

enum Entry {
    File { bytes: Vec<u8>, executable: bool },
    Link(String),
    Missing,
    Other,
}

fn read_entry(path: &Path) -> Result<Entry> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Entry::Missing),
        Err(e) => return Err(e.into()),
    };
    if meta.file_type().is_symlink() {
        let target = std::fs::read_link(path)?;
        return Ok(Entry::Link(target.to_string_lossy().into_owned()));
    }
    if !meta.is_file() {
        return Ok(Entry::Other);
    }
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_FILE + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_FILE,
        "{} : fichier trop grand pour l'empreinte",
        path.display()
    );
    #[cfg(unix)]
    let executable = {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    };
    #[cfg(not(unix))]
    let executable = false;
    Ok(Entry::File { bytes, executable })
}

struct Hasher {
    sha: Sha256,
    files: usize,
    bytes: u64,
}

impl Hasher {
    fn new() -> Self {
        Self {
            sha: Sha256::new(),
            files: 0,
            bytes: 0,
        }
    }
    fn add(&mut self, name: &str, entry: &Entry) {
        let (kind, digest) = match entry {
            Entry::File { bytes, executable } => {
                self.bytes += bytes.len() as u64;
                (
                    if *executable { "exec" } else { "file" },
                    hex::encode(Sha256::digest(bytes)),
                )
            }
            Entry::Link(target) => ("link", hex::encode(Sha256::digest(target.as_bytes()))),
            Entry::Missing => ("missing", String::new()),
            Entry::Other => ("other", String::new()),
        };
        self.files += 1;
        self.sha.update(name.as_bytes());
        self.sha.update(b"\0");
        self.sha.update(kind.as_bytes());
        self.sha.update(b"\0");
        self.sha.update(digest.as_bytes());
        self.sha.update(b"\n");
    }
    fn finish(self) -> TreeDigest {
        TreeDigest {
            sha256: hex::encode(self.sha.finalize()),
            files: self.files,
            bytes: self.bytes,
        }
    }
}

/// The digest of the working tree's inputs now. Any error means: no fingerprint.
pub fn digest(ctx: &Context, checks: &Checks) -> Result<TreeDigest> {
    let names = list_inputs(ctx, checks)?;
    let mut hasher = Hasher::new();
    for name in &names {
        let entry =
            read_entry(&ctx.root.join(name)).with_context(|| format!("{name} illisible"))?;
        hasher.add(name, &entry);
    }
    Ok(hasher.finish())
}

/// A private, read-only copy of the inputs; removed when dropped.
pub struct Snapshot {
    pub area: PathBuf,
    pub tree: PathBuf,
    pub digest: TreeDigest,
    names: Vec<String>,
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.area);
    }
}

fn write_entry(target: &Path, entry: &Entry) -> Result<()> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match entry {
        Entry::File { bytes, executable } => {
            std::fs::write(target, bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = if *executable { 0o555 } else { 0o444 };
                std::fs::set_permissions(target, std::fs::Permissions::from_mode(mode))?;
            }
            #[cfg(not(unix))]
            {
                let _ = executable;
                let mut perms = std::fs::metadata(target)?.permissions();
                perms.set_readonly(true);
                std::fs::set_permissions(target, perms)?;
            }
        }
        Entry::Link(link) => {
            #[cfg(unix)]
            std::os::unix::fs::symlink(link, target)?;
            #[cfg(not(unix))]
            {
                let _ = link;
                anyhow::bail!(
                    "lien symbolique dans le dépôt : instantané impossible sur cette plateforme"
                );
            }
        }
        Entry::Missing | Entry::Other => {}
    }
    Ok(())
}

/// Copy the inputs into a new snapshot; the digest is computed from what was written.
pub fn snapshot(ctx: &Context, checks: &Checks) -> Result<Snapshot> {
    let names = list_inputs(ctx, checks)?;
    let base = ctx.settings.cache()?.join("snapshots");
    private_dir(&base)?;
    let area = base.join(hex::encode(rand::random::<[u8; 8]>()));
    std::fs::create_dir(&area)?;
    let tree = area.join("tree");
    std::fs::create_dir(&tree)?;
    let mut snapshot = Snapshot {
        area,
        tree,
        digest: TreeDigest {
            sha256: String::new(),
            files: 0,
            bytes: 0,
        },
        names,
    };
    let mut hasher = Hasher::new();
    for name in snapshot.names.clone() {
        let entry =
            read_entry(&ctx.root.join(&name)).with_context(|| format!("{name} illisible"))?;
        write_entry(&snapshot.tree.join(&name), &entry)?;
        hasher.add(&name, &entry);
    }
    snapshot.digest = hasher.finish();
    Ok(snapshot)
}

impl Snapshot {
    /// Whether the snapshot still holds exactly what its digest describes.
    pub fn intact(&self) -> Result<bool> {
        let mut hasher = Hasher::new();
        for name in &self.names {
            hasher.add(name, &read_entry(&self.tree.join(name))?);
        }
        Ok(hasher.finish() == self.digest)
    }
}
