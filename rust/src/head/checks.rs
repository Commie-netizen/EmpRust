//! The evaluator: checks the developer allowed, run by the tool itself.
//!
//! What runs comes only from the versioned file `.agents/checks.json` of the repository:
//! the program and its arguments (an argument vector, never a shell line), the working
//! directory (inside the repository) and the timeout. The only thing taken from the
//! command line is the check's name. No journal record, rule, recalled text or other
//! argument can change the program, an argument, the directory or the environment: the
//! child gets a cleared environment plus a fixed list of variables of the tool's own
//! environment (`PASSTHROUGH`).
//!
//! A result records the exit status, the duration, a digest of the output (never the
//! output itself), the digest of the checks file and the repository revision (git HEAD,
//! whether the tree was dirty, and a digest of `git status` and `git diff HEAD`), so it
//! can later be recognised as stale.
use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub const CHECKS_FILE: &str = ".agents/checks.json";
pub const MAX_CHECKS_FILE_BYTES: u64 = 64 * 1024;
pub const DEFAULT_OUTPUT_BYTES: u64 = 64 * 1024;
const MAX_TIMEOUT_SECS: u64 = 7200;
const MAX_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
const GIT_TIMEOUT: Duration = Duration::from_secs(60);

/// Variables of the tool's own environment that a check inherits; nothing else.
pub const PASSTHROUGH: &[&str] = &[
    "PATH",
    "PATHEXT",
    "HOME",
    "USER",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "CARGO_TARGET_DIR",
    "WSL_DISTRO_NAME",
    "WSL_INTEROP",
    "WSLENV",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChecksFile {
    version: u32,
    checks: BTreeMap<String, CheckSpec>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckSpec {
    #[serde(default)]
    pub description: String,
    pub command: Commands,
    #[serde(default = "dot")]
    pub cwd: String,
    pub timeout_secs: u64,
    #[serde(default)]
    pub max_output_bytes: Option<u64>,
}
fn dot() -> String {
    ".".into()
}

/// One argument vector per platform; a platform without one cannot run the check.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commands {
    #[serde(default)]
    pub unix: Option<Vec<String>>,
    #[serde(default)]
    pub windows: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Revision {
    pub head: Option<String>,
    pub dirty: Option<bool>,
    pub tree_sha256: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckResult {
    pub name: String,
    pub passed: bool,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub duration_ms: u64,
    /// SHA-256 of "stdout:" + hex SHA-256(stdout) + "\nstderr:" + hex SHA-256(stderr).
    pub output_sha256: String,
    pub output_bytes: u64,
    /// The output was longer than the check's bound: only its digest covers all of it.
    pub output_truncated: bool,
    pub checks_sha256: String,
    pub revision: Revision,
    pub platform: String,
}

pub struct Checks {
    pub sha256: String,
    specs: BTreeMap<String, CheckSpec>,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn read_checks_file(repo: &Path) -> Result<Vec<u8>> {
    let path = repo.join(CHECKS_FILE);
    let meta = std::fs::symlink_metadata(&path)
        .with_context(|| format!("fichier de contrôles absent : {CHECKS_FILE}"))?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink(),
        "{CHECKS_FILE} doit être un fichier ordinaire"
    );
    let mut bytes = Vec::new();
    std::fs::File::open(&path)?
        .take(MAX_CHECKS_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_CHECKS_FILE_BYTES,
        "{CHECKS_FILE} dépasse 64 Kio"
    );
    Ok(bytes)
}

/// Digest of the checks file as it is now (None when it cannot be read).
pub fn current_hash(repo: &Path) -> Option<String> {
    read_checks_file(repo).ok().map(|b| sha256_hex(&b))
}

pub fn load(repo: &Path) -> Result<Checks> {
    let bytes = read_checks_file(repo)?;
    let file: ChecksFile =
        serde_json::from_slice(&bytes).with_context(|| format!("{CHECKS_FILE} illisible"))?;
    ensure!(file.version == 1, "{CHECKS_FILE} : version 1 attendue");
    for (name, spec) in &file.checks {
        ensure!(valid_name(name), "nom de contrôle invalide : {name}");
        validate_spec(repo, name, spec)?;
    }
    Ok(Checks {
        sha256: sha256_hex(&bytes),
        specs: file.checks,
    })
}

fn validate_spec(repo: &Path, name: &str, spec: &CheckSpec) -> Result<()> {
    for argv in [&spec.command.unix, &spec.command.windows]
        .into_iter()
        .flatten()
    {
        ensure!(
            !argv.is_empty()
                && argv.len() <= 64
                && argv.iter().all(|a| a.len() <= 1000 && !a.contains('\0'))
                && !argv[0].is_empty(),
            "contrôle {name} : commande invalide"
        );
    }
    ensure!(
        (1..=MAX_TIMEOUT_SECS).contains(&spec.timeout_secs),
        "contrôle {name} : délai entre 1 et {MAX_TIMEOUT_SECS} s"
    );
    ensure!(
        spec.max_output_bytes
            .is_none_or(|n| (1..=MAX_OUTPUT_BYTES).contains(&n)),
        "contrôle {name} : borne de sortie invalide"
    );
    working_dir(repo, &spec.cwd).with_context(|| format!("contrôle {name}"))?;
    Ok(())
}

/// The working directory, resolved (links followed) and required to be inside the repository.
fn working_dir(repo: &Path, cwd: &str) -> Result<PathBuf> {
    let relative = Path::new(cwd);
    ensure!(
        !relative.is_absolute()
            && !relative
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir)),
        "répertoire de travail : chemin relatif au dépôt requis"
    );
    let resolved = repo
        .join(relative)
        .canonicalize()
        .context("répertoire de travail introuvable")?;
    ensure!(
        resolved.starts_with(repo) && resolved.is_dir(),
        "répertoire de travail hors du dépôt"
    );
    Ok(resolved)
}

impl Checks {
    pub fn names(&self) -> Vec<&str> {
        self.specs.keys().map(String::as_str).collect()
    }
    pub fn describe(&self) -> serde_json::Value {
        serde_json::json!(
            self.specs
                .iter()
                .map(|(n, s)| (
                    n.clone(),
                    serde_json::json!({
                        "description": s.description,
                        "cwd": s.cwd,
                        "timeout_secs": s.timeout_secs,
                        "platform": argv_for_platform(s).is_some(),
                    })
                ))
                .collect::<BTreeMap<_, _>>()
        )
    }
    pub fn get(&self, name: &str) -> Result<&CheckSpec> {
        ensure!(valid_name(name), "nom de contrôle invalide");
        self.specs
            .get(name)
            .ok_or_else(|| anyhow!("contrôle inconnu : {name} (voir {CHECKS_FILE})"))
    }
}

fn argv_for_platform(spec: &CheckSpec) -> Option<&Vec<String>> {
    if cfg!(windows) {
        spec.command.windows.as_ref()
    } else {
        spec.command.unix.as_ref()
    }
}

pub fn platform() -> &'static str {
    if cfg!(windows) { "windows" } else { "unix" }
}

/// Run the named check of `checks`. Only `name` comes from the caller.
pub fn run(repo: &Path, checks: &Checks, name: &str) -> Result<CheckResult> {
    run_with_tail(repo, checks, name).map(|(result, _)| result)
}

/// As `run`, plus the end of the output (at most 4000 bytes) for the person who ran it.
/// The tail is shown on the command line only; the journal keeps its digest, never text.
pub fn run_with_tail(repo: &Path, checks: &Checks, name: &str) -> Result<(CheckResult, String)> {
    let spec = checks.get(name)?;
    let argv = argv_for_platform(spec)
        .ok_or_else(|| anyhow!("contrôle {name} : aucune commande pour {}", platform()))?;
    let cwd = working_dir(repo, &spec.cwd)?;
    let limit = spec.max_output_bytes.unwrap_or(DEFAULT_OUTPUT_BYTES);
    let revision = revision(repo);
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]).current_dir(&cwd);
    let started = Instant::now();
    let outcome = run_bounded(command, Duration::from_secs(spec.timeout_secs), limit)
        .with_context(|| format!("contrôle {name} : lancement impossible"))?;
    let start = outcome.tail.len().saturating_sub(4000);
    let tail = String::from_utf8_lossy(&outcome.tail[start..]).into_owned();
    let result = CheckResult {
        name: name.into(),
        passed: !outcome.timed_out && outcome.exit_code == Some(0),
        exit_code: outcome.exit_code,
        timed_out: outcome.timed_out,
        duration_ms: started.elapsed().as_millis() as u64,
        output_sha256: outcome.output_sha256,
        output_bytes: outcome.output_bytes,
        output_truncated: outcome.output_bytes > limit,
        checks_sha256: checks.sha256.clone(),
        revision,
        platform: platform().into(),
    };
    Ok((result, tail))
}

pub struct Outcome {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub output_sha256: String,
    pub output_bytes: u64,
    /// The last bytes of stdout then stderr, for display only (never written to the journal).
    pub tail: Vec<u8>,
}

/// Spawn with a cleared environment (plus PASSTHROUGH), no stdin, both outputs drained
/// and hashed. At the deadline the whole process group is killed (Unix); on Windows only
/// the direct child can be killed with the standard library.
pub fn run_bounded(mut command: Command, timeout: Duration, keep: u64) -> Result<Outcome> {
    command.env_clear();
    for name in PASSTHROUGH {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn()?;
    let (tx, rx) = mpsc::channel();
    let readers = [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    ];
    for (index, reader) in readers.into_iter().enumerate() {
        let tx = tx.clone();
        let mut reader = reader.expect("piped");
        std::thread::spawn(move || {
            let mut hasher = Sha256::new();
            let mut tail: Vec<u8> = Vec::new();
            let mut total = 0u64;
            let mut buffer = [0u8; 8192];
            while let Ok(n) = reader.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
                total += n as u64;
                tail.extend_from_slice(&buffer[..n]);
                if tail.len() as u64 > keep {
                    let cut = tail.len() - keep as usize;
                    tail.drain(..cut);
                }
            }
            let _ = tx.send((index, hex::encode(hasher.finalize()), total, tail));
        });
    }
    drop(tx);
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            kill_tree(&mut child);
            break child.wait()?;
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    // Members of the group still alive after the leader exited would keep the pipes open.
    kill_group(&child);
    let mut streams: [(String, u64, Vec<u8>); 2] = Default::default();
    let mut complete = true;
    for _ in 0..2 {
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok((index, digest, total, tail)) => streams[index] = (digest, total, tail),
            Err(_) => complete = false,
        }
    }
    let combined = format!(
        "stdout:{}\nstderr:{}{}",
        streams[0].0,
        streams[1].0,
        if complete { "" } else { "\nincomplete" }
    );
    let mut tail = std::mem::take(&mut streams[0].2);
    tail.extend_from_slice(&streams[1].2);
    Ok(Outcome {
        exit_code: status.code(),
        timed_out,
        output_sha256: sha256_hex(combined.as_bytes()),
        output_bytes: streams[0].1 + streams[1].1,
        tail,
    })
}

fn kill_tree(child: &mut Child) {
    kill_group(child);
    let _ = child.kill();
}

#[cfg(unix)]
fn kill_group(child: &Child) {
    // The child leads its own process group (process_group(0)): signal the whole group.
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
}
#[cfg(not(unix))]
fn kill_group(_child: &Child) {
    // Without a job object (not available through the standard library) grandchildren
    // of a check may survive its timeout on Windows. Documented in THINKING_HEAD.md.
}

fn git(repo: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let mut command = Command::new("git");
    command
        .arg("--no-optional-locks")
        .arg("-C")
        .arg(repo)
        .args(args);
    let mut output = Vec::new();
    // Same bounded runner, so a stuck git cannot hang the tool; output kept whole up to 16 Mio.
    let outcome = run_capture(command, GIT_TIMEOUT, &mut output).ok()?;
    (outcome == Some(0)).then_some(output)
}

fn run_capture(mut command: Command, timeout: Duration, out: &mut Vec<u8>) -> Result<Option<i32>> {
    command.env_clear();
    for name in PASSTHROUGH {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn()?;
    let mut stdout = child.stdout.take().ok_or_else(|| anyhow!("stdout"))?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = (&mut stdout).take(MAX_OUTPUT_BYTES).read_to_end(&mut bytes);
        let _ = tx.send(bytes);
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            child.wait()?;
            bail!("délai dépassé");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    *out = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
    Ok(status.code())
}

/// The repository revision now: HEAD, dirty or not, and a digest of what is uncommitted.
/// Fields are None when git is unavailable.
pub fn revision(repo: &Path) -> Revision {
    let head = git(repo, &["rev-parse", "HEAD"])
        .map(|b| String::from_utf8_lossy(&b).trim().to_string())
        .filter(|h| !h.is_empty());
    // Rule files are excluded: changing a rule's state must not make the code look changed
    // (a rule's own content is tracked by its own digest, see rules.rs).
    let status = git(
        repo,
        &[
            "status",
            "--porcelain",
            "--",
            ".",
            ":(exclude).agents/rules",
        ],
    );
    let diff = git(
        repo,
        &[
            "diff",
            "HEAD",
            "--no-ext-diff",
            "--no-color",
            "--",
            ".",
            ":(exclude).agents/rules",
        ],
    );
    let dirty = status.as_ref().map(|s| !s.is_empty());
    let tree_sha256 = match (&status, &diff) {
        (Some(s), Some(d)) => {
            let mut h = Sha256::new();
            h.update(b"status\0");
            h.update(s);
            h.update(b"\0diff\0");
            h.update(d);
            Some(hex::encode(h.finalize()))
        }
        _ => None,
    };
    Revision {
        head,
        dirty,
        tree_sha256,
    }
}

/// Why a result no longer describes the repository (empty: still current).
pub fn stale_reasons(
    result: &CheckResult,
    checks_now: Option<&str>,
    now: &Revision,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if checks_now != Some(result.checks_sha256.as_str()) {
        reasons.push("le fichier de contrôles a changé depuis ce résultat".to_string());
    }
    if let Some(head) = &result.revision.head
        && now.head.as_ref() != Some(head)
    {
        reasons.push("la révision du dépôt a changé".to_string());
    }
    if let Some(tree) = &result.revision.tree_sha256
        && now.tree_sha256.as_ref() != Some(tree)
    {
        reasons.push("l'arbre de travail a changé".to_string());
    }
    if result.platform != platform() {
        reasons.push(format!("résultat obtenu sous {}", result.platform));
    }
    reasons
}
