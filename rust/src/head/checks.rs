//! The evaluator: checks the developer allowed, run by the tool itself.
//!
//! What runs comes only from `.agents/checks.json` of a trusted repository, as it was when
//! trust was given (see trust.rs): the program, named by an absolute path (a bare or
//! relative name is refused, so no search path is ever consulted), its arguments (an
//! argument vector, never a shell line), the working directory (inside the snapshot) and
//! the timeout. The only thing taken from the command line is the check's name.
//!
//! The environment is built from fixed values, never inherited: PATH, HOME (a private
//! directory of the tool's cache), CARGO_HOME and RUSTUP_HOME (the account's own, from the
//! account database), LANG and PYTHONDONTWRITEBYTECODE, plus the variables the check's entry
//! lists with their values (`@cache` and `@home` stand for the tool's cache directory and
//! the account's home). Each result records the program's path and the SHA-256 of its
//! content, and the SHA-256 of the whole execution configuration (program, arguments,
//! directory, environment, bounds, isolation, Cargo's configuration files under
//! CARGO_HOME); a change in either makes the result stale.
//!
//! A check runs contained (see contain.rs) in a read-only snapshot of the repository's
//! inputs (see tree.rs). Its outcome is "passed" only if it exited with 0 within its time,
//! its output was captured completely within its bound, containment and cleanup were
//! confirmed, the network was isolated when the check requires it, and the snapshot was
//! left intact. A genuine non-zero exit under those conditions is "failed"; anything else
//! is "incomplete". Only a "passed" result can certify anything.
use super::contain::{self, RunSpec};
use super::tree;
use super::trust::{Context, private_dir};
use anyhow::{Context as _, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const CHECKS_FILE: &str = ".agents/checks.json";
pub const MAX_CHECKS_FILE_BYTES: u64 = 64 * 1024;
pub const DEFAULT_OUTPUT_BYTES: u64 = 1024 * 1024;
const MAX_TIMEOUT_SECS: u64 = 7200;
const MAX_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PROGRAM_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChecksFile {
    version: u32,
    git: Platformed<String>,
    checks: BTreeMap<String, CheckSpec>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Platformed<T> {
    #[serde(default)]
    pub unix: Option<T>,
    #[serde(default)]
    pub windows: Option<T>,
}

impl<T> Platformed<T> {
    fn current(&self) -> Option<&T> {
        if cfg!(windows) {
            self.windows.as_ref()
        } else {
            self.unix.as_ref()
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckSpec {
    #[serde(default)]
    pub description: String,
    pub command: Platformed<Vec<String>>,
    #[serde(default = "dot")]
    pub cwd: String,
    pub timeout_secs: u64,
    #[serde(default)]
    pub max_output_bytes: Option<u64>,
    /// Extra environment variables, with their values (no inheritance).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// The result cannot pass unless the network was isolated.
    #[serde(default)]
    pub requires_isolation: bool,
    /// Run without containment (e.g. a Windows program reached through WSL): its result is
    /// always "incomplete" and certifies nothing.
    #[serde(default)]
    pub uncontained: bool,
}
fn dot() -> String {
    ".".into()
}

/// Kept for results written before snapshots existed (then `head` and `dirty` came from git).
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Revision {
    pub head: Option<String>,
    pub dirty: Option<bool>,
    pub tree_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecInfo {
    pub program: String,
    pub program_sha256: String,
    pub config_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Isolation {
    pub contained: bool,
    pub network_isolated: bool,
    pub cleanup_confirmed: bool,
    pub capture_complete: bool,
    pub requires_isolation: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckResult {
    pub name: String,
    /// True only when `outcome` is "passed".
    pub passed: bool,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub duration_ms: u64,
    /// SHA-256 of "stdout:" + hex SHA-256(stdout) + "\nstderr:" + hex SHA-256(stderr).
    pub output_sha256: String,
    pub output_bytes: u64,
    pub output_truncated: bool,
    pub checks_sha256: String,
    pub revision: Revision,
    pub platform: String,
    /// passed, failed or incomplete (absent in results written before snapshots).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// Digest of the snapshot the check ran in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isolation: Option<Isolation>,
    /// Why the outcome is not "passed", when it is not.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub problems: Vec<String>,
}

pub struct Checks {
    pub sha256: String,
    git: Platformed<String>,
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

/// An absolute path in the syntax of the platform it is written for: "/..." for Unix,
/// "C:\..." or "C:/..." for Windows (checked as text, whatever platform reads the file).
fn absolute_program(program: &str, windows: bool) -> bool {
    let bytes = program.as_bytes();
    let absolute = if windows {
        bytes.len() > 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'/' | b'\\')
    } else {
        program.starts_with('/')
    };
    absolute && !program.contains('\0') && program.len() <= 1000
}

/// Parse and validate an allow-list (`root` is where working directories are checked).
pub fn parse(bytes: &[u8], root: &Path) -> Result<Checks> {
    let file: ChecksFile =
        serde_json::from_slice(bytes).with_context(|| format!("{CHECKS_FILE} illisible"))?;
    ensure!(
        file.version == 2,
        "{CHECKS_FILE} : version 2 attendue (programmes en chemin absolu)"
    );
    for (program, windows) in [(&file.git.unix, false), (&file.git.windows, true)] {
        if let Some(program) = program {
            ensure!(
                absolute_program(program, windows),
                "{CHECKS_FILE} : git doit être un chemin absolu"
            );
        }
    }
    for (name, spec) in &file.checks {
        ensure!(valid_name(name), "nom de contrôle invalide : {name}");
        validate_spec(root, name, spec)?;
    }
    Ok(Checks {
        sha256: sha256_hex(bytes),
        git: file.git,
        specs: file.checks,
    })
}

/// The trusted repository's allow-list (refused if it changed since trust was given).
pub fn load(ctx: &Context) -> Result<Checks> {
    parse(&ctx.checks_bytes()?, &ctx.root)
}

fn validate_spec(root: &Path, name: &str, spec: &CheckSpec) -> Result<()> {
    for (argv, windows) in [(&spec.command.unix, false), (&spec.command.windows, true)] {
        let Some(argv) = argv else { continue };
        ensure!(
            !argv.is_empty()
                && argv.len() <= 64
                && argv.iter().all(|a| a.len() <= 1000 && !a.contains('\0')),
            "contrôle {name} : commande invalide"
        );
        ensure!(
            absolute_program(&argv[0], windows),
            "contrôle {name} : le programme doit être nommé par un chemin absolu, pas « {} »",
            argv[0]
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
    for (key, value) in &spec.env {
        ensure!(
            !key.is_empty()
                && key.len() <= 64
                && key
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
                && value.len() <= 4000
                && !value.contains('\0'),
            "contrôle {name} : variable d'environnement invalide {key}"
        );
    }
    ensure!(
        !(spec.requires_isolation && spec.uncontained),
        "contrôle {name} : une isolation exigée ne peut pas être lancée sans confinement"
    );
    relative_dir(&spec.cwd).with_context(|| format!("contrôle {name}"))?;
    let _ = root;
    Ok(())
}

/// A working directory: relative, inside the repository (no root, no "..").
fn relative_dir(cwd: &str) -> Result<PathBuf> {
    let relative = Path::new(cwd);
    ensure!(
        !relative.is_absolute()
            && relative.components().all(|c| matches!(
                c,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )),
        "répertoire de travail : chemin relatif au dépôt requis"
    );
    Ok(relative.to_path_buf())
}

impl Checks {
    pub fn names(&self) -> Vec<&str> {
        self.specs.keys().map(String::as_str).collect()
    }
    pub fn git_program(&self) -> Option<PathBuf> {
        self.git.current().map(PathBuf::from)
    }
    pub fn describe(&self) -> serde_json::Value {
        serde_json::json!(
            self.specs
                .iter()
                .map(|(n, s)| (
                    n.clone(),
                    serde_json::json!({
                        "description": s.description,
                        "command": s.command.current(),
                        "cwd": s.cwd,
                        "timeout_secs": s.timeout_secs,
                        "env": s.env,
                        "requires_isolation": s.requires_isolation,
                        "uncontained": s.uncontained,
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

pub fn platform() -> &'static str {
    if cfg!(windows) { "windows" } else { "unix" }
}

fn expand(value: &str, ctx: &Context) -> Result<String> {
    Ok(value
        .replace("@cache", &ctx.settings.cache()?.display().to_string())
        .replace("@home", &ctx.settings.user_home.display().to_string()))
}

/// The environment of a check: fixed values, then the entry's own (see module documentation).
pub fn environment(ctx: &Context, spec: &CheckSpec) -> Result<Vec<(String, String)>> {
    let home = ctx.settings.cache()?.join("home");
    private_dir(&home)?;
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    let user = &ctx.settings.user_home;
    if cfg!(windows) {
        env.insert("PATH".into(), "C:\\Windows\\System32;C:\\Windows".into());
        env.insert("SYSTEMROOT".into(), "C:\\Windows".into());
        env.insert("USERPROFILE".into(), home.display().to_string());
    } else {
        env.insert("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into());
    }
    env.insert("HOME".into(), home.display().to_string());
    env.insert(
        "CARGO_HOME".into(),
        user.join(".cargo").display().to_string(),
    );
    env.insert(
        "RUSTUP_HOME".into(),
        user.join(".rustup").display().to_string(),
    );
    env.insert("LANG".into(), "C.UTF-8".into());
    env.insert("PYTHONDONTWRITEBYTECODE".into(), "1".into());
    for (key, value) in &spec.env {
        env.insert(key.clone(), expand(value, ctx)?);
    }
    Ok(env.into_iter().collect())
}

fn file_digest(path: &Path, limit: u64) -> Result<String> {
    use std::io::Read;
    let mut file =
        std::fs::File::open(path).with_context(|| format!("{} introuvable", path.display()))?;
    ensure!(
        file.metadata()?.is_file(),
        "{} : fichier ordinaire requis",
        path.display()
    );
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 16];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        ensure!(total <= limit, "{} : trop grand", path.display());
        hasher.update(&buffer[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Program and execution configuration of a check as they are now.
pub fn exec_info(ctx: &Context, checks: &Checks, name: &str) -> Result<ExecInfo> {
    let spec = checks.get(name)?;
    let argv = spec
        .command
        .current()
        .ok_or_else(|| anyhow!("contrôle {name} : aucune commande pour {}", platform()))?;
    let program = PathBuf::from(&argv[0]);
    let program_sha256 = file_digest(&program, MAX_PROGRAM_BYTES)?;
    let env = environment(ctx, spec)?;
    let cargo_home = env
        .iter()
        .find(|(k, _)| k == "CARGO_HOME")
        .map(|(_, v)| PathBuf::from(v));
    let mut cargo_config = BTreeMap::new();
    if let Some(home) = cargo_home {
        for name in ["config.toml", "config"] {
            let path = home.join(name);
            let state = match std::fs::symlink_metadata(&path) {
                Ok(_) => file_digest(&path, MAX_CHECKS_FILE_BYTES * 16)?,
                Err(_) => "absent".to_string(),
            };
            cargo_config.insert(path.display().to_string(), state);
        }
    }
    let config = serde_json::json!({
        "argv": argv,
        "cwd": spec.cwd,
        "env": env,
        "timeout_secs": spec.timeout_secs,
        "max_output_bytes": spec.max_output_bytes.unwrap_or(DEFAULT_OUTPUT_BYTES),
        "requires_isolation": spec.requires_isolation,
        "uncontained": spec.uncontained,
        "cargo_config": cargo_config,
        "platform": platform(),
    });
    Ok(ExecInfo {
        program: program.display().to_string(),
        program_sha256,
        config_sha256: sha256_hex(&serde_json::to_vec(&config)?),
    })
}

/// Run the named check of `checks`. Only `name` comes from the caller.
pub fn run(ctx: &Context, checks: &Checks, name: &str) -> Result<CheckResult> {
    run_with_tail(ctx, checks, name).map(|(result, _)| result)
}

fn incomplete(name: &str, checks: &Checks, exec: Option<ExecInfo>, problem: String) -> CheckResult {
    CheckResult {
        name: name.into(),
        passed: false,
        exit_code: None,
        timed_out: false,
        duration_ms: 0,
        output_sha256: sha256_hex(b""),
        output_bytes: 0,
        output_truncated: false,
        checks_sha256: checks.sha256.clone(),
        revision: Revision {
            head: None,
            dirty: None,
            tree_sha256: None,
        },
        platform: platform().into(),
        outcome: Some("incomplete".into()),
        snapshot_sha256: None,
        exec,
        isolation: None,
        problems: vec![problem],
    }
}

/// As `run`, plus the end of the output (at most 4000 bytes) for the person who ran it.
/// The tail is shown on the command line only; the journal keeps its digest, never text.
pub fn run_with_tail(ctx: &Context, checks: &Checks, name: &str) -> Result<(CheckResult, String)> {
    let spec = checks.get(name)?.clone();
    let argv = spec
        .command
        .current()
        .ok_or_else(|| anyhow!("contrôle {name} : aucune commande pour {}", platform()))?
        .clone();
    let exec = exec_info(ctx, checks, name)?;
    let snapshot = match tree::snapshot(ctx, checks) {
        Ok(s) => s,
        Err(e) => {
            return Ok((
                incomplete(
                    name,
                    checks,
                    Some(exec),
                    format!("empreinte ou instantané impossible : {e:#}"),
                ),
                String::new(),
            ));
        }
    };
    let cwd = snapshot.tree.join(relative_dir(&spec.cwd)?);
    if !cwd.is_dir() {
        return Ok((
            incomplete(
                name,
                checks,
                Some(exec),
                format!(
                    "répertoire de travail absent de l'instantané : {}",
                    spec.cwd
                ),
            ),
            String::new(),
        ));
    }
    let limit = spec.max_output_bytes.unwrap_or(DEFAULT_OUTPUT_BYTES);
    let run_spec = RunSpec {
        program: PathBuf::from(&argv[0]),
        args: argv[1..].to_vec(),
        cwd,
        env: environment(ctx, &spec)?,
        timeout: Duration::from_secs(spec.timeout_secs),
        max_output: limit,
        contain: !spec.uncontained,
        keep_stdout: false,
    };
    let started = Instant::now();
    let outcome = match contain::run(&run_spec) {
        Ok(o) => o,
        Err(e) => contain::error_outcome(format!("lancement impossible : {e}")),
    };
    let duration_ms = started.elapsed().as_millis() as u64;
    let mut problems = outcome.problems.clone();
    let intact = snapshot.intact().unwrap_or(false);
    if !intact {
        problems.push("le contrôle a modifié l'instantané".into());
    }
    if spec.requires_isolation && !outcome.network_isolated {
        problems.push("isolation réseau exigée mais non obtenue".into());
    }
    let finished = outcome.contained
        && outcome.cleanup_confirmed
        && outcome.capture_complete
        && intact
        && (!spec.requires_isolation || outcome.network_isolated);
    let verdict = if !finished {
        "incomplete"
    } else if outcome.exit_code == Some(0) && !outcome.timed_out {
        "passed"
    } else {
        if outcome.timed_out {
            problems.push("délai dépassé".into());
        }
        "failed"
    };
    let tail = String::from_utf8_lossy(&outcome.tail).into_owned();
    let result = CheckResult {
        name: name.into(),
        passed: verdict == "passed",
        exit_code: outcome.exit_code,
        timed_out: outcome.timed_out,
        duration_ms,
        output_sha256: outcome.output_sha256.clone(),
        output_bytes: outcome.output_bytes,
        output_truncated: outcome.output_bytes > limit,
        checks_sha256: checks.sha256.clone(),
        revision: Revision {
            head: None,
            dirty: None,
            tree_sha256: Some(snapshot.digest.sha256.clone()),
        },
        platform: platform().into(),
        outcome: Some(verdict.into()),
        snapshot_sha256: Some(snapshot.digest.sha256.clone()),
        exec: Some(exec),
        isolation: Some(Isolation {
            contained: outcome.contained,
            network_isolated: outcome.network_isolated,
            cleanup_confirmed: outcome.cleanup_confirmed,
            capture_complete: outcome.capture_complete,
            requires_isolation: spec.requires_isolation,
        }),
        problems,
    };
    Ok((result, tail))
}

/// What the repository looks like now, computed at most once per command.
pub struct Now<'a> {
    ctx: &'a Context,
    checks: Option<Result<Checks>>,
    tree: Option<Result<tree::TreeDigest, String>>,
    exec: BTreeMap<String, Result<ExecInfo, String>>,
}

impl<'a> Now<'a> {
    pub fn new(ctx: &'a Context) -> Self {
        Self {
            ctx,
            checks: None,
            tree: None,
            exec: BTreeMap::new(),
        }
    }
    fn checks(&mut self) -> Result<&Checks, String> {
        let ctx = self.ctx;
        self.checks
            .get_or_insert_with(|| load(ctx))
            .as_ref()
            .map_err(|e| format!("{e:#}"))
    }
    pub fn checks_sha256(&mut self) -> Option<String> {
        self.checks().ok().map(|c| c.sha256.clone())
    }
    pub fn tree(&mut self) -> Result<String, String> {
        if self.tree.is_none() {
            let value = match self.checks() {
                Ok(_) => {
                    let checks = self.checks.as_ref().unwrap().as_ref().unwrap();
                    tree::digest(self.ctx, checks).map_err(|e| format!("{e:#}"))
                }
                Err(e) => Err(e),
            };
            self.tree = Some(value);
        }
        self.tree
            .as_ref()
            .unwrap()
            .as_ref()
            .map(|d| d.sha256.clone())
            .map_err(Clone::clone)
    }
    pub fn exec(&mut self, name: &str) -> Result<ExecInfo, String> {
        if !self.exec.contains_key(name) {
            let value = match self.checks() {
                Ok(_) => {
                    let checks = self.checks.as_ref().unwrap().as_ref().unwrap();
                    exec_info(self.ctx, checks, name).map_err(|e| format!("{e:#}"))
                }
                Err(e) => Err(e),
            };
            self.exec.insert(name.to_string(), value);
        }
        self.exec[name].clone()
    }
}

/// Why a result does not certify the repository as it is now (empty: it does).
pub fn certify(result: &CheckResult, now: &mut Now) -> Vec<String> {
    let mut reasons = Vec::new();
    let Some(snapshot) = &result.snapshot_sha256 else {
        return vec!["résultat d'avant les instantanés : relancer le contrôle".into()];
    };
    if result.outcome.as_deref() != Some("passed") {
        reasons.push(format!(
            "résultat {}",
            result.outcome.as_deref().unwrap_or("inconnu")
        ));
    }
    if result.platform != platform() {
        reasons.push(format!("résultat obtenu sous {}", result.platform));
    }
    match now.checks_sha256() {
        Some(h) if h == result.checks_sha256 => {}
        Some(_) => reasons.push("la liste des contrôles a changé depuis ce résultat".into()),
        None => reasons.push("liste des contrôles illisible".into()),
    }
    match (now.exec(&result.name), &result.exec) {
        (Ok(current), Some(recorded)) if &current == recorded => {}
        (Ok(current), Some(recorded)) if current.program_sha256 != recorded.program_sha256 => {
            reasons.push("le programme du contrôle a changé".into())
        }
        (Ok(_), Some(_)) => reasons.push("la configuration d'exécution a changé".into()),
        (Ok(_), None) => reasons.push("résultat sans empreinte d'exécution".into()),
        (Err(e), _) => reasons.push(format!("configuration d'exécution illisible : {e}")),
    }
    match now.tree() {
        Ok(tree) if &tree == snapshot => {}
        Ok(_) => reasons.push("l'arbre de travail diffère de l'instantané contrôlé".into()),
        Err(e) => reasons.push(format!("empreinte de l'arbre de travail impossible : {e}")),
    }
    reasons
}
