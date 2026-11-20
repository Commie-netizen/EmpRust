//! Shared helpers of the head's integration tests: a real Git repository, trusted in a
//! private settings directory (never the account's own trust list).
#![allow(dead_code)]
use empreinte::head::trust::{self, Context};
use empreinte::head::{Input, Memory, Settings, checks, rules};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const JOURNAL: &str = "events.jsonl";

pub struct Repo {
    pub _dir: tempfile::TempDir,
    pub _state: tempfile::TempDir,
    pub root: PathBuf,
    pub memory: PathBuf,
    pub settings: Settings,
    pub ctx: Context,
}

pub fn git(root: &Path, args: &[&str]) -> bool {
    Command::new("/usr/bin/git")
        .args([
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .current_dir(root)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// An allow-list with the given checks (a JSON object body), git at its usual place.
pub fn allow_list(checks: &str) -> String {
    format!(r#"{{"version":2,"git":{{"unix":"/usr/bin/git"}},"checks":{{{checks}}}}}"#)
}

pub fn check(name: &str, argv: &[&str], timeout: u64, extra: &str) -> String {
    let argv = serde_json::to_string(argv).unwrap();
    format!(r#""{name}":{{"command":{{"unix":{argv}}},"timeout_secs":{timeout}{extra}}}"#)
}

pub fn ok_ko() -> String {
    allow_list(&format!(
        "{},{}",
        check("ok", &["/bin/true"], 30, ""),
        check("ko", &["/bin/false"], 30, "")
    ))
}

/// A Git repository with `checks` as allow-list, trusted.
pub fn repo(checks_body: &str) -> Repo {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    assert!(git(&root, &["init", "-q"]), "git init");
    fs::create_dir_all(root.join(".agents")).unwrap();
    fs::write(root.join(checks::CHECKS_FILE), checks_body).unwrap();
    let state = tempfile::tempdir().unwrap();
    let settings = Settings::in_dir(
        &state.path().canonicalize().unwrap(),
        &state.path().canonicalize().unwrap(),
    );
    trust::trust(&settings, &root, true).unwrap();
    let ctx = trust::resolve(&settings, Some(&root), &root).unwrap();
    let memory = root.join(".empreinte-head");
    Repo {
        _dir: dir,
        _state: state,
        root,
        memory,
        settings,
        ctx,
    }
}

/// Replace the allow-list and trust it again (as a person would after reading it).
pub fn retrust(r: &mut Repo, checks_body: &str) {
    fs::write(r.root.join(checks::CHECKS_FILE), checks_body).unwrap();
    trust::trust(&r.settings, &r.root, true).unwrap();
    r.ctx = trust::resolve(&r.settings, Some(&r.root), &r.root).unwrap();
}

pub fn input(id: &str, task: &str, kind: &str) -> Input {
    Input {
        event_id: id.into(),
        task_id: task.into(),
        kind: kind.into(),
        summary: "mémoire Rust".into(),
        source_refs: vec![],
        evidence_refs: vec![],
        supersedes: None,
    }
}

pub fn running_task(r: &Repo, task: &str) {
    let mut m = Memory::open(&r.memory, &r.ctx).unwrap();
    m.record(input(&format!("{task}-p"), task, "proposed"))
        .unwrap();
    m.record(input(&format!("{task}-r"), task, "running"))
        .unwrap();
}

pub fn rules_dir(r: &Repo) -> PathBuf {
    let dir = r.root.join(rules::RULES_DIR);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// A rule as a person writes it (not in the tool's canonical form).
pub fn write_rule(r: &Repo, id: &str, refuted_by: &str, replaces: Option<&str>) {
    let replaces = replaces
        .map(|x| format!(",\n  \"replaces\": \"{x}\""))
        .unwrap_or_default();
    fs::write(
        rules_dir(r).join(format!("{id}.json")),
        format!(
            "{{\n  \"version\": 1, \"id\": \"{id}\",\n  \"statement\": \"Règle {id}.\",\n  \"scope\": [\"src\"],\n  \"origin\": [\"observation\"],\n  \"refuted_by\": [{refuted_by}]{replaces},\n  \"state\": \"candidate\"\n}}\n"
        ),
    )
    .unwrap();
}

/// Write then register a rule (the only way a rule file enters the journal).
pub fn new_rule(r: &Repo, id: &str, refuted_by: &str, replaces: Option<&str>) {
    write_rule(r, id, refuted_by, replaces);
    rules::register(&r.memory, &r.ctx, id).unwrap();
}

pub fn files(r: &Repo) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(rules_dir(r))
        .unwrap()
        .map(|e| e.unwrap().path())
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                fs::read(p).unwrap(),
            )
        })
        .collect()
}

pub fn derived(r: &Repo) -> BTreeMap<String, String> {
    let m = Memory::open(&r.memory, &r.ctx).unwrap();
    rules::states(m.events())
        .into_iter()
        .map(|(k, v)| (k, v.state))
        .collect()
}

/// Processes whose command name is `comm`, zombies included.
pub fn processes_named(comm: &str) -> Vec<String> {
    let mut found = Vec::new();
    for entry in fs::read_dir("/proc").unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if let Ok(stat) = fs::read_to_string(entry.path().join("stat"))
            && stat.contains(&format!("({comm})"))
        {
            found.push(stat);
        }
    }
    found
}
