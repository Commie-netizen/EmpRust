//! Rule life cycle: versioned rule files, measured against the allowed checks, promoted
//! and rolled back by explicit commands, every move recorded by the tool.
//!
//! A rule is a file `.agents/rules/<id>.json`: an identifier, a statement, a scope and an
//! origin (both plain text), the names of the checks that can refute it (only names that
//! exist in `.agents/checks.json`), optionally the rule it would replace, and its state.
//! Any other field (a command, an argument, a path to run, an environment variable, a
//! permission) makes the file invalid. A rule's text is data: nothing in it is executed
//! or read as an instruction.
//!
//! States and the only moves: candidate -> evaluated (a passing evaluation), evaluated ->
//! active (promote), active -> evaluated (rollback, undoing the last promotion), and
//! candidate, evaluated or active -> retired. Each move is a journal event of kind "rule"
//! written by the tool with the digests of the files before and after; the journal alone
//! gives every rule's state, and a file that disagrees with it is reported, not trusted.
//!
//! "active" means listed as active: status and recall return it so that whoever starts
//! work can read it. Nothing consumes or enforces a rule automatically.
use super::checks::{self, Checks, Revision};
use super::{Event, Memory, SCHEMA_VERSION, now};
use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const RULES_DIR: &str = ".agents/rules";
pub const MAX_RULE_BYTES: u64 = 16 * 1024;
const MAX_RULES: usize = 200;
const STATES: [&str; 4] = ["candidate", "evaluated", "active", "retired"];

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub version: u32,
    pub id: String,
    pub statement: String,
    #[serde(default)]
    pub scope: Vec<String>,
    #[serde(default)]
    pub origin: Vec<String>,
    pub refuted_by: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces: Option<String>,
    pub state: String,
}

pub struct RuleFile {
    pub rule: Rule,
    pub text: String,
    /// SHA-256 of the file bytes.
    pub file_sha256: String,
    /// SHA-256 of the rule's canonical JSON without its state: what an evaluation is tied to.
    pub content_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Measure {
    pub name: String,
    pub passed: bool,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub duration_ms: u64,
    pub output_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Evaluation {
    pub passed: bool,
    pub checks: Vec<Measure>,
    pub checks_sha256: String,
    pub revision: Revision,
    pub platform: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleChange {
    pub rule: String,
    pub state_before: Option<String>,
    pub state_after: String,
    pub file_sha256_before: String,
    pub file_sha256_after: String,
    /// The exact file before the move, so that a rollback restores it byte for byte.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_text: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleRecord {
    /// registered, evaluated, promoted, rolled-back or retired.
    pub action: String,
    pub rule: String,
    pub content_sha256: String,
    #[serde(default)]
    pub changes: Vec<RuleChange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation: Option<Evaluation>,
    /// For rolled-back: the promotion event undone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undoes: Option<String>,
}

fn valid_rule_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn is_link(meta: &fs::Metadata) -> bool {
    super::is_link(meta)
}

fn rules_dir(repo: &Path) -> Result<PathBuf> {
    let dir = repo.join(RULES_DIR);
    let meta = fs::symlink_metadata(&dir).context("dossier des règles absent")?;
    ensure!(
        meta.is_dir() && !is_link(&meta),
        "{RULES_DIR} doit être un dossier ordinaire"
    );
    Ok(dir)
}

pub fn rule_path(repo: &Path, id: &str) -> Result<PathBuf> {
    ensure!(valid_rule_id(id), "identifiant de règle invalide : {id}");
    Ok(rules_dir(repo)?.join(format!("{id}.json")))
}

fn content_digest(rule: &Rule) -> Result<String> {
    let mut value = serde_json::to_value(rule)?;
    value
        .as_object_mut()
        .ok_or_else(|| anyhow!("règle"))?
        .remove("state");
    Ok(checks::sha256_hex(&serde_json::to_vec(&value)?))
}

/// Read and validate one rule file. Refused: a link, a non-regular file, over 16 Kio, an
/// unknown field, a check name absent from the allow-list, an id that is not the name.
pub fn load_rule(repo: &Path, id: &str, allowed: &Checks) -> Result<RuleFile> {
    let path = rule_path(repo, id)?;
    let meta = fs::symlink_metadata(&path).with_context(|| format!("règle introuvable : {id}"))?;
    ensure!(
        meta.is_file() && !is_link(&meta),
        "règle {id} : fichier ordinaire requis"
    );
    let mut bytes = Vec::new();
    fs::File::open(&path)?
        .take(MAX_RULE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_RULE_BYTES,
        "règle {id} : plus de 16 Kio"
    );
    let text = String::from_utf8(bytes).map_err(|_| anyhow!("règle {id} : texte UTF-8 requis"))?;
    let rule: Rule = serde_json::from_str(&text)
        .with_context(|| format!("règle {id} : champs inconnus ou invalides"))?;
    ensure!(rule.version == 1, "règle {id} : version 1 attendue");
    ensure!(
        rule.id == id,
        "règle {id} : l'identifiant ne correspond pas au nom du fichier"
    );
    ensure!(
        !rule.statement.trim().is_empty() && rule.statement.len() <= 2000,
        "règle {id} : énoncé invalide"
    );
    ensure!(
        rule.scope.len() <= 16
            && rule.origin.len() <= 16
            && rule.scope.iter().all(|s| !s.is_empty() && s.len() <= 300)
            && rule.origin.iter().all(|s| !s.is_empty() && s.len() <= 500),
        "règle {id} : portée ou origine invalide"
    );
    ensure!(
        (1..=8).contains(&rule.refuted_by.len()),
        "règle {id} : de un à huit contrôles réfutants"
    );
    for name in &rule.refuted_by {
        ensure!(
            checks::valid_name(name),
            "règle {id} : nom de contrôle invalide"
        );
    }
    if let Some(other) = &rule.replaces {
        ensure!(
            valid_rule_id(other) && other != id,
            "règle {id} : replaces invalide"
        );
    }
    ensure!(
        STATES.contains(&rule.state.as_str()),
        "règle {id} : état inconnu"
    );
    for name in &rule.refuted_by {
        allowed
            .get(name)
            .with_context(|| format!("règle {id} : contrôle absent de la liste autorisée"))?;
    }
    Ok(RuleFile {
        file_sha256: checks::sha256_hex(text.as_bytes()),
        content_sha256: content_digest(&rule)?,
        rule,
        text,
    })
}

/// Every *.json of the rules directory, each loaded on its own: an invalid file is
/// reported and does not hide the others.
pub fn list_rules(repo: &Path, allowed: &Checks) -> Vec<(String, Result<RuleFile>)> {
    let Ok(dir) = rules_dir(repo) else {
        return Vec::new();
    };
    let Ok(entries) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str().map(str::to_owned))
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.sort();
    names
        .into_iter()
        .take(MAX_RULES)
        .map(|name| {
            let id = name.trim_end_matches(".json").to_string();
            let loaded = load_rule(repo, &id, allowed);
            (id, loaded)
        })
        .collect()
}

/// The tool's form of a rule file: sorted keys, two-space indent, final newline.
fn canonical_text(rule: &Rule) -> Result<String> {
    let value = serde_json::to_value(rule)?;
    Ok(serde_json::to_string_pretty(&value)? + "\n")
}

/// Replace a rule file atomically (temporary file in the same directory, then rename).
fn write_rule(repo: &Path, id: &str, text: &str) -> Result<()> {
    let path = rule_path(repo, id)?;
    let temporary = path.with_extension(format!("tmp-{}", hex::encode(rand::random::<[u8; 4]>())));
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
    }
    if let Err(e) = fs::rename(&temporary, &path) {
        let _ = fs::remove_file(&temporary);
        return Err(e.into());
    }
    Ok(())
}

// ------------------------------------------------------------------ state from the journal

#[derive(Debug, Clone, Default)]
pub struct RuleState {
    pub state: String,
    pub file_sha256: String,
    pub content_sha256: String,
    /// Last evaluation: event id, content digest evaluated, measures.
    pub evaluation: Option<(String, String, Evaluation)>,
    /// Promotion events not yet rolled back, oldest first.
    pub promotions: Vec<String>,
}

/// Every rule's state rebuilt from the journal alone.
pub fn states(events: &[Event]) -> BTreeMap<String, RuleState> {
    let mut out: BTreeMap<String, RuleState> = BTreeMap::new();
    for event in events {
        let Some(record) = &event.rule else { continue };
        for change in &record.changes {
            let entry = out.entry(change.rule.clone()).or_default();
            entry.state = change.state_after.clone();
            entry.file_sha256 = change.file_sha256_after.clone();
        }
        let entry = out.entry(record.rule.clone()).or_default();
        entry.content_sha256 = record.content_sha256.clone();
        match record.action.as_str() {
            "evaluated" => {
                if let Some(evaluation) = &record.evaluation {
                    entry.evaluation = Some((
                        event.event_id.clone(),
                        record.content_sha256.clone(),
                        evaluation.clone(),
                    ));
                }
            }
            "promoted" => entry.promotions.push(event.event_id.clone()),
            "rolled-back" => {
                if let Some(undone) = &record.undoes {
                    entry.promotions.retain(|p| p != undone);
                }
            }
            _ => {}
        }
    }
    out
}

fn move_allowed(action: &str, own: bool, before: Option<&str>, after: &str) -> bool {
    match (action, own) {
        ("registered", true) => before.is_none() && after == "candidate",
        ("evaluated", true) => before == Some("candidate") && after == "evaluated",
        ("promoted", true) => before == Some("evaluated") && after == "active",
        ("promoted", false) => before == Some("active") && after == "retired",
        ("rolled-back", true) => before == Some("active") && after == "evaluated",
        ("rolled-back", false) => before == Some("retired") && after == "active",
        ("retired", true) => {
            matches!(before, Some("candidate" | "evaluated" | "active")) && after == "retired"
        }
        _ => false,
    }
}

/// A rule event must follow from the journal before it (replay and append alike).
pub(super) fn check_move(events: &[Event], record: &RuleRecord) -> Result<()> {
    ensure!(valid_rule_id(&record.rule), "règle : identifiant invalide");
    ensure!(
        super::valid_hex64(&record.content_sha256),
        "règle : empreinte invalide"
    );
    let current = states(events);
    for change in &record.changes {
        let before = current
            .get(&change.rule)
            .map(|s| s.state.as_str())
            .filter(|s| !s.is_empty());
        ensure!(
            before == change.state_before.as_deref(),
            "règle {} : état précédent incohérent avec le journal",
            change.rule
        );
        ensure!(
            move_allowed(
                &record.action,
                change.rule == record.rule,
                before,
                &change.state_after
            ),
            "règle {} : mouvement {} interdit",
            change.rule,
            record.action
        );
        if let Some(state) = current.get(&change.rule)
            && !state.file_sha256.is_empty()
        {
            ensure!(
                state.file_sha256 == change.file_sha256_before,
                "règle {} : fichier différent de celui du journal",
                change.rule
            );
        }
    }
    match record.action.as_str() {
        "registered" | "promoted" | "retired" => {
            ensure!(
                !record.changes.is_empty(),
                "règle : mouvement sans changement"
            )
        }
        "evaluated" => ensure!(record.evaluation.is_some(), "évaluation absente"),
        "rolled-back" => {
            let undone = record
                .undoes
                .as_deref()
                .ok_or_else(|| anyhow!("retour sans promotion"))?;
            ensure!(
                current
                    .get(&record.rule)
                    .is_some_and(|s| s.promotions.last().map(String::as_str) == Some(undone)),
                "retour : ce n'est pas la dernière promotion de cette règle"
            );
        }
        other => bail!("règle : action inconnue {other}"),
    }
    Ok(())
}

// ------------------------------------------------------------------ staleness

fn evaluation_stale(
    content_evaluated: &str,
    evaluation: &Evaluation,
    content_now: &str,
    checks_now: Option<&str>,
    revision_now: &Revision,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if content_evaluated != content_now {
        reasons.push("la règle a changé depuis l'évaluation".to_string());
    }
    if checks_now != Some(evaluation.checks_sha256.as_str()) {
        reasons.push("le fichier de contrôles a changé depuis l'évaluation".to_string());
    }
    if let Some(head) = &evaluation.revision.head
        && revision_now.head.as_ref() != Some(head)
    {
        reasons.push("la révision du dépôt a changé".to_string());
    }
    if let Some(tree) = &evaluation.revision.tree_sha256
        && revision_now.tree_sha256.as_ref() != Some(tree)
    {
        reasons.push("l'arbre de travail a changé".to_string());
    }
    if evaluation.platform != checks::platform() {
        reasons.push(format!("évaluation obtenue sous {}", evaluation.platform));
    }
    reasons
}

/// Differences between a rule file and what the journal recorded (empty: they agree).
fn mismatch(file: &RuleFile, journal: Option<&RuleState>) -> Vec<String> {
    match journal {
        None if file.rule.state == "candidate" => Vec::new(),
        None => vec![format!(
            "le fichier dit {} mais le journal ne connaît pas cette règle",
            file.rule.state
        )],
        Some(state) => {
            let mut out = Vec::new();
            if state.state != file.rule.state {
                out.push(format!(
                    "le fichier dit {}, le journal {}",
                    file.rule.state, state.state
                ));
            }
            if !state.file_sha256.is_empty() && state.file_sha256 != file.file_sha256 {
                out.push(
                    "le fichier a été modifié hors de l'outil depuis le dernier mouvement".into(),
                );
            }
            out
        }
    }
}

// ------------------------------------------------------------------ reports

fn render_active(rule: &Rule) -> Value {
    json!({
        "id": rule.id,
        "statement": rule.statement,
        "scope": rule.scope,
        "refuted_by": rule.refuted_by,
        "untrusted": true,
    })
}

/// Active rules (journal state active and file in agreement), as status and recall show
/// them: data for whoever reads, never enforced.
pub fn active_rules(memory: &Memory) -> Value {
    let Ok(allowed) = checks::load(memory.repo()) else {
        return json!([]);
    };
    let journal = states(&memory.events);
    json!(
        list_rules(memory.repo(), &allowed)
            .into_iter()
            .filter_map(|(id, file)| {
                let file = file.ok()?;
                let state = journal.get(&id)?;
                (state.state == "active" && mismatch(&file, Some(state)).is_empty())
                    .then(|| render_active(&file.rule))
            })
            .collect::<Vec<_>>()
    )
}

pub fn status_section(memory: &Memory) -> Value {
    let report = report(memory);
    json!({
        "active": active_rules(memory),
        "count": report["rules"].as_array().map_or(0, Vec::len),
        "mismatches": report["mismatches"],
        "note": "active signifie listée pour lecture ; aucune règle n'est appliquée automatiquement",
    })
}

/// `head rules`: every rule file and every rule the journal knows, with state,
/// disagreement with the journal and last evaluation.
pub fn report(memory: &Memory) -> Value {
    let repo = memory.repo();
    let journal = states(&memory.events);
    let allowed = checks::load(repo);
    let checks_now = checks::current_hash(repo);
    let mut revision_now: Option<Revision> = None;
    let mut rules = Vec::new();
    let mut mismatches = 0;
    let mut seen = std::collections::BTreeSet::new();
    let files = match &allowed {
        Ok(allowed) => list_rules(repo, allowed),
        Err(_) => Vec::new(),
    };
    for (id, loaded) in files {
        seen.insert(id.clone());
        let state = journal.get(&id);
        let mut entry = json!({"id": id, "journal_state": state.map(|s| s.state.clone())});
        match loaded {
            Err(e) => {
                entry["invalid"] = json!(e.to_string());
                mismatches += 1;
            }
            Ok(file) => {
                let differences = mismatch(&file, state);
                mismatches += usize::from(!differences.is_empty());
                entry["file_state"] = json!(file.rule.state);
                entry["mismatch"] = json!(differences);
                entry["statement"] = json!(file.rule.statement);
                entry["untrusted"] = json!(true);
                if let Some((event_id, content, evaluation)) =
                    state.and_then(|s| s.evaluation.as_ref())
                {
                    let now = revision_now.get_or_insert_with(|| checks::revision(repo));
                    let stale = evaluation_stale(
                        content,
                        evaluation,
                        &file.content_sha256,
                        checks_now.as_deref(),
                        now,
                    );
                    entry["last_evaluation"] = json!({
                        "event_id": event_id,
                        "passed": evaluation.passed,
                        "stale": stale,
                    });
                }
            }
        }
        rules.push(entry);
    }
    for (id, state) in &journal {
        if !seen.contains(id) {
            mismatches += 1;
            rules.push(json!({"id": id, "journal_state": state.state, "mismatch": ["fichier de règle absent"]}));
        }
    }
    json!({
        "rules": rules,
        "mismatches": mismatches,
        "checks_file": allowed.err().map(|e| e.to_string()),
    })
}

// ------------------------------------------------------------------ moves

fn rule_event(record: RuleRecord, summary: String) -> Event {
    Event {
        schema_version: Some(SCHEMA_VERSION),
        event_id: format!("rule-{}", hex::encode(rand::random::<[u8; 6]>())),
        task_id: format!("rule-{}", record.rule),
        kind: "rule".into(),
        summary,
        source_refs: Vec::new(),
        evidence_refs: Vec::new(),
        source_hashes: BTreeMap::new(),
        timestamp: Some(now()),
        supersedes: None,
        check: None,
        rule: Some(record),
    }
}

/// The rule file, checked against the journal before any move.
fn agreed(memory: &Memory, id: &str, allowed: &Checks) -> Result<(RuleFile, Option<RuleState>)> {
    let file = load_rule(memory.repo(), id, allowed)?;
    let journal = states(&memory.events).get(id).cloned();
    let differences = mismatch(&file, journal.as_ref());
    ensure!(
        differences.is_empty(),
        "règle {id} en désaccord avec le journal : {}",
        differences.join(" ; ")
    );
    Ok((file, journal))
}

/// Write the changed files, then the event; if the event cannot be written, the files
/// are put back as they were.
fn apply(memory: &mut Memory, files: &[(String, String, String)], event: Event) -> Result<Event> {
    // files: (rule id, new text, old text)
    let mut written = Vec::new();
    for (id, new_text, old_text) in files {
        if let Err(e) = write_rule(memory.repo(), id, new_text) {
            for (id, old) in written {
                let _ = write_rule(memory.repo(), id, old);
            }
            return Err(e);
        }
        written.push((id.as_str(), old_text.as_str()));
    }
    match memory
        .check_shape(&event)
        .and_then(|_| memory.check_context(&event))
    {
        Ok(()) => {}
        Err(e) => {
            for (id, old) in &written {
                let _ = write_rule(memory.repo(), id, old);
            }
            return Err(e);
        }
    }
    match memory.append(event) {
        Ok(event) => Ok(event),
        Err(e) => {
            for (id, old) in &written {
                let _ = write_rule(memory.repo(), id, old);
            }
            Err(e)
        }
    }
}

fn with_state(file: &RuleFile, state: &str) -> Result<(String, String)> {
    let mut rule = file.rule.clone();
    rule.state = state.into();
    let text = canonical_text(&rule)?;
    let digest = checks::sha256_hex(text.as_bytes());
    Ok((text, digest))
}

/// `head evaluate <rule>`: run the rule's refuting checks (the allow-list's commands,
/// isolation and timeouts) and record the measures. A passing evaluation moves a
/// candidate to evaluated; a failing one is recorded and moves nothing.
pub fn evaluate(memory_dir: &Path, repo: &Path, id: &str) -> Result<Value> {
    let repo = repo.canonicalize()?;
    let allowed = checks::load(&repo)?;
    let (before, journal_before) = {
        let memory = Memory::open(memory_dir, &repo)?;
        let (file, journal) = agreed(&memory, id, &allowed)?;
        if let Some(state) = &journal {
            ensure!(
                matches!(state.state.as_str(), "candidate" | "evaluated"),
                "règle {id} : seule une règle candidate ou évaluée s'évalue (état {})",
                state.state
            );
        }
        (file, journal.map(|s| s.state))
    };
    let mut measures = Vec::new();
    let mut tails = BTreeMap::new();
    let revision = checks::revision(&repo);
    for name in &before.rule.refuted_by {
        let (result, tail) = checks::run_with_tail(&repo, &allowed, name)?;
        if !result.passed {
            tails.insert(name.clone(), tail); // shown to the person, never journaled
        }
        measures.push(Measure {
            name: result.name,
            passed: result.passed,
            exit_code: result.exit_code,
            timed_out: result.timed_out,
            duration_ms: result.duration_ms,
            output_sha256: result.output_sha256,
        });
    }
    let passed = measures.iter().all(|m| m.passed);
    let mut memory = Memory::open(memory_dir, &repo)?;
    let (file, journal) = agreed(&memory, id, &allowed)?;
    ensure!(
        file.file_sha256 == before.file_sha256
            && journal.as_ref().map(|s| &s.state) == journal_before.as_ref(),
        "règle {id} modifiée pendant l'évaluation : rien n'est enregistré"
    );
    if journal.is_none() {
        let record = RuleRecord {
            action: "registered".into(),
            rule: id.into(),
            content_sha256: file.content_sha256.clone(),
            changes: vec![RuleChange {
                rule: id.into(),
                state_before: None,
                state_after: "candidate".into(),
                file_sha256_before: file.file_sha256.clone(),
                file_sha256_after: file.file_sha256.clone(),
                before_text: None,
            }],
            evaluation: None,
            undoes: None,
        };
        apply(
            &mut memory,
            &[],
            rule_event(record, format!("Règle {id} : enregistrée (candidate)")),
        )?;
    }
    let evaluation = Evaluation {
        passed,
        checks: measures,
        checks_sha256: allowed.sha256.clone(),
        revision,
        platform: checks::platform().into(),
    };
    let mut files = Vec::new();
    let mut changes = Vec::new();
    if passed && file.rule.state == "candidate" {
        let (text, digest) = with_state(&file, "evaluated")?;
        changes.push(RuleChange {
            rule: id.into(),
            state_before: Some("candidate".into()),
            state_after: "evaluated".into(),
            file_sha256_before: file.file_sha256.clone(),
            file_sha256_after: digest,
            before_text: Some(file.text.clone()),
        });
        files.push((id.to_string(), text, file.text.clone()));
    }
    let summary = format!(
        "Règle {id} : évaluation {} ({} contrôle(s))",
        if passed { "réussie" } else { "échouée" },
        evaluation.checks.len()
    );
    let record = RuleRecord {
        action: "evaluated".into(),
        rule: id.into(),
        content_sha256: file.content_sha256.clone(),
        changes,
        evaluation: Some(evaluation),
        undoes: None,
    };
    let event = apply(&mut memory, &files, rule_event(record, summary))?;
    Ok(
        json!({"event_id": event.event_id, "rule": id, "passed": passed, "evaluation": event.rule.as_ref().and_then(|r| r.evaluation.clone()), "state": states(&memory.events).get(id).map(|s| s.state.clone()), "output_tail": tails}),
    )
}

/// `head promote <rule>`: needs a current, passing evaluation of this exact rule. The
/// rule it replaces, if active, is retired in the same move. The journal lock is held
/// throughout, so two promotions cannot both succeed.
pub fn promote(memory_dir: &Path, repo: &Path, id: &str) -> Result<Value> {
    let repo = repo.canonicalize()?;
    let allowed = checks::load(&repo)?;
    let mut memory = Memory::open(memory_dir, &repo)?;
    let (file, journal) = agreed(&memory, id, &allowed)?;
    let journal = journal.ok_or_else(|| anyhow!("règle {id} jamais évaluée"))?;
    ensure!(
        journal.state == "evaluated",
        "règle {id} : seule une règle évaluée se promeut (état {})",
        journal.state
    );
    let (_, content, evaluation) = journal
        .evaluation
        .as_ref()
        .ok_or_else(|| anyhow!("règle {id} : aucune évaluation"))?;
    ensure!(
        evaluation.passed,
        "règle {id} : la dernière évaluation a échoué"
    );
    let stale = evaluation_stale(
        content,
        evaluation,
        &file.content_sha256,
        checks::current_hash(&repo).as_deref(),
        &checks::revision(&repo),
    );
    ensure!(
        stale.is_empty(),
        "règle {id} : évaluation périmée ({})",
        stale.join(", ")
    );
    let (text, digest) = with_state(&file, "active")?;
    let mut changes = vec![RuleChange {
        rule: id.into(),
        state_before: Some("evaluated".into()),
        state_after: "active".into(),
        file_sha256_before: file.file_sha256.clone(),
        file_sha256_after: digest,
        before_text: Some(file.text.clone()),
    }];
    let mut files = vec![(id.to_string(), text, file.text.clone())];
    if let Some(other) = &file.rule.replaces {
        let replaced_state = states(&memory.events).get(other).map(|s| s.state.clone());
        if replaced_state.as_deref() == Some("active") {
            let (replaced, _) = agreed(&memory, other, &allowed)?;
            let (text, digest) = with_state(&replaced, "retired")?;
            changes.push(RuleChange {
                rule: other.clone(),
                state_before: Some("active".into()),
                state_after: "retired".into(),
                file_sha256_before: replaced.file_sha256.clone(),
                file_sha256_after: digest,
                before_text: Some(replaced.text.clone()),
            });
            files.push((other.clone(), text, replaced.text.clone()));
        }
    }
    let record = RuleRecord {
        action: "promoted".into(),
        rule: id.into(),
        content_sha256: file.content_sha256.clone(),
        changes,
        evaluation: None,
        undoes: None,
    };
    let event = apply(
        &mut memory,
        &files,
        rule_event(record, format!("Règle {id} : promue (active)")),
    )?;
    Ok(
        json!({"event_id": event.event_id, "rule": id, "state": "active", "changes": event.rule.as_ref().map(|r| r.changes.iter().map(|c| json!({"rule": c.rule, "from": c.state_before, "to": c.state_after})).collect::<Vec<_>>())}),
    )
}

/// `head rollback <rule>`: undo the rule's last promotion, putting back every file it
/// changed exactly as it was, provided nobody changed them since.
pub fn rollback(memory_dir: &Path, repo: &Path, id: &str) -> Result<Value> {
    let repo = repo.canonicalize()?;
    let allowed = checks::load(&repo)?;
    let mut memory = Memory::open(memory_dir, &repo)?;
    let (file, journal) = agreed(&memory, id, &allowed)?;
    let journal = journal.ok_or_else(|| anyhow!("règle {id} inconnue du journal"))?;
    ensure!(
        journal.state == "active",
        "règle {id} : seule une règle active se retire en arrière"
    );
    let promotion_id = journal
        .promotions
        .last()
        .cloned()
        .ok_or_else(|| anyhow!("règle {id} : aucune promotion à annuler"))?;
    let promotion = memory
        .events
        .iter()
        .find(|e| e.event_id == promotion_id)
        .and_then(|e| e.rule.clone())
        .ok_or_else(|| anyhow!("promotion introuvable"))?;
    let mut files = Vec::new();
    let mut changes = Vec::new();
    for change in &promotion.changes {
        let current = load_rule(&repo, &change.rule, &allowed)?;
        ensure!(
            current.file_sha256 == change.file_sha256_after,
            "règle {} modifiée depuis la promotion : retour refusé",
            change.rule
        );
        let previous = change
            .before_text
            .clone()
            .ok_or_else(|| anyhow!("promotion sans texte d'origine"))?;
        // The exact bytes the promotion replaced, not a rewritten form.
        let restored = previous;
        ensure!(
            checks::sha256_hex(restored.as_bytes()) == change.file_sha256_before,
            "promotion : texte d'origine incohérent avec son empreinte"
        );
        changes.push(RuleChange {
            rule: change.rule.clone(),
            state_before: Some(change.state_after.clone()),
            state_after: change.state_before.clone().unwrap_or_default(),
            file_sha256_before: current.file_sha256.clone(),
            file_sha256_after: checks::sha256_hex(restored.as_bytes()),
            before_text: Some(current.text.clone()),
        });
        files.push((change.rule.clone(), restored, current.text.clone()));
    }
    let record = RuleRecord {
        action: "rolled-back".into(),
        rule: id.into(),
        content_sha256: file.content_sha256.clone(),
        changes,
        evaluation: None,
        undoes: Some(promotion_id),
    };
    let event = apply(
        &mut memory,
        &files,
        rule_event(record, format!("Règle {id} : promotion annulée")),
    )?;
    Ok(
        json!({"event_id": event.event_id, "rule": id, "state": "evaluated", "undoes": event.rule.as_ref().and_then(|r| r.undoes.clone())}),
    )
}

/// `head retire <rule>`: candidate, evaluated or active to retired.
pub fn retire(memory_dir: &Path, repo: &Path, id: &str) -> Result<Value> {
    let repo = repo.canonicalize()?;
    let allowed = checks::load(&repo)?;
    let mut memory = Memory::open(memory_dir, &repo)?;
    let (file, journal) = agreed(&memory, id, &allowed)?;
    let journal =
        journal.ok_or_else(|| anyhow!("règle {id} inconnue du journal : l'évaluer d'abord"))?;
    ensure!(journal.state != "retired", "règle {id} déjà retirée");
    let (text, digest) = with_state(&file, "retired")?;
    let record = RuleRecord {
        action: "retired".into(),
        rule: id.into(),
        content_sha256: file.content_sha256.clone(),
        changes: vec![RuleChange {
            rule: id.into(),
            state_before: Some(journal.state.clone()),
            state_after: "retired".into(),
            file_sha256_before: file.file_sha256.clone(),
            file_sha256_after: digest,
            before_text: Some(file.text.clone()),
        }],
        evaluation: None,
        undoes: None,
    };
    let event = apply(
        &mut memory,
        &[(id.to_string(), text, file.text.clone())],
        rule_event(record, format!("Règle {id} : retirée")),
    )?;
    Ok(json!({"event_id": event.event_id, "rule": id, "state": "retired"}))
}

/// `head compare <a> <b>`: the two rules' last evaluations and context cost side by
/// side. It reports; it decides nothing and promotes nothing.
pub fn compare(memory_dir: &Path, repo: &Path, a: &str, b: &str) -> Result<Value> {
    let repo = repo.canonicalize()?;
    let allowed = checks::load(&repo)?;
    let memory = Memory::open(memory_dir, &repo)?;
    let journal = states(&memory.events);
    let checks_now = checks::current_hash(&repo);
    let revision_now = checks::revision(&repo);
    let side = |id: &str| -> Result<Value> {
        let file = load_rule(&repo, id, &allowed)?;
        let state = journal.get(id);
        let context_bytes = serde_json::to_vec(&render_active(&file.rule))?.len();
        let measures = state.and_then(|s| s.evaluation.as_ref()).map(|(event_id, content, evaluation)| {
            json!({
                "event_id": event_id,
                "checks": evaluation.checks.len(),
                "passed": evaluation.checks.iter().filter(|m| m.passed).count(),
                "failures": evaluation.checks.iter().filter(|m| !m.passed).count(),
                "duration_ms": evaluation.checks.iter().map(|m| m.duration_ms).sum::<u64>(),
                "stale": evaluation_stale(content, evaluation, &file.content_sha256, checks_now.as_deref(), &revision_now),
            })
        });
        Ok(json!({
            "id": id,
            "state": state.map(|s| s.state.clone()),
            "replaces": file.rule.replaces,
            "evaluation": measures,
            "context_bytes": context_bytes,
        }))
    };
    Ok(json!({
        "a": side(a)?,
        "b": side(b)?,
        "decision": null,
        "note": "comparaison seulement : rien n'est promu ni retiré ; context_bytes = octets ajoutés à status et recall si la règle est active",
    }))
}
