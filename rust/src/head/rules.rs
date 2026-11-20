//! Rule life cycle: versioned rule files, measured against the allowed checks, promoted
//! and rolled back by explicit commands, every move recorded by the tool.
//!
//! A rule is a file `.agents/rules/<id>.json` of a trusted repository, read beneath the
//! repository's directory handle without following links: an identifier, a statement, a
//! scope and an origin (plain text), the names of the checks that can refute it (only
//! names that exist in the trusted allow-list), optionally the rule it would replace, and
//! its state. Any other field (a command, an argument, a path to run, an environment
//! variable, a permission) makes the file invalid. A rule's text is data: nothing in it is
//! executed or read as an instruction.
//!
//! A rule file enters the journal only through `head register` (as a candidate); a fresh
//! checkout therefore starts from candidates and fresh evaluations. States and the only
//! moves: candidate -> evaluated (a certifying evaluation), evaluated -> active (promote),
//! active -> evaluated (rollback, undoing the last promotion), and candidate, evaluated or
//! active -> retired. Each move is a journal event of kind "rule" written by the tool with
//! the digests of the files before and after; a promotion cites the evaluation it relies
//! on, and replay checks that this evaluation exists, precedes it, is the rule's latest
//! one, concerns the same content and passed. A move that changes files records its
//! intent first and is completed or undone at the next opening (see `recover`).
//!
//! "active" means listed as active, with the freshness of its evaluation: status and
//! recall return it so that whoever starts work can read it. Nothing consumes or enforces
//! a rule automatically.
use super::checks::{self, Checks, ExecInfo, Now, Revision};
use super::fsafe::{self, Dir};
use super::trust::Context;
use super::{Event, Memory, SCHEMA_VERSION, now};
use anyhow::{Context as _, Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub const RULES_DIR: &str = ".agents/rules";
pub const MAX_RULE_BYTES: u64 = 16 * 1024;
const MAX_RULES: usize = 200;
const STATES: [&str; 4] = ["candidate", "evaluated", "active", "retired"];
const TRANSACTION: &str = "rule-transaction.json";

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub problems: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Evaluation {
    pub passed: bool,
    pub checks: Vec<Measure>,
    pub checks_sha256: String,
    pub revision: Revision,
    pub platform: String,
    /// The one snapshot digest every refuting check ran on (absent: before snapshots).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree_sha256: Option<String>,
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
    /// For promoted: the evaluation event relied on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

fn valid_rule_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `.agents/rules`, opened beneath the repository without following any link.
fn rules_dir(ctx: &Context) -> Result<Dir> {
    ctx.agents_dir()?
        .sub("rules")
        .context("dossier des règles absent ou lié")
}

fn content_digest(rule: &Rule) -> Result<String> {
    let mut value = serde_json::to_value(rule)?;
    value
        .as_object_mut()
        .ok_or_else(|| anyhow!("règle"))?
        .remove("state");
    Ok(checks::sha256_hex(&serde_json::to_vec(&value)?))
}

fn parse_rule(id: &str, bytes: Vec<u8>, allowed: &Checks) -> Result<RuleFile> {
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
        allowed
            .get(name)
            .with_context(|| format!("règle {id} : contrôle absent de la liste autorisée"))?;
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
    Ok(RuleFile {
        file_sha256: checks::sha256_hex(text.as_bytes()),
        content_sha256: content_digest(&rule)?,
        rule,
        text,
    })
}

/// Read and validate one rule file. Refused: a link anywhere on the way, a non-regular
/// file, over 16 Kio, an unknown field, a check absent from the allow-list, an id that is
/// not the file name.
pub fn load_rule(ctx: &Context, id: &str, allowed: &Checks) -> Result<RuleFile> {
    ensure!(valid_rule_id(id), "identifiant de règle invalide : {id}");
    let bytes = rules_dir(ctx)?
        .read(&format!("{id}.json"), MAX_RULE_BYTES)
        .with_context(|| format!("règle {id} illisible"))?;
    parse_rule(id, bytes, allowed)
}

/// Every *.json of the rules directory, each loaded on its own: an invalid file is
/// reported and does not hide the others.
pub fn list_rules(ctx: &Context, allowed: &Checks) -> Vec<(String, Result<RuleFile>)> {
    let Ok(dir) = rules_dir(ctx) else {
        return Vec::new();
    };
    let names = dir.list().unwrap_or_default();
    names
        .into_iter()
        .filter(|n| n.ends_with(".json") && !n.starts_with('.'))
        .take(MAX_RULES)
        .map(|name| {
            let id = name.trim_end_matches(".json").to_string();
            let loaded = if valid_rule_id(&id) {
                dir.read(&name, MAX_RULE_BYTES)
                    .and_then(|b| parse_rule(&id, b, allowed))
            } else {
                Err(anyhow!("identifiant de règle invalide : {id}"))
            };
            (id, loaded)
        })
        .collect()
}

/// The tool's form of a rule file: sorted keys, two-space indent, final newline.
fn canonical_text(rule: &Rule) -> Result<String> {
    let value = serde_json::to_value(rule)?;
    Ok(serde_json::to_string_pretty(&value)? + "\n")
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

/// A rule event must follow from the journal before it (replay and append alike),
/// including the evidence it cites.
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
        "registered" | "retired" => {
            ensure!(
                !record.changes.is_empty(),
                "règle : mouvement sans changement"
            )
        }
        "evaluated" => {
            ensure!(record.evaluation.is_some(), "évaluation absente");
            ensure!(
                current
                    .get(&record.rule)
                    .is_some_and(|s| !s.state.is_empty()),
                "évaluation d'une règle non enregistrée"
            );
            if !record.changes.is_empty() {
                let evaluation = record.evaluation.as_ref().unwrap();
                ensure!(
                    evaluation.passed && evaluation.tree_sha256.is_some(),
                    "seule une évaluation réussie, sur un instantané, rend une règle evaluated"
                );
            }
        }
        "promoted" => {
            ensure!(
                !record.changes.is_empty(),
                "règle : mouvement sans changement"
            );
            let cited = record
                .evidence
                .as_deref()
                .ok_or_else(|| anyhow!("promotion sans évaluation citée"))?;
            let latest = current
                .get(&record.rule)
                .and_then(|s| s.evaluation.as_ref());
            let Some((latest_id, content, evaluation)) = latest else {
                bail!("promotion sans évaluation antérieure");
            };
            ensure!(
                latest_id == cited,
                "promotion : l'évaluation citée n'est pas la dernière de cette règle"
            );
            ensure!(
                content == &record.content_sha256
                    && evaluation.passed
                    && evaluation.tree_sha256.is_some(),
                "promotion : l'évaluation citée ne porte pas sur ce contenu ou n'a pas réussi"
            );
        }
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

// ------------------------------------------------------------------ freshness

/// Why an evaluation does not certify the rule as it is now (empty: it does).
fn evaluation_reasons(
    content_evaluated: &str,
    evaluation: &Evaluation,
    content_now: &str,
    now: &mut Now,
) -> Vec<String> {
    let mut reasons = Vec::new();
    let Some(tree) = &evaluation.tree_sha256 else {
        return vec!["évaluation d'avant les instantanés : réévaluer".into()];
    };
    if !evaluation.passed {
        reasons.push("l'évaluation n'a pas réussi".into());
    }
    if content_evaluated != content_now {
        reasons.push("la règle a changé depuis l'évaluation".into());
    }
    if evaluation.platform != checks::platform() {
        reasons.push(format!("évaluation obtenue sous {}", evaluation.platform));
    }
    match now.checks_sha256() {
        Some(h) if h == evaluation.checks_sha256 => {}
        _ => reasons.push("la liste des contrôles a changé depuis l'évaluation".into()),
    }
    for measure in &evaluation.checks {
        match (&measure.exec, now.exec(&measure.name)) {
            (Some(recorded), Ok(current)) if *recorded == current => {}
            _ => reasons.push(format!(
                "programme ou configuration de {} changés",
                measure.name
            )),
        }
    }
    match now.tree() {
        Ok(current) if &current == tree => {}
        Ok(_) => reasons.push("l'arbre de travail diffère de l'instantané évalué".into()),
        Err(e) => reasons.push(format!("empreinte de l'arbre de travail impossible : {e}")),
    }
    reasons
}

/// Differences between a rule file and what the journal recorded (empty: they agree).
fn mismatch(file: &RuleFile, journal: Option<&RuleState>) -> Vec<String> {
    match journal {
        None => vec![format!(
            "règle absente du journal (fichier : {}) : « empreinte head register {} »",
            file.rule.state, file.rule.id
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

fn render_active(rule: &Rule, evaluation: Value) -> Value {
    json!({
        "id": rule.id,
        "statement": rule.statement,
        "scope": rule.scope,
        "refuted_by": rule.refuted_by,
        "evaluation": evaluation,
        "untrusted": true,
    })
}

/// Active rules (journal state active, file in agreement), with the freshness of their
/// evaluation: data for whoever reads, never enforced.
pub fn active_rules(memory: &Memory, now: &mut Now) -> Value {
    let ctx = memory.context();
    let Ok(allowed) = checks::load(ctx) else {
        return json!([]);
    };
    let journal = states(&memory.events);
    let mut out = Vec::new();
    for (id, file) in list_rules(ctx, &allowed) {
        let (Ok(file), Some(state)) = (file, journal.get(&id)) else {
            continue;
        };
        if state.state != "active" || !mismatch(&file, Some(state)).is_empty() {
            continue;
        }
        let freshness = match &state.evaluation {
            Some((event_id, content, evaluation)) => {
                let reasons = evaluation_reasons(content, evaluation, &file.content_sha256, now);
                json!({"event_id": event_id, "state": if reasons.is_empty() { "current" } else { "stale" }, "reasons": reasons})
            }
            None => json!({"state": "stale", "reasons": ["aucune évaluation"]}),
        };
        let mut rendered = render_active(&file.rule, freshness.clone());
        rendered["state"] = json!(if freshness["state"] == "current" {
            "active"
        } else {
            "active-stale"
        });
        out.push(rendered);
    }
    json!(out)
}

pub fn status_section(memory: &Memory, now: &mut Now) -> Value {
    let report = report_with(memory, now);
    json!({
        "active": active_rules(memory, now),
        "count": report["rules"].as_array().map_or(0, Vec::len),
        "mismatches": report["mismatches"],
        "note": "active signifie listée pour lecture ; aucune règle n'est appliquée automatiquement",
    })
}

/// `head rules`: every rule file and every rule the journal knows, with state,
/// disagreement with the journal and last evaluation.
pub fn report(memory: &Memory) -> Value {
    let mut now = Now::new(memory.context());
    report_with(memory, &mut now)
}

fn report_with(memory: &Memory, now: &mut Now) -> Value {
    let ctx = memory.context();
    let journal = states(&memory.events);
    let allowed = checks::load(ctx);
    let mut rules = Vec::new();
    let mut mismatches = 0;
    let mut seen = std::collections::BTreeSet::new();
    let files = match &allowed {
        Ok(allowed) => list_rules(ctx, allowed),
        Err(_) => Vec::new(),
    };
    for (id, loaded) in files {
        seen.insert(id.clone());
        let state = journal.get(&id);
        let mut entry = json!({"id": id, "journal_state": state.map(|s| s.state.clone())});
        match loaded {
            Err(e) => {
                entry["invalid"] = json!(format!("{e:#}"));
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
                    let reasons =
                        evaluation_reasons(content, evaluation, &file.content_sha256, now);
                    entry["last_evaluation"] = json!({
                        "event_id": event_id,
                        "passed": evaluation.passed,
                        "state": if reasons.is_empty() { "current" } else { "stale" },
                        "stale": reasons,
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
        "checks_file": allowed.err().map(|e| format!("{e:#}")),
    })
}

// ------------------------------------------------------------------ transactions

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileWrite {
    rule: String,
    before_text: String,
    after_text: String,
    before_sha256: String,
    after_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Transaction {
    event: Event,
    files: Vec<FileWrite>,
}

fn write_intent(root: &Path, transaction: &Transaction) -> Result<()> {
    let temporary = root.join(format!(".{TRANSACTION}.tmp"));
    {
        use std::io::Write;
        let mut file = fs::File::create(&temporary)?;
        file.write_all(&serde_json::to_vec(transaction)?)?;
        file.sync_all()?;
    }
    fs::rename(&temporary, root.join(TRANSACTION))?;
    fsafe::sync_dir(root)
}

fn clear_intent(root: &Path) -> Result<()> {
    fs::remove_file(root.join(TRANSACTION))?;
    fsafe::sync_dir(root)
}

fn file_sha(dir: &Dir, rule: &str) -> Option<String> {
    dir.read_opt(&format!("{rule}.json"), MAX_RULE_BYTES)
        .ok()
        .flatten()
        .map(|b| checks::sha256_hex(&b))
}

/// At opening: a rule move whose intent was recorded but which did not finish is
/// completed (files written, event missing: the event is appended) or undone (files put
/// back). If the files match neither state, writes are refused until a person decides.
pub(super) fn recover(memory: &mut Memory) -> Result<()> {
    let path = memory.root.join(TRANSACTION);
    if fs::symlink_metadata(&path).is_err() {
        return Ok(());
    }
    let parsed: Result<Transaction> = fs::read(&path)
        .map_err(Into::into)
        .and_then(|b| serde_json::from_slice(&b).map_err(Into::into));
    let Ok(transaction) = parsed else {
        memory.unresolved = Some(format!("intention illisible : {}", path.display()));
        return Ok(());
    };
    if memory
        .events
        .iter()
        .any(|e| e.event_id == transaction.event.event_id)
    {
        return clear_intent(&memory.root);
    }
    let dir = match rules_dir(memory.context()) {
        Ok(d) => d,
        Err(e) => {
            memory.unresolved = Some(format!("dossier des règles illisible : {e:#}"));
            return Ok(());
        }
    };
    let current: Vec<Option<String>> = transaction
        .files
        .iter()
        .map(|f| file_sha(&dir, &f.rule))
        .collect();
    let all_after = transaction
        .files
        .iter()
        .zip(&current)
        .all(|(f, c)| c.as_deref() == Some(f.after_sha256.as_str()));
    if all_after {
        let event = transaction.event.clone();
        if memory
            .check_shape(&event)
            .and_then(|_| memory.check_context(&event))
            .is_ok()
        {
            memory.append(event)?;
            return clear_intent(&memory.root);
        }
    }
    // Undo: a file the move wrote goes back to its text before the move. A file in any
    // other state was changed by someone else: it is left untouched.
    for (write, now) in transaction.files.iter().zip(&current) {
        if now.as_deref() == Some(write.after_sha256.as_str()) {
            dir.write_atomic(
                &format!("{}.json", write.rule),
                write.before_text.as_bytes(),
            )?;
        }
    }
    let restored = transaction
        .files
        .iter()
        .all(|f| file_sha(&dir, &f.rule).as_deref() == Some(f.before_sha256.as_str()));
    if restored {
        clear_intent(&memory.root)
    } else {
        memory.unresolved = Some(format!(
            "la transaction {} n'a pu être ni achevée ni annulée ; examiner {}",
            transaction.event.event_id,
            path.display()
        ));
        Ok(())
    }
}

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
    let file = load_rule(memory.context(), id, allowed)?;
    let journal = states(&memory.events).get(id).cloned();
    if journal.is_some() {
        let differences = mismatch(&file, journal.as_ref());
        ensure!(
            differences.is_empty(),
            "règle {id} en désaccord avec le journal : {}",
            differences.join(" ; ")
        );
    }
    Ok((file, journal))
}

/// A move as a transaction: intent recorded durably, files written, event appended,
/// intent removed. If something fails after the intent, the files are put back; if even
/// that fails, the intent stays and the next opening resolves it.
fn apply(memory: &mut Memory, files: Vec<FileWrite>, event: Event) -> Result<Event> {
    memory.seal_tail()?;
    memory.check_shape(&event)?;
    memory.check_context(&event)?;
    if files.is_empty() {
        return memory.append(event);
    }
    let transaction = Transaction {
        event: event.clone(),
        files,
    };
    write_intent(&memory.root, &transaction)?;
    let dir = rules_dir(memory.context())?;
    let mut outcome: Result<Event> = Ok(event.clone());
    for write in &transaction.files {
        if let Err(e) =
            dir.write_atomic(&format!("{}.json", write.rule), write.after_text.as_bytes())
        {
            outcome = Err(e);
            break;
        }
    }
    if outcome.is_ok() {
        outcome = memory.append(event);
    }
    match outcome {
        Ok(event) => {
            clear_intent(&memory.root)?;
            Ok(event)
        }
        Err(e) => {
            let mut undone = true;
            for write in &transaction.files {
                undone &= dir
                    .write_atomic(
                        &format!("{}.json", write.rule),
                        write.before_text.as_bytes(),
                    )
                    .is_ok();
            }
            if undone {
                let _ = clear_intent(&memory.root);
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

fn change_to(file: &RuleFile, from: Option<&str>, to: &str) -> Result<(RuleChange, FileWrite)> {
    let (text, digest) = with_state(file, to)?;
    Ok((
        RuleChange {
            rule: file.rule.id.clone(),
            state_before: from.map(str::to_owned),
            state_after: to.into(),
            file_sha256_before: file.file_sha256.clone(),
            file_sha256_after: digest.clone(),
            before_text: Some(file.text.clone()),
        },
        FileWrite {
            rule: file.rule.id.clone(),
            before_text: file.text.clone(),
            after_text: text,
            before_sha256: file.file_sha256.clone(),
            after_sha256: digest,
        },
    ))
}

/// `head register <rule>`: a rule file of the repository enters the journal as a
/// candidate. Its file must say candidate: nothing shipped can claim an evaluation the
/// local journal cannot show.
pub fn register(memory_dir: &Path, ctx: &Context, id: &str) -> Result<Value> {
    let allowed = checks::load(ctx)?;
    let mut memory = Memory::open(memory_dir, ctx)?;
    let file = load_rule(ctx, id, &allowed)?;
    ensure!(
        !states(&memory.events).contains_key(id),
        "règle {id} déjà connue du journal"
    );
    // A file that claims more than this journal can show (evaluated, active or retired in
    // a fresh checkout) is put back to candidate in the same recorded move: the claim is
    // never believed, and the text before is kept in the event.
    let (change, files) = if file.rule.state == "candidate" {
        let change = RuleChange {
            rule: id.into(),
            state_before: None,
            state_after: "candidate".into(),
            file_sha256_before: file.file_sha256.clone(),
            file_sha256_after: file.file_sha256.clone(),
            before_text: None,
        };
        (change, Vec::new())
    } else {
        let (change, write) = change_to(&file, None, "candidate")?;
        (change, vec![write])
    };
    let reset = !files.is_empty();
    let record = RuleRecord {
        action: "registered".into(),
        rule: id.into(),
        content_sha256: file.content_sha256.clone(),
        changes: vec![change],
        evaluation: None,
        undoes: None,
        evidence: None,
    };
    let event = apply(
        &mut memory,
        files,
        rule_event(record, format!("Règle {id} : enregistrée (candidate)")),
    )?;
    Ok(json!({
        "event_id": event.event_id,
        "rule": id,
        "state": "candidate",
        "file_reset": if reset {
            json!(format!("le fichier disait {} : remis à candidate ; l'évaluer à nouveau", file.rule.state))
        } else {
            Value::Null
        },
    }))
}

/// `head evaluate <rule>`: run the rule's refuting checks (allow-list, containment,
/// snapshot, timeouts as for `head check`) and record the measures. A certifying
/// evaluation (every check passed, all on the same snapshot) moves a candidate to
/// evaluated; any other is recorded and moves nothing.
pub fn evaluate(memory_dir: &Path, ctx: &Context, id: &str) -> Result<Value> {
    let allowed = checks::load(ctx)?;
    let (before, journal_before) = {
        let memory = Memory::open(memory_dir, ctx)?;
        let (file, journal) = agreed(&memory, id, &allowed)?;
        let state = journal.as_ref().ok_or_else(|| {
            anyhow!("règle {id} absente du journal : « empreinte head register {id} » d'abord")
        })?;
        ensure!(
            matches!(state.state.as_str(), "candidate" | "evaluated"),
            "règle {id} : seule une règle candidate ou évaluée s'évalue (état {})",
            state.state
        );
        (file, state.state.clone())
    };
    let mut measures = Vec::new();
    let mut tails = BTreeMap::new();
    for name in &before.rule.refuted_by {
        let (result, tail) = checks::run_with_tail(ctx, &allowed, name)?;
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
            outcome: result.outcome,
            snapshot_sha256: result.snapshot_sha256,
            exec: result.exec,
            problems: result.problems,
        });
    }
    let snapshots: std::collections::BTreeSet<_> =
        measures.iter().map(|m| m.snapshot_sha256.clone()).collect();
    let tree = match (snapshots.len(), snapshots.iter().next()) {
        (1, Some(Some(digest))) => Some(digest.clone()),
        _ => None,
    };
    let passed = tree.is_some() && measures.iter().all(|m| m.passed);
    let mut memory = Memory::open(memory_dir, ctx)?;
    let (file, journal) = agreed(&memory, id, &allowed)?;
    ensure!(
        file.file_sha256 == before.file_sha256
            && journal.as_ref().map(|s| s.state.clone()) == Some(journal_before),
        "règle {id} modifiée pendant l'évaluation : rien n'est enregistré"
    );
    let evaluation = Evaluation {
        passed,
        checks: measures,
        checks_sha256: allowed.sha256.clone(),
        revision: Revision {
            head: None,
            dirty: None,
            tree_sha256: tree.clone(),
        },
        platform: checks::platform().into(),
        tree_sha256: tree,
    };
    let mut files = Vec::new();
    let mut changes = Vec::new();
    if passed && file.rule.state == "candidate" {
        let (change, write) = change_to(&file, Some("candidate"), "evaluated")?;
        changes.push(change);
        files.push(write);
    }
    let summary = format!(
        "Règle {id} : évaluation {} ({} contrôle(s))",
        if passed {
            "réussie"
        } else {
            "non certifiante"
        },
        evaluation.checks.len()
    );
    let record = RuleRecord {
        action: "evaluated".into(),
        rule: id.into(),
        content_sha256: file.content_sha256.clone(),
        changes,
        evaluation: Some(evaluation),
        undoes: None,
        evidence: None,
    };
    let event = apply(&mut memory, files, rule_event(record, summary))?;
    Ok(json!({
        "event_id": event.event_id,
        "rule": id,
        "passed": passed,
        "evaluation": event.rule.as_ref().and_then(|r| r.evaluation.clone()),
        "state": states(&memory.events).get(id).map(|s| s.state.clone()),
        "output_tail": tails,
    }))
}

/// `head promote <rule>`: needs the rule's latest evaluation to certify this exact
/// content and the working tree as it is now. The rule it replaces, if active, is retired
/// in the same move. The journal lock is held throughout, so two promotions cannot both
/// succeed.
pub fn promote(memory_dir: &Path, ctx: &Context, id: &str) -> Result<Value> {
    let allowed = checks::load(ctx)?;
    let mut memory = Memory::open(memory_dir, ctx)?;
    let (file, journal) = agreed(&memory, id, &allowed)?;
    let journal = journal.ok_or_else(|| anyhow!("règle {id} absente du journal"))?;
    ensure!(
        journal.state == "evaluated",
        "règle {id} : seule une règle évaluée se promeut (état {})",
        journal.state
    );
    let (evaluation_id, content, evaluation) = journal
        .evaluation
        .as_ref()
        .ok_or_else(|| anyhow!("règle {id} : aucune évaluation"))?;
    let reasons = evaluation_reasons(
        content,
        evaluation,
        &file.content_sha256,
        &mut Now::new(ctx),
    );
    ensure!(
        reasons.is_empty(),
        "règle {id} : la dernière évaluation ne certifie pas l'état actuel ({}) ; réévaluer",
        reasons.join(", ")
    );
    let (change, write) = change_to(&file, Some("evaluated"), "active")?;
    let mut changes = vec![change];
    let mut files = vec![write];
    if let Some(other) = &file.rule.replaces {
        let replaced_state = states(&memory.events).get(other).map(|s| s.state.clone());
        if replaced_state.as_deref() == Some("active") {
            let (replaced, _) = agreed(&memory, other, &allowed)?;
            let (change, write) = change_to(&replaced, Some("active"), "retired")?;
            changes.push(change);
            files.push(write);
        }
    }
    let record = RuleRecord {
        action: "promoted".into(),
        rule: id.into(),
        content_sha256: file.content_sha256.clone(),
        changes,
        evaluation: None,
        undoes: None,
        evidence: Some(evaluation_id.clone()),
    };
    let event = apply(
        &mut memory,
        files,
        rule_event(record, format!("Règle {id} : promue (active)")),
    )?;
    Ok(
        json!({"event_id": event.event_id, "rule": id, "state": "active", "evidence": evaluation_id,
        "changes": event.rule.as_ref().map(|r| r.changes.iter().map(|c| json!({"rule": c.rule, "from": c.state_before, "to": c.state_after})).collect::<Vec<_>>())}),
    )
}

/// `head rollback <rule>`: undo the rule's last promotion, putting back every file it
/// changed exactly as it was, provided nobody changed them since.
pub fn rollback(memory_dir: &Path, ctx: &Context, id: &str) -> Result<Value> {
    let allowed = checks::load(ctx)?;
    let mut memory = Memory::open(memory_dir, ctx)?;
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
        let current = load_rule(ctx, &change.rule, &allowed)?;
        ensure!(
            current.file_sha256 == change.file_sha256_after,
            "règle {} modifiée depuis la promotion : retour refusé",
            change.rule
        );
        let previous = change
            .before_text
            .clone()
            .ok_or_else(|| anyhow!("promotion sans texte d'origine"))?;
        ensure!(
            checks::sha256_hex(previous.as_bytes()) == change.file_sha256_before,
            "promotion : texte d'origine incohérent avec son empreinte"
        );
        changes.push(RuleChange {
            rule: change.rule.clone(),
            state_before: Some(change.state_after.clone()),
            state_after: change.state_before.clone().unwrap_or_default(),
            file_sha256_before: current.file_sha256.clone(),
            file_sha256_after: change.file_sha256_before.clone(),
            before_text: Some(current.text.clone()),
        });
        files.push(FileWrite {
            rule: change.rule.clone(),
            before_text: current.text.clone(),
            after_text: previous,
            before_sha256: current.file_sha256.clone(),
            after_sha256: change.file_sha256_before.clone(),
        });
    }
    let record = RuleRecord {
        action: "rolled-back".into(),
        rule: id.into(),
        content_sha256: file.content_sha256.clone(),
        changes,
        evaluation: None,
        undoes: Some(promotion_id),
        evidence: None,
    };
    let event = apply(
        &mut memory,
        files,
        rule_event(record, format!("Règle {id} : promotion annulée")),
    )?;
    Ok(
        json!({"event_id": event.event_id, "rule": id, "state": "evaluated", "undoes": event.rule.as_ref().and_then(|r| r.undoes.clone())}),
    )
}

/// `head retire <rule>`: candidate, evaluated or active to retired.
pub fn retire(memory_dir: &Path, ctx: &Context, id: &str) -> Result<Value> {
    let allowed = checks::load(ctx)?;
    let mut memory = Memory::open(memory_dir, ctx)?;
    let (file, journal) = agreed(&memory, id, &allowed)?;
    let journal =
        journal.ok_or_else(|| anyhow!("règle {id} inconnue du journal : l'enregistrer d'abord"))?;
    ensure!(journal.state != "retired", "règle {id} déjà retirée");
    let (change, write) = change_to(&file, Some(&journal.state), "retired")?;
    let record = RuleRecord {
        action: "retired".into(),
        rule: id.into(),
        content_sha256: file.content_sha256.clone(),
        changes: vec![change],
        evaluation: None,
        undoes: None,
        evidence: None,
    };
    let event = apply(
        &mut memory,
        vec![write],
        rule_event(record, format!("Règle {id} : retirée")),
    )?;
    Ok(json!({"event_id": event.event_id, "rule": id, "state": "retired"}))
}

/// `head compare <a> <b>`: the two rules' last evaluations and context cost side by
/// side. It reports; it decides nothing and promotes nothing.
pub fn compare(memory_dir: &Path, ctx: &Context, a: &str, b: &str) -> Result<Value> {
    let allowed = checks::load(ctx)?;
    let memory = Memory::open(memory_dir, ctx)?;
    let journal = states(&memory.events);
    let mut now = Now::new(ctx);
    let mut side = |id: &str| -> Result<Value> {
        let file = load_rule(ctx, id, &allowed)?;
        let state = journal.get(id);
        let context_bytes = serde_json::to_vec(&render_active(
            &file.rule,
            json!({"state": "current", "reasons": []}),
        ))?
        .len();
        let measures = match state.and_then(|s| s.evaluation.as_ref()) {
            Some((event_id, content, evaluation)) => Some(json!({
                "event_id": event_id,
                "checks": evaluation.checks.len(),
                "passed": evaluation.checks.iter().filter(|m| m.passed).count(),
                "failures": evaluation.checks.iter().filter(|m| !m.passed).count(),
                "duration_ms": evaluation.checks.iter().map(|m| m.duration_ms).sum::<u64>(),
                "stale": evaluation_reasons(content, evaluation, &file.content_sha256, &mut now),
            })),
            None => None,
        };
        Ok(json!({
            "id": id,
            "state": state.map(|s| s.state.clone()),
            "replaces": file.rule.replaces,
            "evaluation": measures,
            "context_bytes": context_bytes,
        }))
    };
    let first = side(a)?;
    let second = side(b)?;
    Ok(json!({
        "a": first,
        "b": second,
        "decision": null,
        "note": "comparaison seulement : rien n'est promu ni retiré ; context_bytes = octets ajoutés à status et recall si la règle est active",
    }))
}
