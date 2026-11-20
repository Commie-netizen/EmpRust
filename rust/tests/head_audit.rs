//! One test (or more) per finding of docs/reviews/2026-11-16-audit-tete-pensante.md.
//! Findings 1, 2, 3 and 5 were first shown failing on the former code by
//! tests/head_audit_before.rs (same scenarios, former API), since removed.
mod common;
use common::*;
use empreinte::head::rules::{self, evaluate, promote, register};
use empreinte::head::trust;
use empreinte::head::{Memory, checks, run_check};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

fn verify_with(r: &Repo, task: &str, check_event: &str, id: &str) -> anyhow::Result<()> {
    let mut m = Memory::open(&r.memory, &r.ctx)?;
    let mut verified = input(id, task, "verified");
    verified.evidence_refs.push(check_event.into());
    m.record(verified).map(|_| ())
}

fn event_id(report: &serde_json::Value) -> String {
    report["event"]["event_id"].as_str().unwrap().to_string()
}

fn unique(prefix: &str) -> String {
    format!("{prefix}{}", hex::encode(rand_bytes()))
}

fn rand_bytes() -> [u8; 4] {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    (nanos ^ std::process::id().rotate_left(7)).to_le_bytes()
}

// 1 ------------------------------------------------------------------ execution authority

#[test]
fn finding_1_programs_are_absolute_and_the_environment_is_fixed() {
    let out = tempfile::tempdir().unwrap();
    let env_file = out.path().join("env.txt");
    let script = format!(
        "/usr/bin/env > {}; cargo --version > /dev/null 2>&1; true",
        env_file.display()
    );
    let r = repo(&allow_list(&check(
        "env",
        &["/bin/sh", "-c", &script],
        60,
        "",
    )));
    running_task(&r, "t");
    let report = run_check(&r.memory, &r.ctx, "t", "env").unwrap();
    assert_eq!(report["event"]["check"]["outcome"], "passed", "{report}");
    let env = fs::read_to_string(&env_file).unwrap();
    let keys: Vec<&str> = env.lines().filter_map(|l| l.split('=').next()).collect();
    for key in &keys {
        assert!(
            [
                "PATH",
                "HOME",
                "CARGO_HOME",
                "RUSTUP_HOME",
                "LANG",
                "PYTHONDONTWRITEBYTECODE",
                "PWD",
                "SHLVL",
                "_"
            ]
            .contains(key),
            "inherited variable {key} reached the check"
        );
    }
    assert!(
        env.contains("PATH=/usr/local/bin:/usr/bin:/bin\n"),
        "PATH is the fixed one, never the caller's"
    );
    assert!(
        !env.contains("CARGO_MANIFEST_DIR"),
        "nothing of the caller's environment"
    );
}

#[test]
fn finding_1_a_changed_program_makes_the_result_stale() {
    let bin = tempfile::tempdir().unwrap();
    let program = bin.path().join("checker.sh");
    fs::write(&program, "#!/bin/sh\nexit 0\n").unwrap();
    std::process::Command::new("/bin/chmod")
        .arg("+x")
        .arg(&program)
        .status()
        .unwrap();
    let r = repo(&allow_list(&check(
        "prog",
        &[program.to_str().unwrap()],
        30,
        "",
    )));
    running_task(&r, "t");
    let report = run_check(&r.memory, &r.ctx, "t", "prog").unwrap();
    assert_eq!(report["event"]["check"]["outcome"], "passed", "{report}");
    let recorded = &report["event"]["check"];
    assert!(recorded.to_string().contains("passed"));
    verify_with(&r, "t", &event_id(&report), "v").unwrap();
    fs::write(&program, "#!/bin/sh\necho autre\nexit 0\n").unwrap(); // same path, other content
    let status = Memory::open(&r.memory, &r.ctx).unwrap().status();
    assert_eq!(status["tasks"]["t"]["state"], "verified-stale");
    assert!(
        status["tasks"]["t"]["stale"]
            .to_string()
            .contains("programme"),
        "{status}"
    );
}

// 2 ------------------------------------------------------------------ git helpers

#[test]
fn finding_2_configured_git_helpers_are_never_executed() {
    let r = repo(&ok_ko());
    let marker = r.root.join("helper-ran");
    let helper = r.root.join("helper.sh");
    fs::write(
        &helper,
        format!(
            "#!/bin/sh\ntouch {}\ncat \"$1\" 2>/dev/null\n",
            marker.display()
        ),
    )
    .unwrap();
    std::process::Command::new("/bin/chmod")
        .arg("+x")
        .arg(&helper)
        .status()
        .unwrap();
    fs::write(
        r.root.join(".gitattributes"),
        "*.txt diff=probe filter=probe\n",
    )
    .unwrap();
    fs::write(r.root.join("a.txt"), "v1").unwrap();
    assert!(
        git(&r.root, &["add", "a.txt", ".gitattributes"])
            && git(&r.root, &["commit", "-q", "-m", "v1"])
    );
    for (key, value) in [
        ("diff.probe.textconv", helper.to_str().unwrap()),
        ("diff.external", helper.to_str().unwrap()),
        ("filter.probe.clean", helper.to_str().unwrap()),
        ("core.fsmonitor", helper.to_str().unwrap()),
        ("core.pager", helper.to_str().unwrap()),
    ] {
        assert!(git(&r.root, &["config", key, value]));
    }
    fs::write(r.root.join("a.txt"), "v2").unwrap();
    running_task(&r, "t");
    let report = run_check(&r.memory, &r.ctx, "t", "ok").unwrap();
    let _ = Memory::open(&r.memory, &r.ctx).unwrap().status();
    let _ = verify_with(&r, "t", &event_id(&report), "v");
    let _ = Memory::open(&r.memory, &r.ctx)
        .unwrap()
        .recall("Rust", 12000);
    assert!(!marker.exists(), "a configured git helper ran");
}

// 3 ------------------------------------------------------------------ trust

#[test]
fn finding_3_only_an_explicitly_trusted_root_is_used() {
    let r = repo(&ok_ko());
    let sub = r.root.join("vendor/evil");
    fs::create_dir_all(sub.join(".git")).unwrap();
    let marker = r.root.join("hostile-ran");
    fs::create_dir_all(sub.join(".agents")).unwrap();
    fs::write(
        sub.join(checks::CHECKS_FILE),
        allow_list(&check(
            "ok",
            &["/bin/sh", "-c", &format!("touch {}", marker.display())],
            30,
            "",
        )),
    )
    .unwrap();
    // From the subdirectory, the nearest trusted ancestor is the outer repository.
    let ctx = trust::resolve(&r.settings, None, &sub).unwrap();
    assert_eq!(ctx.root, r.root);
    let _ = run_check(&r.memory, &ctx, "t", "ok");
    running_task(&r, "t");
    run_check(&r.memory, &ctx, "t", "ok").unwrap();
    assert!(!marker.exists(), "the hostile allow-list was used");
    // The subdirectory itself is not trusted, marker or not.
    let error = trust::resolve(&r.settings, Some(&sub), &sub)
        .err()
        .expect("refused")
        .to_string();
    assert!(error.contains("head trust"), "{error}");
    // Nothing trusted at all: refused, with the way to trust.
    let elsewhere = tempfile::tempdir().unwrap();
    assert!(trust::resolve(&r.settings, None, elsewhere.path()).is_err());
    // trust without --confirm only shows.
    let shown = trust::trust(&r.settings, &sub, false).unwrap();
    assert_eq!(shown["trusted"], false);
    assert!(trust::resolve(&r.settings, Some(&sub), &sub).is_err());
}

#[test]
fn finding_3_links_in_agents_are_refused() {
    let r = repo(&ok_ko());
    let elsewhere = tempfile::tempdir().unwrap();
    fs::create_dir_all(elsewhere.path().join("rules")).unwrap();
    fs::write(elsewhere.path().join("checks.json"), ok_ko()).unwrap();
    // .agents/rules as a link: no rule is read through it.
    write_rule(&r, "inner", r#""ok""#, None);
    fs::rename(r.root.join(".agents/rules"), r.root.join("rules-real")).unwrap();
    std::os::unix::fs::symlink(r.root.join("rules-real"), r.root.join(".agents/rules")).unwrap();
    let allowed = checks::load(&r.ctx).unwrap();
    assert!(rules::list_rules(&r.ctx, &allowed).is_empty());
    assert!(rules::load_rule(&r.ctx, "inner", &allowed).is_err());
    // .agents itself as a link (to a copy with the same checks): refused.
    fs::rename(r.root.join(".agents"), r.root.join("agents-real")).unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), r.root.join(".agents")).unwrap();
    let error = checks::load(&r.ctx).err().expect("refused").to_string();
    assert!(error.contains("lien"), "{error}");
}

// 4 ------------------------------------------------------------------ fail closed

#[test]
fn finding_4_no_fingerprint_no_certification() {
    let body = format!(
        r#"{{"version":2,"git":{{"unix":"/nonexistent/git"}},"checks":{{{}}}}}"#,
        check("ok", &["/bin/true"], 30, "")
    );
    let r = repo(&body);
    running_task(&r, "t");
    let report = run_check(&r.memory, &r.ctx, "t", "ok").unwrap();
    assert_eq!(
        report["event"]["check"]["outcome"], "incomplete",
        "{report}"
    );
    assert!(verify_with(&r, "t", &event_id(&report), "v").is_err());
}

#[test]
fn finding_4_untracked_content_is_fingerprinted() {
    let r = repo(&ok_ko());
    fs::write(r.root.join("notes.txt"), "un").unwrap(); // untracked, not ignored
    running_task(&r, "t");
    let report = run_check(&r.memory, &r.ctx, "t", "ok").unwrap();
    verify_with(&r, "t", &event_id(&report), "v").unwrap();
    fs::write(r.root.join("notes.txt"), "deux").unwrap();
    let status = Memory::open(&r.memory, &r.ctx).unwrap().status();
    assert_eq!(status["tasks"]["t"]["state"], "verified-stale", "{status}");
}

// 5 ------------------------------------------------------------------ snapshots

#[test]
fn finding_5_a_tree_swapped_during_the_run_is_not_certified() {
    let body = allow_list(&check(
        "state",
        &["/bin/sh", "-c", "sleep 1; grep -q pass state.txt"],
        30,
        "",
    ));
    let r = repo(&body);
    fs::write(r.root.join("state.txt"), "fail").unwrap();
    assert!(git(&r.root, &["add", "state.txt"]) && git(&r.root, &["commit", "-q", "-m", "A"]));
    running_task(&r, "t");
    let editor = {
        let root = r.root.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            fs::write(root.join("state.txt"), "pass").unwrap(); // tree B during the run
        })
    };
    let report = run_check(&r.memory, &r.ctx, "t", "state").unwrap();
    editor.join().unwrap();
    fs::write(r.root.join("state.txt"), "fail").unwrap(); // back to A
    assert_eq!(
        report["event"]["check"]["outcome"], "failed",
        "the check saw the snapshot A"
    );
    assert!(verify_with(&r, "t", &event_id(&report), "v").is_err());
}

#[test]
fn finding_5_the_tree_must_match_the_snapshot_at_commitment() {
    let r = repo(&ok_ko());
    fs::write(r.root.join("code.txt"), "A").unwrap();
    running_task(&r, "t");
    let report = run_check(&r.memory, &r.ctx, "t", "ok").unwrap();
    assert_eq!(report["event"]["check"]["outcome"], "passed");
    fs::write(r.root.join("code.txt"), "B").unwrap();
    let error = verify_with(&r, "t", &event_id(&report), "v")
        .err()
        .expect("refused")
        .to_string();
    assert!(error.contains("instantané"), "{error}");
    fs::write(r.root.join("code.txt"), "A").unwrap();
    verify_with(&r, "t", &event_id(&report), "v").unwrap();
}

#[test]
fn finding_5_a_check_that_alters_its_snapshot_is_incomplete() {
    let body = allow_list(&check(
        "writer",
        &[
            "/bin/sh",
            "-c",
            "chmod u+w state.txt; echo pass > state.txt",
        ],
        30,
        "",
    ));
    let r = repo(&body);
    fs::write(r.root.join("state.txt"), "fail").unwrap();
    running_task(&r, "t");
    let report = run_check(&r.memory, &r.ctx, "t", "writer").unwrap();
    assert_eq!(
        report["event"]["check"]["outcome"], "incomplete",
        "{report}"
    );
    assert!(
        report["event"]["check"]["problems"]
            .to_string()
            .contains("instantané")
    );
    assert_eq!(
        fs::read_to_string(r.root.join("state.txt")).unwrap(),
        "fail",
        "the working tree is untouched"
    );
}

// 6 ------------------------------------------------------------------ containment

/// A sleeping script with a unique command name (its shell process carries that name).
fn copy_of_sleep(dir: &Path, name: &str) -> String {
    let path = dir.join(name);
    fs::write(&path, "#!/bin/sh\n/bin/sleep \"$1\"\n").unwrap();
    std::process::Command::new("/bin/chmod")
        .arg("+x")
        .arg(&path)
        .status()
        .unwrap();
    path.display().to_string()
}

fn wait_gone(comm: &str) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let found = processes_named(comm);
        if found.is_empty() || Instant::now() > deadline {
            return found;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn finding_6_a_setsid_descendant_does_not_survive() {
    let bin = tempfile::tempdir().unwrap();
    let comm = unique("zs");
    let sleeper = copy_of_sleep(bin.path(), &comm);
    let script = format!("setsid {sleeper} 300 < /dev/null > /dev/null 2>&1 & exit 0");
    let r = repo(&allow_list(&check(
        "escape",
        &["/bin/sh", "-c", &script],
        30,
        "",
    )));
    running_task(&r, "t");
    let report = run_check(&r.memory, &r.ctx, "t", "escape").unwrap();
    assert_eq!(
        report["event"]["check"]["isolation"]["cleanup_confirmed"], true,
        "{report}"
    );
    assert!(
        wait_gone(&comm).is_empty(),
        "a descendant survived, zombie or not"
    );
}

#[test]
fn finding_6_without_containment_the_same_descendant_survives() {
    // The control of the test above: the detector does see a survivor when nothing
    // contains the check, and such a run is never "passed".
    let bin = tempfile::tempdir().unwrap();
    let comm = unique("zu");
    let sleeper = copy_of_sleep(bin.path(), &comm);
    let script = format!("setsid {sleeper} 30 < /dev/null > /dev/null 2>&1 & exit 0");
    let r = repo(&allow_list(&check(
        "escape",
        &["/bin/sh", "-c", &script],
        30,
        r#","uncontained":true"#,
    )));
    running_task(&r, "t");
    let report = run_check(&r.memory, &r.ctx, "t", "escape").unwrap();
    assert_eq!(report["event"]["check"]["outcome"], "incomplete");
    std::thread::sleep(Duration::from_millis(300));
    let survivors = processes_named(&comm);
    for stat in &survivors {
        if let Some(pid) = stat
            .split_whitespace()
            .next()
            .and_then(|p| p.parse::<i32>().ok())
        {
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
    assert!(
        !survivors.is_empty(),
        "the detector saw nothing: the containment test proves nothing"
    );
}

#[test]
fn finding_6_the_timeout_kills_everything_and_leaves_no_zombie() {
    let bin = tempfile::tempdir().unwrap();
    let comm = unique("zt");
    let sleeper = copy_of_sleep(bin.path(), &comm);
    let script = format!("{sleeper} 300 & {sleeper} 300 & wait");
    let r = repo(&allow_list(&check(
        "hang",
        &["/bin/sh", "-c", &script],
        1,
        "",
    )));
    running_task(&r, "t");
    let started = Instant::now();
    let report = run_check(&r.memory, &r.ctx, "t", "hang").unwrap();
    assert!(started.elapsed() < Duration::from_secs(25));
    assert_eq!(report["event"]["check"]["timed_out"], true);
    assert_ne!(report["event"]["check"]["outcome"], "passed");
    assert!(
        wait_gone(&comm).is_empty(),
        "a process survived the timeout, zombie or not"
    );
}

#[test]
fn finding_6_output_beyond_its_bound_is_incomplete() {
    let r = repo(&allow_list(&check(
        "loud",
        &["/bin/sh", "-c", "head -c 5000 /dev/zero"],
        30,
        r#","max_output_bytes":1000"#,
    )));
    running_task(&r, "t");
    let report = run_check(&r.memory, &r.ctx, "t", "loud").unwrap();
    assert_eq!(
        report["event"]["check"]["outcome"], "incomplete",
        "{report}"
    );
}

// 7 ------------------------------------------------------------------ evidence on replay

#[test]
fn finding_7_promotion_relies_on_the_latest_evaluation_and_replay_checks_it() {
    let flag = tempfile::tempdir().unwrap();
    let pass = flag.path().join("pass");
    let body = allow_list(&check(
        "flaky",
        &["/usr/bin/test", "-f", pass.to_str().unwrap()],
        30,
        "",
    ));
    let r = repo(&body);
    new_rule(&r, "rule", r#""flaky""#, None);
    fs::write(&pass, b"").unwrap();
    let first = evaluate(&r.memory, &r.ctx, "rule").unwrap();
    assert_eq!(first["passed"], true);
    fs::remove_file(&pass).unwrap();
    let second = evaluate(&r.memory, &r.ctx, "rule").unwrap();
    assert_eq!(second["passed"], false);
    assert!(
        promote(&r.memory, &r.ctx, "rule").is_err(),
        "the latest evaluation failed"
    );
    // A forged promotion citing the earlier, passing evaluation is set aside on replay.
    let journal = r.memory.join(JOURNAL);
    let text = fs::read_to_string(&journal).unwrap();
    let content = rules::states(Memory::open(&r.memory, &r.ctx).unwrap().events())["rule"]
        .content_sha256
        .clone();
    let file_sha = hex::encode(Sha256::digest(
        fs::read(rules_dir(&r).join("rule.json")).unwrap(),
    ));
    let forged = serde_json::json!({
        "schema_version": 2, "event_id": "rule-forged", "task_id": "rule-rule", "kind": "rule",
        "summary": "forgée", "timestamp": "2026-11-20T00:00:00.000Z",
        "rule": {"action": "promoted", "rule": "rule", "content_sha256": content,
                 "changes": [{"rule": "rule", "state_before": "evaluated", "state_after": "active",
                              "file_sha256_before": file_sha, "file_sha256_after": file_sha}],
                 "evidence": first["event_id"]}
    });
    fs::write(&journal, format!("{text}{forged}\n")).unwrap();
    let m = Memory::open(&r.memory, &r.ctx).unwrap();
    assert_eq!(m.status()["set_aside"]["count"], 1);
    assert_eq!(rules::states(m.events())["rule"].state, "evaluated");
}

// 8 ------------------------------------------------------------------ transactions

fn sha(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

#[test]
fn finding_8_an_interrupted_rule_move_is_completed_or_undone_at_opening() {
    let r = repo(&ok_ko());
    new_rule(&r, "rule", r#""ok""#, None);
    evaluate(&r.memory, &r.ctx, "rule").unwrap();
    let path = rules_dir(&r).join("rule.json");
    let before = fs::read_to_string(&path).unwrap();
    let journal_before = fs::read_to_string(r.memory.join(JOURNAL)).unwrap();
    promote(&r.memory, &r.ctx, "rule").unwrap();
    let after = fs::read_to_string(&path).unwrap();
    let journal_after = fs::read_to_string(r.memory.join(JOURNAL)).unwrap();
    let event: serde_json::Value =
        serde_json::from_str(journal_after.lines().last().unwrap()).unwrap();
    let intent = serde_json::json!({"event": event, "files": [{"rule": "rule", "before_text": before,
        "after_text": after, "before_sha256": sha(&before), "after_sha256": sha(&after)}]});
    // Crash after the files, before the event: the move is completed.
    fs::write(r.memory.join(JOURNAL), &journal_before).unwrap();
    fs::write(r.memory.join("rule-transaction.json"), intent.to_string()).unwrap();
    assert_eq!(derived(&r)["rule"], "active");
    assert!(!r.memory.join("rule-transaction.json").exists());
    // Crash before the files: the move is undone (nothing recorded, files as before).
    fs::write(r.memory.join(JOURNAL), &journal_before).unwrap();
    fs::write(&path, &before).unwrap();
    fs::write(r.memory.join("rule-transaction.json"), intent.to_string()).unwrap();
    assert_eq!(derived(&r)["rule"], "evaluated");
    assert_eq!(fs::read_to_string(&path).unwrap(), before);
    // Files in a third state: writes are refused until a person decides.
    fs::write(&path, before.replace("Règle rule.", "Règle rule, autre.")).unwrap();
    fs::write(r.memory.join("rule-transaction.json"), intent.to_string()).unwrap();
    let mut m = Memory::open(&r.memory, &r.ctx).unwrap();
    assert!(!m.status()["unresolved_transaction"].is_null());
    assert!(m.record(input("x", "x", "proposed")).is_err());
}

// 10 ----------------------------------------------------------------- effective states

#[test]
fn finding_10_recall_and_active_listings_show_staleness() {
    let r = repo(&ok_ko());
    fs::write(r.root.join("code.txt"), "A").unwrap();
    running_task(&r, "t");
    let report = run_check(&r.memory, &r.ctx, "t", "ok").unwrap();
    verify_with(&r, "t", &event_id(&report), "v").unwrap();
    new_rule(&r, "rule", r#""ok""#, None);
    evaluate(&r.memory, &r.ctx, "rule").unwrap();
    promote(&r.memory, &r.ctx, "rule").unwrap();
    fs::write(r.root.join("code.txt"), "B").unwrap();
    let m = Memory::open(&r.memory, &r.ctx).unwrap();
    let recalled = m.recall("Rust", 12000);
    let verified = recalled["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "verified")
        .unwrap();
    assert_eq!(
        verified["effective"]["state"], "verified-stale",
        "{verified}"
    );
    let status = m.status();
    assert_eq!(status["rules"]["active"][0]["state"], "active-stale");
    assert_eq!(status["rules"]["active"][0]["evaluation"]["state"], "stale");
    assert_eq!(recalled["active_rules"][0]["state"], "active-stale");
}

// 11 ----------------------------------------------------------------- registration

#[test]
fn finding_11_a_rule_enters_the_journal_by_registration_then_fresh_evaluation() {
    let r = repo(&ok_ko());
    write_rule(&r, "fresh", r#""ok""#, None);
    let error = evaluate(&r.memory, &r.ctx, "fresh")
        .err()
        .expect("refused")
        .to_string();
    assert!(error.contains("register"), "{error}");
    register(&r.memory, &r.ctx, "fresh").unwrap();
    assert_eq!(
        evaluate(&r.memory, &r.ctx, "fresh").unwrap()["state"],
        "evaluated"
    );
    // A file that claims more than the local journal can show is put back to candidate.
    let claimed = fs::read_to_string(rules_dir(&r).join("fresh.json"))
        .unwrap()
        .replace("fresh", "claims");
    fs::write(rules_dir(&r).join("claims.json"), claimed).unwrap();
    let report = register(&r.memory, &r.ctx, "claims").unwrap();
    assert_eq!(report["state"], "candidate", "the claim is not believed");
    assert!(report["file_reset"].as_str().unwrap().contains("evaluated"));
    assert!(
        fs::read_to_string(rules_dir(&r).join("claims.json"))
            .unwrap()
            .contains("\"candidate\"")
    );
    assert_eq!(derived(&r)["claims"], "candidate");
}

// 12 ----------------------------------------------------------------- network

#[test]
fn finding_12_a_check_that_requires_isolation_has_no_network() {
    let Ok(listener) = std::net::TcpListener::bind("127.0.0.1:0") else {
        eprintln!("no loopback here (already isolated): skipped");
        return;
    };
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let script = format!("exec 3<>/dev/tcp/127.0.0.1/{port}");
    let r = repo(&allow_list(&check(
        "net",
        &["/bin/bash", "-c", &script],
        30,
        r#","requires_isolation":true"#,
    )));
    running_task(&r, "t");
    let report = run_check(&r.memory, &r.ctx, "t", "net").unwrap();
    let check = &report["event"]["check"];
    assert_eq!(check["isolation"]["network_isolated"], true, "{report}");
    assert_eq!(
        check["outcome"], "failed",
        "the connection must fail inside the namespace"
    );
    assert!(listener.accept().is_err(), "the check reached the outside");
}

#[test]
fn finding_12_an_uncontained_check_never_passes() {
    let r = repo(&allow_list(&check(
        "loose",
        &["/bin/true"],
        30,
        r#","uncontained":true"#,
    )));
    running_task(&r, "t");
    let report = run_check(&r.memory, &r.ctx, "t", "loose").unwrap();
    assert_eq!(report["event"]["check"]["outcome"], "incomplete");
    assert!(verify_with(&r, "t", &event_id(&report), "v").is_err());
}
