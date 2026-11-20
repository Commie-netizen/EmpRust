use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use empreinte::{server, vault::Vault};
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version,
    about = "Empreinte — archive personnelle chiffrée, moteur Rust"
)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    ChangePassphrase {
        vault: PathBuf,
    },
    RecoverAccess {
        vault: PathBuf,
    },
    RotateRecoveryKey {
        vault: PathBuf,
    },
    Memory {
        #[arg(long)]
        database: Option<PathBuf>,
        #[arg(long)]
        database_key_env: Option<String>,
        #[command(subcommand)]
        action: MemoryCommand,
    },
    Head {
        /// Dossier du journal ; par défaut <dépôt>/.empreinte-head.
        #[arg(long)]
        memory: Option<PathBuf>,
        /// Racine du dépôt (de confiance) ; par défaut le dépôt de confiance qui contient
        /// le dossier courant.
        #[arg(long)]
        repo: Option<PathBuf>,
        #[command(subcommand)]
        action: HeadCommand,
    },
    Init {
        vault: PathBuf,
    },
    Import {
        vault: PathBuf,
        folder: PathBuf,
    },
    Verify {
        vault: PathBuf,
    },
    List {
        vault: PathBuf,
    },
    Serve {
        vault: PathBuf,
        #[arg(long, default_value_t = 0)]
        port: u16,
    },
    Demo {
        #[arg(long, default_value_t = 0)]
        port: u16,
    },
}
#[derive(Subcommand)]
enum HeadCommand {
    /// Montre ce que contient un dépôt ; avec --confirm, l'ajoute à la liste de confiance.
    Trust {
        path: PathBuf,
        #[arg(long)]
        confirm: bool,
    },
    /// Fait entrer une règle du dépôt dans le journal, comme candidate.
    Register {
        rule: String,
    },
    Status,
    Recall {
        query: String,
        #[arg(long, default_value_t = 12000)]
        budget: usize,
    },
    Record {
        file: PathBuf,
    },
    ProposeRule {
        file: PathBuf,
    },
    /// Déplace les lignes écartées en quarantaine ; l'ancien journal est gardé entier.
    Repair,
    /// Liste les contrôles autorisés de .agents/checks.json.
    Checks,
    /// Lance le contrôle nommé pour la tâche et enregistre son résultat.
    Check {
        task: String,
        name: String,
    },
    /// Liste les règles de .agents/rules, leur état et leur dernière évaluation.
    Rules,
    /// Lance les contrôles réfutants de la règle et enregistre les mesures.
    Evaluate {
        rule: String,
    },
    /// Rend active une règle évaluée (évaluation réussie et à jour exigée).
    Promote {
        rule: String,
    },
    /// Annule la dernière promotion de la règle.
    Rollback {
        rule: String,
    },
    /// Retire une règle.
    Retire {
        rule: String,
    },
    /// Compare les mesures de deux règles, sans rien décider.
    Compare {
        a: String,
        b: String,
    },
}
#[derive(Subcommand)]
enum MemoryCommand {
    EncryptCopy {
        destination: PathBuf,
        #[arg(long)]
        new_key_env: String,
    },
    Recover,
    Runs,
    Profile,
    SetProfile {
        file: PathBuf,
        #[arg(long)]
        reason: String,
    },
    RestoreProfile {
        revision: i64,
    },
    Prepare {
        file: PathBuf,
    },
    Run {
        id: String,
    },
    Execute {
        id: String,
        #[arg(long)]
        approve: String,
        #[arg(long)]
        key_env: Option<String>,
    },
    Cancel {
        id: String,
    },
    Feedback {
        id: String,
        #[arg(long, allow_hyphen_values = true)]
        rating: i64,
        #[arg(long)]
        note: String,
    },
    Adapt,
    Export,
    Forget {
        provider: String,
        id: String,
        #[arg(long)]
        confirm: bool,
    },
    Sync {
        folder: PathBuf,
        #[arg(long)]
        follow: bool,
    },
    Stats,
    Import {
        file: PathBuf,
        #[arg(long,default_value="normalized",value_parser=["normalized","chatgpt","claude"])]
        format: String,
    },
    Search {
        query: String,
        #[arg(long, default_value_t = 4000)]
        budget: usize,
    },
    Get {
        id: String,
    },
    Rebuild,
    Mcp,
    Ask {
        query: String,
        #[arg(long)]
        model: String,
        #[arg(long, default_value = "http://127.0.0.1:11434/v1/chat/completions")]
        endpoint: String,
        #[arg(long, default_value_t = 4000)]
        budget: usize,
    },
}
fn memory_command(
    database: Option<PathBuf>,
    database_key_env: Option<String>,
    action: MemoryCommand,
) -> Result<()> {
    use empreinte::conversations::{self, Store};
    use std::io::Read;
    let database = database
        .or_else(|| {
            std::env::var_os("LOCALAPPDATA")
                .map(|p| PathBuf::from(p).join("Empreinte/conversations.sqlite"))
        })
        .or_else(|| {
            std::env::var_os("HOME")
                .map(|p| PathBuf::from(p).join(".local/share/empreinte/conversations.sqlite"))
        })
        .ok_or_else(|| anyhow::anyhow!("fournir --database"))?;
    let key = database_key_env
        .map(|name| std::env::var(name).map(Zeroizing::new))
        .transpose()?;
    let mut store = Store::open_with_key(&database, key.as_ref().map(|k| k.as_str()))?;
    let result = match action {
        MemoryCommand::EncryptCopy {
            destination,
            new_key_env,
        } => {
            let key = Zeroizing::new(std::env::var(new_key_env)?);
            store.encrypted_copy(&destination, &key)?
        }
        MemoryCommand::Recover => store.recover_runs()?,
        MemoryCommand::Runs => store.list_runs()?,
        MemoryCommand::Profile => store.profile()?,
        MemoryCommand::SetProfile { file, reason } => {
            store.set_profile(read_config(&file)?, &reason)?
        }
        MemoryCommand::RestoreProfile { revision } => store.restore_profile(revision)?,
        MemoryCommand::Prepare { file } => store.prepare(read_config(&file)?)?,
        MemoryCommand::Run { id } => store.run(&id)?,
        MemoryCommand::Execute {
            id,
            approve,
            key_env,
        } => store.execute_run(&id, &approve, key_env.as_deref())?,
        MemoryCommand::Cancel { id } => store.cancel_run(&id)?,
        MemoryCommand::Feedback { id, rating, note } => store.feedback(&id, rating, &note)?,
        MemoryCommand::Adapt => store.adapt()?,
        MemoryCommand::Export => store.export_conversations()?,
        MemoryCommand::Forget {
            provider,
            id,
            confirm,
        } => {
            ensure!(
                confirm,
                "--confirm requis : purge aussi les plans/résultats/feedback qui référencent cette conversation"
            );
            store.forget(&provider, &id)?
        }
        MemoryCommand::Sync { folder, follow } => loop {
            let report = store.sync(&folder)?;
            if !follow {
                break report;
            }
            println!("{report}");
            std::thread::sleep(std::time::Duration::from_secs(10));
        },
        MemoryCommand::Stats => store.stats()?,
        MemoryCommand::Import { file, format } => {
            let mut bytes = Vec::new();
            std::fs::File::open(file)?
                .take(64 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() <= 64 * 1024 * 1024,
                "export supérieur à 64 Mio : fractionner avant import"
            );
            store.import(conversations::decode(
                serde_json::from_slice(&bytes)?,
                &format,
            )?)?
        }
        MemoryCommand::Search { query, budget } => store.search(&query, budget)?,
        MemoryCommand::Get { id } => store.get(&id)?,
        MemoryCommand::Rebuild => {
            store.rebuild()?;
            store.stats()?
        }
        MemoryCommand::Mcp => return conversations::mcp(&store),
        MemoryCommand::Ask {
            query,
            model,
            endpoint,
            budget,
        } => conversations::ask(&store, &endpoint, &model, &query, budget)?,
    };
    println!("{result}");
    Ok(())
}
fn read_config<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Result<T> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(65537)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 65536, "configuration trop grande");
    Ok(serde_json::from_slice(&bytes)?)
}
fn pass() -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(rpassword::prompt_password(
        "Phrase de passe : ",
    )?))
}
fn new_passphrase() -> Result<Zeroizing<String>> {
    let first = Zeroizing::new(rpassword::prompt_password("Nouvelle phrase de passe : ")?);
    let second = Zeroizing::new(rpassword::prompt_password("Confirmer : ")?);
    ensure!(
        !first.is_empty() && *first == *second,
        "phrases vides ou différentes"
    );
    Ok(first)
}
#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().command.unwrap_or(Command::Demo { port: 0 }) {
        Command::ChangePassphrase { vault } => {
            let old = pass()?;
            let mut v = Vault::open(&vault, &old)?;
            let new = new_passphrase()?;
            v.change_passphrase(&old, &new)?;
            println!("Phrase de passe modifiée ; clé de secours inchangée.");
        }
        Command::RecoverAccess { vault } => {
            let recovery = Zeroizing::new(rpassword::prompt_password("Clé de secours : ")?);
            let mut v = Vault::open_recovery(&vault, &recovery)?;
            let new = new_passphrase()?;
            v.reset_passphrase(&new)?;
            println!(
                "Accès rétabli ; clé de secours inchangée. Aucune réparation du registre effectuée."
            );
        }
        Command::RotateRecoveryKey { vault } => {
            let mut v = Vault::open(&vault, &pass()?)?;
            let recovery = v.rotate_recovery_key()?;
            println!(
                "Nouvelle clé de secours (ancienne invalidée pour ce coffre) :\n{}",
                recovery.as_str()
            );
        }
        Command::Memory {
            database,
            database_key_env,
            action,
        } => {
            tokio::task::spawn_blocking(move || memory_command(database, database_key_env, action))
                .await??
        }
        Command::Head {
            memory,
            repo,
            action,
        } => {
            use empreinte::head;
            let settings = head::Settings::for_current_user()?;
            if let HeadCommand::Trust { path, confirm } = &action {
                let shown = head::trust::trust(&settings, path, *confirm)?;
                println!("{}", serde_json::to_string_pretty(&shown)?);
                return Ok(());
            }
            let ctx = head::trust::resolve(&settings, repo.as_deref(), &std::env::current_dir()?)?;
            let memory = memory.unwrap_or_else(|| ctx.root.join(".empreinte-head"));
            let candidate = matches!(&action, HeadCommand::ProposeRule { .. });
            let result = match action {
                HeadCommand::Trust { .. } => unreachable!("handled above"),
                HeadCommand::Register { rule } => head::rules::register(&memory, &ctx, &rule)?,
                HeadCommand::Check { task, name } => head::run_check(&memory, &ctx, &task, &name)?,
                HeadCommand::Checks => head::checks::load(&ctx)?.describe(),
                HeadCommand::Rules => head::rules::report(&head::Memory::open(&memory, &ctx)?),
                HeadCommand::Evaluate { rule } => head::rules::evaluate(&memory, &ctx, &rule)?,
                HeadCommand::Promote { rule } => head::rules::promote(&memory, &ctx, &rule)?,
                HeadCommand::Rollback { rule } => head::rules::rollback(&memory, &ctx, &rule)?,
                HeadCommand::Retire { rule } => head::rules::retire(&memory, &ctx, &rule)?,
                HeadCommand::Compare { a, b } => head::rules::compare(&memory, &ctx, &a, &b)?,
                HeadCommand::Repair => head::Memory::open(&memory, &ctx)?.repair()?,
                HeadCommand::Status => head::Memory::open(&memory, &ctx)?.status(),
                HeadCommand::Recall { query, budget } => {
                    head::Memory::open(&memory, &ctx)?.recall(&query, budget)
                }
                HeadCommand::Record { file } | HeadCommand::ProposeRule { file } => {
                    let mut input = head::read_input(&file)?;
                    if candidate {
                        input.kind = "candidate".into();
                    }
                    let mut journal = head::Memory::open(&memory, &ctx)?;
                    journal.record(input)?;
                    journal.status()
                }
            };
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::Init { vault } => {
            let first = pass()?;
            let second = Zeroizing::new(rpassword::prompt_password("Confirmer : ")?);
            ensure!(*first == *second, "phrases différentes");
            let (_vault, recovery) = Vault::create(&vault, &first, false)?;
            println!(
                "Archive créée. Conservez cette clé de secours :\n{}",
                recovery.as_str()
            );
        }
        Command::Import { vault, folder } => {
            let mut v = Vault::open(&vault, &pass()?)?;
            println!("{}", server::import_folder(&mut v, &folder)?);
        }
        Command::Verify { vault } => {
            let v = Vault::open(&vault, &pass()?)?;
            let report = v.verify();
            println!("{}", serde_json::to_string_pretty(&report)?);
            ensure!(report["ok"] == true, "vérification non concluante");
        }
        Command::List { vault } => {
            let v = Vault::open(&vault, &pass()?)?;
            println!("{}", serde_json::to_string_pretty(&v.entries())?);
        }
        Command::Serve { vault, port } => server::serve(vault, port, false).await?,
        Command::Demo { port } => {
            let temp = tempfile::tempdir()?;
            let path = temp.path().join("coffre");
            {
                let (mut v, _) = Vault::create(&path, "demo", true)?;
                for (p, t) in [
                    (
                        "Index.md",
                        "# Empreinte Rust\n\nBienvenue dans l'archive native. [[Recherche/Provenance]] et [[Journal/Idées]]. #accueil",
                    ),
                    (
                        "Recherche/Provenance.md",
                        "# Provenance\n\nLe registre signé conserve l'ordre des versions. Une date externe exige une autorité authentifiée. [[Index]] #recherche",
                    ),
                    (
                        "Journal/Idées.md",
                        "# Idées\n\nUn jardin de connaissances privé. [[Recherche/Provenance]] #journal",
                    ),
                    ("Code/exemple.rs", "fn main() { println!(\"Empreinte\"); }"),
                ] {
                    v.put(p, t.as_bytes(), empreinte::workspace::media(p), None)?;
                }
            }
            println!("Données fictives ; phrase de passe : demo");
            server::serve(path, port, true).await?;
        }
    }
    Ok(())
}
