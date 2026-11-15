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
    command: Command,
}
#[derive(Subcommand)]
enum Command {
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
fn pass() -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(rpassword::prompt_password(
        "Phrase de passe : ",
    )?))
}
#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().command {
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
