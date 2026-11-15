//! Test-only interchange driver. Never use these public credentials for personal data.
use anyhow::{Result, ensure};
use empreinte::vault::{Vault, s};
use std::path::Path;
fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    ensure!(args.len() == 3, "interop <read-write|create> <test-vault>");
    let path = Path::new(&args[2]);
    if args[1] == "create" {
        let (mut v, _) = Vault::create(path, "interop-test-only", true)?;
        v.put(
            "Rust/école.md",
            "Créé en Rust 🦀".as_bytes(),
            "text/markdown",
            None,
        )?;
        v.aux_put("interop", b"rust-aux")?;
        ensure!(v.verify()["ok"] == true, "Rust verification failed");
    } else {
        let mut v = Vault::open(path, "interop-test-only")?;
        let e = v
            .entries()
            .into_iter()
            .find(|e| e["path"] == "Python/école.md")
            .unwrap();
        ensure!(
            &*v.read(&s(&e, "entry_id"), None)? == "Créé en Python 🐍".as_bytes(),
            "Python plaintext differs"
        );
        ensure!(
            v.verify()["ok"] == true,
            "Python fixture failed Rust verification"
        );
        ensure!(
            v.aux_get("interop")?.unwrap().as_slice() == b"python-aux",
            "aux mismatch"
        );
        v.put(
            "Python/école.md",
            "Modifié en Rust 🦀".as_bytes(),
            "text/markdown",
            None,
        )?;
        v.aux_put("interop", b"rust-updated")?;
    }
    println!("interop OK");
    Ok(())
}
