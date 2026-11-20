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
        let id = s(&v.entries()[0], "entry_id");
        let grant = v.grant(
            &serde_json::json!({"licensee":"Interop", "usage":"test", "items":[{"entry_id":id}]}),
        )?;
        v.record_royalty(&serde_json::json!({"license_id":grant["license_id"],"amount":1.25}))?;
        v.export_bundle(
            &s(&grant, "license_id"),
            &path.parent().unwrap().join("exports"),
        )?;
        ensure!(v.verify()["ok"] == true, "Rust verification failed");
        v.change_passphrase("interop-test-only", "temporary-test-password")?;
        let recovery = v.rotate_recovery_key()?;
        drop(v);
        let mut v = Vault::open_recovery(path, &recovery)?;
        v.reset_passphrase("interop-test-only")?;
        std::fs::write(
            path.parent().unwrap().join("test-only-recovery.txt"),
            recovery.as_bytes(),
        )?;
    } else {
        let mut v = Vault::open(path, "interop-test-only")?;
        let e = v
            .entries()
            .into_iter()
            .find(|e| e["path"] == "Python/école.md")
            .unwrap();
        ensure!(
            v.read(&s(&e, "entry_id"), None)?.as_slice() == "Créé en Python 🐍".as_bytes(),
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
