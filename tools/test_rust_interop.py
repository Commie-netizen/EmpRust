"""Round-trip disposable fixtures through Python and the Rust example binary.

Usage: python tools/test_rust_interop.py --driver /tmp/empreinte-rust-target/debug/examples/interop
Windows runs the driver in Ubuntu WSL; Linux runs it directly. No personal vault is read.
"""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import runpy

from empreinte.crypto import TEST_KDF
from empreinte.vault import Vault


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--driver", required=True)
    parser.add_argument("--temp-root", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.temp_root) as temp:
        root = Path(temp)

        def rust(mode, path):
            if os.name == "nt":
                raw = path.resolve().as_posix()
                converted = "/mnt/" + raw[0].lower() + raw[2:]
                command = ["wsl", "-d", "Ubuntu", "--", args.driver, mode, converted]
            else:
                command = [args.driver, mode, str(path)]
            subprocess.run(command, check=True, timeout=30)

        py = root / "python"
        vault = Vault.create(py, "interop-test-only", kdf_params=TEST_KDF)
        item = vault.put("Python/école.md", "Créé en Python 🐍".encode(), title="Titre personnalisé", tags=["test"])
        grant = vault.grant("Test recipient", [(item.entry_id, None)], usage="interoperability test")
        vault.record_royalty(grant.license_id, 1.25)
        vault.aux_put("interop", b"python-aux")
        vault.close()
        rust("read-write", py)
        vault = Vault.open(py, "interop-test-only")
        assert vault.verify().ok, vault.verify().errors
        assert vault.read(item.entry_id) == "Modifié en Rust 🦀".encode()
        assert vault.read(item.entry_id, 1) == "Créé en Python 🐍".encode()
        assert vault.aux_get("interop") == b"rust-updated"
        assert vault.entry(item.entry_id).title == "Titre personnalisé"
        vault.close()
        native = root / "rust"
        rust("create", native)
        vault = Vault.open(native, "interop-test-only")
        assert vault.verify().ok, vault.verify().errors
        assert vault.read(vault.find("Rust/école.md").entry_id) == "Créé en Rust 🦀".encode()
        assert vault.aux_get("interop") == b"rust-aux"
        assert len(vault.licenses()) == 1
        assert vault.royalties()[0].amount == 1.25
        vault.close()
        vault = Vault.open_with_recovery_key(native, (root / "test-only-recovery.txt").read_text())
        assert vault.verify().ok
        vault.close()
        verifier = runpy.run_path(str(Path(__file__).with_name("verify_bundle.py")))
        bundle = next((root / "exports").iterdir())
        report = verifier["verify"](bundle, [])
        assert report["ok"], report
    print("Python -> Rust -> Python and Rust -> Python: all checks passed")


if __name__ == "__main__":
    main()
