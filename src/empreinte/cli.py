"""Command line.

    empreinte init VAULT                 create an encrypted vault (prints the recovery key once)
    empreinte import VAULT FOLDER        record every file of a folder (an Obsidian vault for example)
    empreinte serve VAULT                open the interface in the browser (unlock there)
    empreinte verify VAULT               re-check the whole ledger and every blob
    empreinte anchor VAULT               ask an outside authority to timestamp the chain head
    empreinte demo                       the interface on generated data, no vault needed

The passphrase is asked on the terminal. For scripts it can come from the environment
variable EMPREINTE_PASSPHRASE; it is never accepted as a command line argument, where it
would end up in the shell history and the process list.
"""
from __future__ import annotations

import argparse
import dataclasses
import getpass
import json
import os
import sys
from pathlib import Path

from .api import VaultError, WrongPassphrase

ENV_PASSPHRASE = "EMPREINTE_PASSPHRASE"


def _passphrase(prompt: str, *, confirm: bool = False) -> str:
    value = os.environ.get(ENV_PASSPHRASE)
    if value:
        return value
    value = getpass.getpass(prompt)
    if confirm and getpass.getpass("Confirmer : ") != value:
        raise SystemExit("Les deux saisies diffèrent.")
    if not value:
        raise SystemExit("Phrase de passe vide.")
    return value


def _utf8_console() -> None:
    """Accented French output must survive a redirected stdout on Windows (cp1252)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def _is_vault(path: Path) -> bool:
    return (Path(path) / "header.json").is_file()


def _require_vault(path: Path) -> None:
    if not _is_vault(path):
        raise SystemExit(f"Aucune archive Empreinte dans {path} (créez-la avec : empreinte init {path}).")


def report_dict(report) -> dict:
    """JSON-ready summary of an importer.ImportReport (a dataclass): lists become counts."""
    data = dataclasses.asdict(report) if dataclasses.is_dataclass(report) else report.model_dump(mode="json")
    data["skipped"] = len(data.get("skipped", []))
    data["missing"] = len(data.get("missing", []))
    return data


def _open(path: Path):
    from .vault import Vault

    _require_vault(path)
    try:
        return Vault.open(path, _passphrase("Phrase de passe : "))
    except WrongPassphrase:
        raise SystemExit("Phrase de passe incorrecte.") from None


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def cmd_init(args: argparse.Namespace) -> int:
    from .vault import Vault

    if args.vault.exists() and any(args.vault.iterdir()):
        print(f"{args.vault} existe déjà et n'est pas vide.", file=sys.stderr)
        return 1
    vault = Vault.create(args.vault, _passphrase("Nouvelle phrase de passe : ", confirm=True))
    print(f"Coffre créé : {args.vault}")
    print("Clé de secours, à noter maintenant, elle ne sera plus affichée :")
    print(f"\n    {vault.take_recovery_key()}\n")
    print("Sans la phrase de passe ni cette clé, l'archive est définitivement illisible.")
    vault.lock()
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    from .importer import sync_folder

    if not Path(args.folder).is_dir():
        raise SystemExit(f"Dossier introuvable : {args.folder}")
    vault = _open(args.vault)
    try:
        report = sync_folder(vault, args.folder, prefix=args.prefix)
    finally:
        vault.lock()
    _print(report_dict(report))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    vault = _open(args.vault)
    try:
        report = vault.verify()
    finally:
        vault.lock()
    _print(report.model_dump(mode="json"))
    return 0 if report.ok else 1


def cmd_anchor(args: argparse.Namespace) -> int:
    vault = _open(args.vault)
    try:
        head = vault.ledger()[-1] if vault.ledger() else None
        if head is None:
            print("Registre vide, rien à ancrer.", file=sys.stderr)
            return 1
        print(f"Ceci envoie à {vault.tsa_url} l'empreinte de 32 octets de la tête du registre")
        print(f"({head.record_hash}) et rien d'autre : ni contenu, ni titre, ni nom de fichier.")
        if not args.yes and input("Continuer ? [o/N] ").strip().lower() not in ("o", "oui", "y", "yes"):
            print("Annulé.")
            return 1
        anchor = vault.anchor("rfc3161")
    finally:
        vault.lock()
    _print(anchor.model_dump(mode="json", exclude={"proof"}))
    return 0


def session_for(path: Path, *, model: str | None = None, model_url: str = "http://127.0.0.1:11434/v1",
                kdf_params=None):
    """The object the server needs: how to open, create and feed this vault.

    The callables keep no reference to an opened vault: the server passes the current
    vault and workspace to import_folder and make_previews, and drops both on lock.
    `model` names a model served on this machine (Ollama, llama.cpp, LM Studio). Without
    it the interface hides the preview action. The client refuses any non-loopback URL.
    `kdf_params` is for tests only (cheap key derivation).
    """
    from .importer import sync_folder
    from .server import Session
    from .vault import Vault
    from .workspace import Workspace

    path = Path(path)

    def open_vault(passphrase: str):
        vault = Vault.open(path, passphrase)
        return vault, Workspace(vault)

    def create_vault(passphrase: str):
        vault = Vault.create(path, passphrase, kdf_params=kdf_params) if kdf_params else Vault.create(path, passphrase)
        recovery_key = vault.take_recovery_key()
        return vault, Workspace(vault), recovery_key

    def exists() -> bool:
        return _is_vault(path)

    def import_folder(vault, workspace, folder: Path) -> dict:
        return report_dict(sync_folder(vault, Path(folder)))

    make_previews = None
    if model:
        from .localllm import LocalLLMClient
        from .previews import make_previews as generate

        client = LocalLLMClient(model_url, model)

        def make_previews(vault, workspace, entry_ids: list[str]):
            return generate(client, vault, workspace, entry_ids)

    return Session(
        open_vault=open_vault,
        create_vault=create_vault,
        exists=exists,
        import_folder=import_folder,
        make_previews=make_previews,
        # License bundles hold plaintext by design: they go next to the vault, never inside it.
        export_dir=path.parent / f"{path.name}-licences",
    )


def _run(server, label: str) -> int:
    import time

    print(f"{label} : {server.url}\nCtrl+C pour arrêter.")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from .server import serve

    if not _is_vault(args.vault):
        if args.vault.exists() and any(args.vault.iterdir()):
            raise SystemExit(f"{args.vault} n'est pas une archive Empreinte et n'est pas vide.")
        print(f"Aucune archive dans {args.vault} : l'interface propose de la créer.")
    session = session_for(args.vault, model=args.model, model_url=args.model_url)
    return _run(serve(session, port=args.port, open_browser=not args.no_browser), "Interface")


def cmd_demo(args: argparse.Namespace) -> int:
    from .demo import demo_session
    from .server import serve

    return _run(serve(demo_session(), port=args.port, open_browser=not args.no_browser), "Démonstration")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="empreinte", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init")
    p.add_argument("vault", type=Path)
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("import")
    p.add_argument("vault", type=Path)
    p.add_argument("folder", type=Path)
    p.add_argument("--prefix", default="", help="logical folder to file the import under")
    p.set_defaults(func=cmd_import)

    p = sub.add_parser("verify")
    p.add_argument("vault", type=Path)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("anchor")
    p.add_argument("vault", type=Path)
    p.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    p.set_defaults(func=cmd_anchor)

    for name, func in (("serve", cmd_serve), ("demo", cmd_demo)):
        p = sub.add_parser(name)
        if name == "serve":
            p.add_argument("vault", type=Path)
            p.add_argument("--model", default=None, help="local model for previews, e.g. qwen2.5-coder:7b")
            p.add_argument("--model-url", default="http://127.0.0.1:11434/v1")
        p.add_argument("--port", type=int, default=0)
        p.add_argument("--no-browser", action="store_true")
        p.set_defaults(func=func)

    _utf8_console()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except VaultError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
