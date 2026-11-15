"""Deterministic, non-destructive folder imports.

Metadata checks and SHA-256 comparisons of two reads detect concurrent
modification, but do not provide a coherent snapshot guarantee.
"""
from __future__ import annotations

import json
import mimetypes
import os
import stat
import time
from collections.abc import Iterator
from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from .api import VaultAPI
from .model import EntryKind
from .parse import is_text, parse_document

_SKIP = {".obsidian", ".git", ".trash", "node_modules", "__pycache__"}
_CODE = {".py", ".js", ".jsx", ".ts", ".tsx", ".c", ".h", ".cpp", ".hpp", ".rs",
         ".go", ".java", ".sh", ".ps1", ".rb", ".php", ".swift", ".kt", ".sql", ".css", ".html"}
_TEXT = {".json": "application/json", ".yaml": "application/yaml", ".yml": "application/yaml",
         ".toml": "application/toml", ".csv": "text/csv", ".xml": "application/xml",
         ".txt": "text/plain", ".log": "text/plain", ".logs": "text/plain"}
_MIME = mimetypes.MimeTypes(filenames=())


@dataclass(frozen=True)
class SourceFile:
    """A regular source file and its stable import metadata."""
    path: Path
    relative_path: str
    size: int
    source_mtime: datetime
    media_type: str
    kind: EntryKind


@dataclass(frozen=True)
class SkippedFile:
    """A path omitted from this import and a human-readable reason."""
    path: str
    reason: str


@dataclass
class ImportReport:
    """Counts refer to files; bytes counts content successfully passed to put."""
    scanned: int = 0
    added: int = 0
    updated: int = 0
    unchanged: int = 0
    skipped: list[SkippedFile] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    bytes: int = 0
    elapsed: float = 0.0


def _classify(relative: str) -> tuple[str, EntryKind]:
    path = PurePosixPath(relative)
    ext = path.suffix.lower()
    if ext in {".md", ".markdown"}:
        return "text/markdown", "draft" if any(p.casefold() in {"drafts", "brouillons"} for p in path.parts[:-1]) else "note"
    if ext in {".txt", ".log", ".logs"}:
        return "text/plain", "log"
    if ext in _CODE:
        return "text/plain", "code"
    return _TEXT.get(ext) or _MIME.guess_type(relative)[0] or "application/octet-stream", "file"


def _scan(root: Path) -> Iterator[SourceFile | SkippedFile]:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("import root must be a directory")
    pending = [root]
    found: list[SourceFile | SkippedFile] = []
    while pending:
        folder = pending.pop()
        try:
            if folder.is_symlink() or not folder.resolve(strict=True).is_relative_to(root):
                raise OSError("directory changed to a link outside root")
            children = sorted(folder.iterdir(), key=lambda p: p.name)
        except OSError as exc:
            found.append(SkippedFile(folder.relative_to(root).as_posix(), str(exc)))
            continue
        for path in children:
            relative = path.relative_to(root).as_posix()
            try:
                info = path.lstat()
                reparse = bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
                if path.is_symlink() or reparse:
                    found.append(SkippedFile(relative, "symlink or reparse point"))
                elif path.name.startswith(".") or path.name in _SKIP or bool(getattr(info, "st_file_attributes", 0) & 2):
                    found.append(SkippedFile(relative, "hidden or excluded path"))
                elif not path.resolve().is_relative_to(root):
                    found.append(SkippedFile(relative, "outside root"))
                elif stat.S_ISDIR(info.st_mode):
                    pending.append(path)
                elif stat.S_ISREG(info.st_mode):
                    media, kind = _classify(relative)
                    found.append(SourceFile(path, relative, info.st_size,
                        datetime.fromtimestamp(info.st_mtime, timezone.utc), media, kind))
                else:
                    found.append(SkippedFile(relative, "not a regular file"))
            except OSError as exc:
                found.append(SkippedFile(relative, str(exc)))
    yield from sorted(found, key=lambda f: f.relative_path if isinstance(f, SourceFile) else f.path)


def scan_folder(root: Path) -> Iterator[SourceFile]:
    """Yield regular visible files in relative-path order without following links."""
    for item in _scan(Path(root)):
        if isinstance(item, SourceFile):
            yield item


def _open_source(root: Path, relative: str) -> int:
    """Pin directory handles on POSIX; validate the opened handle on Windows."""
    parts = PurePosixPath(relative).parts
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if os.name != "nt":
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                os.close(directory)
                directory = child
            return os.open(parts[-1], flags, dir_fd=directory)
        finally:
            os.close(directory)
    fd = os.open(root.joinpath(*parts), flags)
    try:
        import ctypes
        import msvcrt
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        get_path = kernel.GetFinalPathNameByHandleW
        get_path.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
        get_path.restype = wintypes.DWORD
        buffer = ctypes.create_unicode_buffer(32768)
        size = get_path(msvcrt.get_osfhandle(fd), buffer, len(buffer), 0)
        if not size or size >= len(buffer):
            raise OSError("cannot verify opened source path")
        final_path = buffer.value
        if final_path.startswith("\\\\?\\UNC\\"):
            final_path = "\\\\" + final_path[8:]
        elif final_path.startswith("\\\\?\\"):
            final_path = final_path[4:]
        if not Path(final_path).is_relative_to(root):
            raise OSError("opened source lies outside root")
        return fd
    except BaseException:
        os.close(fd)
        raise


def sync_folder(vault: VaultAPI, root: Path, *, prefix: str = "", max_bytes: int = 20_000_000) -> ImportReport:
    """Import changed content and retain an encrypted manifest for missing files."""
    started = time.perf_counter()
    root = Path(root).resolve(strict=True)
    prefix = prefix.replace("\\", "/").strip("/")
    if any(part in {"..", "."} for part in prefix.split("/")) or ":" in prefix:
        raise ValueError("prefix must be a relative logical folder")
    if max_bytes < 0:
        raise ValueError("max_bytes must be nonnegative")
    # Root paths are private; aux storage encrypts the manifest and its key.
    import hashlib
    key = "import/" + hashlib.sha256((str(root) + "\0" + prefix).encode("utf-8")).hexdigest()
    old = vault.aux_get(key)
    previous = set(json.loads(old)) if old else set()
    seen: set[str] = set()
    report = ImportReport()
    batch = getattr(vault, "batch", None)
    with batch() if callable(batch) else nullcontext():
        for source in _scan(root):
            if isinstance(source, SkippedFile):
                report.skipped.append(source)
                continue
            report.scanned += 1
            logical = f"{prefix}/{source.relative_path}" if prefix else source.relative_path
            seen.add(logical)
            if source.size > max_bytes:
                report.skipped.append(SkippedFile(logical, "exceeds max_bytes"))
                continue
            try:
                # Re-check containment and links just before opening, and bound reads.
                parts = source.path.relative_to(root).parts
                current = root
                for part in parts:
                    current = current / part
                    info = current.lstat()
                    if current.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                        raise OSError("source changed to a link")
                if not source.path.resolve(strict=True).is_relative_to(root):
                    raise OSError("source moved outside root")
                expected = info
                fd = _open_source(root, source.relative_path)
                with os.fdopen(fd, "rb", buffering=0) as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode):
                        raise OSError("source is no longer a regular file")
                    if (info.st_dev, info.st_ino) != (expected.st_dev, expected.st_ino):
                        raise OSError("source changed while opening")
                    for attempt in range(4):  # Initial read and up to three retries.
                        if attempt:
                            stream.seek(0)
                            info = os.fstat(stream.fileno())
                        content = stream.read(max_bytes + 1)
                        after = os.fstat(stream.fileno())
                        if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) == (
                                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                            stream.seek(0)
                            confirmation = stream.read(max_bytes + 1)
                            confirmed = os.fstat(stream.fileno())
                            if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) == (
                                    confirmed.st_dev, confirmed.st_ino, confirmed.st_size, confirmed.st_mtime_ns
                            ) and hashlib.sha256(content).digest() == hashlib.sha256(confirmation).digest():
                                break
                    else:
                        raise OSError("unstable during read")
                if len(content) > max_bytes:
                    report.skipped.append(SkippedFile(logical, "exceeds max_bytes"))
                    continue
            except OSError as exc:
                report.skipped.append(SkippedFile(logical, str(exc)))
                continue
            doc = parse_document(content.decode("utf-8-sig", errors="replace") if is_text(source.media_type) else "",
                                 path=logical, media_type=source.media_type)
            existing = vault.find(logical)
            before = existing.n_versions if existing else 0
            version = vault.put(logical, content, title=doc.title, tags=doc.tags, kind=source.kind,
                media_type=source.media_type, source_mtime=datetime.fromtimestamp(info.st_mtime, timezone.utc))
            if not before:
                report.added += 1
            elif version.version > before:
                report.updated += 1
            else:
                report.unchanged += 1
            report.bytes += len(content)
        report.missing = sorted(previous - seen)
        vault.aux_put(key, json.dumps(sorted(previous | seen), ensure_ascii=False).encode("utf-8"))
    report.elapsed = time.perf_counter() - started
    return report
