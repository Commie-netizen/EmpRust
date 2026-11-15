from contextlib import contextmanager
from types import SimpleNamespace
import os
import pytest
from empreinte.importer import scan_folder, sync_folder
from empreinte.testing import InMemoryVault, stepping_clock


def test_import_repeat_update_missing_and_skips(tmp_path):
    vault = InMemoryVault(clock=stepping_clock())
    (tmp_path / "drafts").mkdir()
    (tmp_path / "drafts" / "a.md").write_text("---\ntags: alpha, beta\n---\n# Heading", encoding="utf-8", newline="\n")
    (tmp_path / "x.py").write_text("print('hello')", encoding="utf-8", newline="\n")
    (tmp_path / "log.txt").write_text("log", encoding="utf-8", newline="\n")
    (tmp_path / "large.bin").write_bytes(b"x" * 101)
    (tmp_path / ".hidden").write_bytes(b"secret")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "bad.md").write_bytes(b"skip")
    report = sync_folder(vault, tmp_path, prefix="imported", max_bytes=100)
    assert report.scanned == 4 and report.added == 3
    assert len(report.skipped) == 3
    entry = vault.find("imported/drafts/a.md")
    assert entry.kind == "draft" and entry.title == "Heading" and entry.tags == ["alpha", "beta"]
    assert entry.authored_at.utcoffset().total_seconds() == 0
    assert vault.find("imported/x.py").kind == "code"
    assert vault.find("imported/log.txt").kind == "log"
    assert sync_folder(vault, tmp_path, prefix="imported", max_bytes=100).unchanged == 3
    (tmp_path / "x.py").write_text("changed", encoding="utf-8", newline="\n")
    (tmp_path / "log.txt").unlink()
    result = sync_folder(vault, tmp_path, prefix="imported", max_bytes=100)
    assert result.updated == 1 and result.missing == ["imported/log.txt"]
    assert vault.find("imported/log.txt") is not None
    assert [s.relative_path for s in scan_folder(tmp_path)] == ["drafts/a.md", "large.bin", "x.py"]


def test_batch_and_symlink(tmp_path):
    class BatchVault(InMemoryVault):
        batches = 0

        @contextmanager
        def batch(self):
            self.batches += 1
            yield

    vault = BatchVault(clock=stepping_clock())
    (tmp_path / "a.md").write_bytes(b"hello")
    linked = False
    try:
        (tmp_path / "link.md").symlink_to(tmp_path / "a.md")
        linked = True
    except OSError:
        pass  # Windows can require privileges for symlink creation.
    report = sync_folder(vault, tmp_path)
    assert vault.batches == 1 and report.added == 1
    if linked:
        assert any("symlink" in s.reason for s in report.skipped)


@pytest.mark.parametrize("changed_field", ["st_size", "st_mtime_ns"])
@pytest.mark.parametrize("stabilizes", [True, False])
def test_descriptor_changes_retry_or_skip(tmp_path, monkeypatch, changed_field, stabilizes):
    (tmp_path / "a.md").write_text("stable content", encoding="utf-8", newline="\n")
    vault = InMemoryVault(clock=stepping_clock())
    original = os.fstat
    calls = []

    def changing_fstat(fd):
        info = original(fd)
        calls.append(fd)
        values = {name: getattr(info, name) for name in
                  ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime", "st_mtime_ns")}
        # Only the post-read metadata changes, then optionally settles on retry.
        if len(calls) % 2 == 0 and (not stabilizes or len(calls) == 2):
            values[changed_field] += 1
        return SimpleNamespace(**values)

    monkeypatch.setattr(os, "fstat", changing_fstat)
    report = sync_folder(vault, tmp_path)
    assert len(calls) == (5 if stabilizes else 8)
    assert len(set(calls)) == 1
    if stabilizes:
        assert report.added == 1 and not report.skipped
        assert vault.read(vault.find("a.md").entry_id) == b"stable content"
    else:
        assert report.added == 0 and not vault.entries()
        assert report.skipped[0].reason == "unstable during read"


@pytest.mark.parametrize("stabilizes", [True, False])
def test_same_metadata_rewrite_retry_or_skip(tmp_path, monkeypatch, stabilizes):
    path = tmp_path / "a.md"
    path.write_bytes(b"first content")
    original = os.fdopen
    reads = []

    class RewritingStream:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def fileno(self):
            return self.stream.fileno()

        def seek(self, offset):
            return self.stream.seek(offset)

        def read(self, size):
            data = self.stream.read(size)
            reads.append(data)
            if not stabilizes or len(reads) == 1:
                info = path.stat()
                path.write_bytes(b"other content" if data == b"first content" else b"first content")
                os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
            return data

    monkeypatch.setattr(os, "fdopen", lambda *a, **k: RewritingStream(original(*a, **k)))
    vault = InMemoryVault(clock=stepping_clock())
    report = sync_folder(vault, tmp_path)
    assert len(reads) == (4 if stabilizes else 8)
    if stabilizes:
        assert report.added == 1 and not report.skipped
        assert vault.read(vault.find("a.md").entry_id) == b"other content"
    else:
        assert not vault.entries()
        assert report.skipped[0].reason == "unstable during read"
