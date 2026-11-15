"""Browser session regressions, including late responses and abandoned dialogs."""
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_web_session_regressions():
    result = subprocess.run(
        ["node", str(Path(__file__).with_name("web_session.test.mjs"))],
        capture_output=True, text=True, encoding="utf-8", timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "all checks passed" in result.stdout
